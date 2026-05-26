"""
RTC Name Recovery - Binary Ninja plugin

Recovers original local-variable names from MSVC /RTC1 debug-build frame
descriptors (_RTC_framedesc / _RTC_vardesc, declared in rtcapi.h) and
applies them to the matching Binary Ninja stack variables.

Two actions are registered under Plugins:
    RTC: Recover Names (Current Function)
    RTC: Recover Names (Whole Binary)

The descriptor layout (MSVC, all targets) is:

    struct _RTC_vardesc   { int addr; int size; char *name; };
    struct _RTC_framedesc { int varCount; _RTC_vardesc *variables; };

Each call to `_RTC_CheckStackVars(void *frameBase, _RTC_framedesc *fd)` (or
the alloca-aware `_RTC_CheckStackVars2`) hands the runtime a pointer to a
static descriptor table for the current function. Each entry's `name`
field points to the original ASCII source name of a stack buffer - that's
what we recover here.

We resolve each entry's BN stack-variable target as:

    target_storage = frameBase_storage + descriptor.addr

where `frameBase_storage` is the BN storage offset of the local whose
address is passed as the first argument to the RTC check call (typically
the lowest-addressed local in the frame).
"""

import struct

from binaryninja import (
    PluginCommand,
    MediumLevelILOperation,
    RegisterValueType,
    Type,
    BackgroundTaskThread,
)
from binaryninja.log import log_info, log_warn


# When a descriptor entry points to a stack region for which BN has no
# existing local (common when the buffer is only used by-address, e.g.
# OSVERSIONINFOEXW passed to GetVersionExW), create a placeholder local
# typed as `char[size]` so the original name has something to attach to.
# Set False for strict "rename existing vars only" behavior.
_AUTO_CREATE_MISSING = True


# First/second integer-argument registers per architecture.
# MSVC x64 ABI uses RCX, RDX for fastcall. x86 __fastcall is ECX, EDX.
_ARG_REGS = {
    "x86_64": ("rcx", "rdx"),
    "x86":    ("ecx", "edx"),
}


# ---------------------------------------------------------------------------
# Symbol / IL helpers
# ---------------------------------------------------------------------------

def _is_rtc_check_symbol(sym):
    """True if `sym` names one of the _RTC_CheckStackVars[2] runtime checks."""
    if sym is None:
        return False
    raw = sym.short_name or sym.full_name or sym.name
    if not raw:
        return False
    return raw.lstrip("_").startswith("RTC_CheckStackVars")


def _resolve_call_target(bv, dest_il):
    """Resolve a MLIL call destination to a Symbol (direct or via IAT load)."""
    op = dest_il.operation
    if op == MediumLevelILOperation.MLIL_CONST_PTR:
        return bv.get_symbol_at(dest_il.constant)
    if op == MediumLevelILOperation.MLIL_LOAD:
        src = dest_il.src
        if src.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            return bv.get_symbol_at(src.constant)
    return None


def _iter_rtc_calls(func):
    """Yield MLIL call instructions targeting _RTC_CheckStackVars[2] in `func`."""
    mlil = func.mlil
    if mlil is None:
        return
    bv = func.view
    call_ops = (MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_TAILCALL)
    for block in mlil:
        for instr in block:
            if instr.operation not in call_ops:
                continue
            sym = _resolve_call_target(bv, instr.dest)
            if _is_rtc_check_symbol(sym):
                yield instr


def _extract_base_storage(call, func):
    """Resolve arg 0 of an RTC check to a stack-frame offset.

    Strategy:
      1. If MLIL lifted arg 0 as `MLIL_ADDRESS_OF` of a stack var, use that
         variable's storage. Cheapest and most semantically clean.
      2. Otherwise, query the first-arg register's value at the call site
         via BN's value-set analysis. RTC passes `frameBase` directly, so a
         `StackFrameOffset` result is exactly what we need.
    """
    params = call.params
    if params and params[0].operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
        s = getattr(params[0].src, "storage", None)
        if s is not None:
            return s
    regs = _ARG_REGS.get(func.arch.name)
    if regs:
        val = func.get_reg_value_at(call.address, regs[0])
        if val.type == RegisterValueType.StackFrameOffset:
            return val.value
    return None


def _extract_fd_addr(call, func):
    """Resolve arg 1 of an RTC check to the framedesc pointer."""
    params = call.params
    if len(params) >= 2 and params[1].operation == MediumLevelILOperation.MLIL_CONST_PTR:
        return params[1].constant
    regs = _ARG_REGS.get(func.arch.name)
    if regs:
        val = func.get_reg_value_at(call.address, regs[1])
        if val.type in (RegisterValueType.ConstantValue,
                        RegisterValueType.ConstantPointerValue):
            return val.value
    return None


# ---------------------------------------------------------------------------
# Descriptor parsing
# ---------------------------------------------------------------------------

def _read_cstring(bv, addr, max_len=512):
    if not addr:
        return None
    try:
        data = bv.read(addr, max_len)
    except Exception:
        return None
    if not data:
        return None
    end = data.find(b"\x00")
    if end < 0:
        return None
    try:
        return data[:end].decode("ascii")
    except UnicodeDecodeError:
        return data[:end].decode("utf-8", errors="replace")


def _parse_framedesc(bv, fd_addr):
    """Parse `_RTC_framedesc` at `fd_addr`. Returns [(addr, size, name), ...] or None.

    Layout: { int varCount; _RTC_vardesc *variables; }
    Entry:  { int addr;     int size;       char *name;   }

    On x64 there are 4 bytes of natural padding between varCount and the
    pointer (and zero padding inside vardesc because two int32s align an
    8-byte pointer). On x86 everything is tightly packed.
    """
    ptr_size = bv.arch.address_size
    fmt_ptr = "<Q" if ptr_size == 8 else "<I"
    ptr_align = 8 if ptr_size == 8 else 4

    header_size = 4 + (ptr_align - 4) + ptr_size  # int + pad + ptr
    raw = bv.read(fd_addr, header_size)
    if len(raw) < header_size:
        return None

    var_count = struct.unpack_from("<i", raw, 0)[0]
    if var_count <= 0 or var_count > 4096:
        return None
    vars_ptr = struct.unpack_from(fmt_ptr, raw, ptr_align)[0]
    if not vars_ptr:
        return None

    entry_size = 4 + 4 + ptr_size  # name pointer naturally aligned on both archs
    raw_arr = bv.read(vars_ptr, entry_size * var_count)
    if len(raw_arr) < entry_size * var_count:
        return None

    out = []
    for i in range(var_count):
        off = i * entry_size
        addr = struct.unpack_from("<i", raw_arr, off)[0]
        size = struct.unpack_from("<i", raw_arr, off + 4)[0]
        name_ptr = struct.unpack_from(fmt_ptr, raw_arr, off + 8)[0]
        name = _read_cstring(bv, name_ptr)
        if name:
            out.append((addr, size, name))
    return out


# ---------------------------------------------------------------------------
# Per-function processing
# ---------------------------------------------------------------------------

def _process_function(func):
    """Recover names for one function. Returns (calls_seen, renamed, skipped)."""
    bv = func.view
    calls_seen = 0
    renamed = 0
    skipped = 0

    for call in _iter_rtc_calls(func):
        calls_seen += 1

        base = _extract_base_storage(call, func)
        if base is None:
            log_warn(
                f"[RTC] {func.name}@{call.address:#x}: could not resolve arg0; skipping"
            )
            continue

        fd_addr = _extract_fd_addr(call, func)
        if fd_addr is None:
            log_warn(
                f"[RTC] {func.name}@{call.address:#x}: could not resolve arg1; skipping"
            )
            continue

        entries = _parse_framedesc(bv, fd_addr)
        if not entries:
            log_warn(f"[RTC] {func.name}: framedesc parse failed @ {fd_addr:#x}")
            continue

        # Rebuild the storage->var map each call: a previous entry on the
        # same call may have created a new stack var that's now in scope.
        var_by_storage = {v.storage: v for v in func.stack_layout}

        for off, size, name in entries:
            target = base + off
            v = var_by_storage.get(target)

            if v is None:
                if not _AUTO_CREATE_MISSING:
                    log_warn(
                        f"[RTC] {func.name}: no BN local at storage {target:#x} "
                        f"(want '{name}', size {size})"
                    )
                    skipped += 1
                    continue
                # Create a placeholder typed as `char[size]` so the name has
                # a stack slot to attach to. Caller can refine the type later.
                placeholder = Type.array(Type.char(), size)
                try:
                    func.create_user_stack_var(target, placeholder, name)
                    renamed += 1
                    log_info(
                        f"[RTC] {func.name}: created stack var at {target:#x} "
                        f"-> {name} (char[{size}])"
                    )
                    # Keep our map in sync for subsequent entries on this call.
                    var_by_storage = {v.storage: v for v in func.stack_layout}
                except Exception as e:
                    log_warn(
                        f"[RTC] {func.name}: create var '{name}' at "
                        f"{target:#x} failed: {e}"
                    )
                    skipped += 1
                continue

            if v.name == name:
                skipped += 1
                continue
            old = v.name
            try:
                # `set_name_async` skips the per-rename update_analysis_and_wait
                # that `Variable.name =` would otherwise trigger - avoids the
                # "UI threads are not permitted to wait for analysis" warning
                # and is dramatically faster for bulk renames. Callers do one
                # bv.update_analysis() at the end of the sweep.
                v.set_name_async(name)
                renamed += 1
                log_info(f"[RTC] {func.name}: {old} -> {name} (size {size})")
            except Exception as e:
                log_warn(f"[RTC] {func.name}: rename {old} -> {name} failed: {e}")
                skipped += 1

    return calls_seen, renamed, skipped


# ---------------------------------------------------------------------------
# PluginCommand entry points
# ---------------------------------------------------------------------------

class _RtcRecoveryTask(BackgroundTaskThread):
    """Background task that walks RTC framedescs and renames stack vars.

    If `target_func` is set, only that function is processed. Otherwise the
    whole binary is swept. Progress is shown in the BN status bar (bottom
    left) and the task is cancellable from the UI.
    """

    def __init__(self, bv, target_func=None):
        label = (
            f"RTC: scanning {target_func.name}"
            if target_func is not None
            else "RTC: starting whole-binary sweep"
        )
        super().__init__(initial_progress_text=label, can_cancel=True)
        self.bv = bv
        self.target_func = target_func
        self.funcs_with_rtc = 0
        self.total_seen = 0
        self.total_renamed = 0
        self.total_skipped = 0

    def _accumulate(self, func):
        seen, renamed, skipped = _process_function(func)
        if seen:
            self.funcs_with_rtc += 1
        self.total_seen += seen
        self.total_renamed += renamed
        self.total_skipped += skipped

    def _process_all(self):
        funcs = list(self.bv.functions)
        total = len(funcs)
        for i, func in enumerate(funcs, 1):
            if self.cancelled:
                return
            # Status-bar update; keep it short so it fits.
            self.progress = f"RTC: {i}/{total}  {func.name}"
            self._accumulate(func)

    def run(self):
        bv = self.bv
        bv.begin_undo_actions()
        try:
            if self.target_func is not None:
                self._accumulate(self.target_func)
            else:
                self._process_all()
        finally:
            bv.commit_undo_actions()
            if self.total_renamed:
                self.progress = "RTC: updating analysis"
                bv.update_analysis()

        # Final log line - one summary instead of polluting the log mid-sweep.
        prefix = "[RTC] cancelled" if self.cancelled else "[RTC] done"
        if self.target_func is not None:
            log_info(
                f"{prefix}: {self.target_func.name}: {self.total_seen} RTC "
                f"call(s); renamed {self.total_renamed}, "
                f"skipped {self.total_skipped}"
            )
        else:
            log_info(
                f"{prefix}: swept binary: {self.funcs_with_rtc} function(s) "
                f"with RTC; {self.total_seen} call(s); renamed "
                f"{self.total_renamed}, skipped {self.total_skipped}"
            )


def _run_on_current(bv, func):
    _RtcRecoveryTask(bv, target_func=func).start()


def _run_on_binary(bv):
    _RtcRecoveryTask(bv).start()


PluginCommand.register_for_function(
    "RTC: Recover Names (Current Function)",
    "Walk the _RTC_CheckStackVars frame descriptor for this function and "
    "rename matching stack variables to their original /RTC1 source names.",
    _run_on_current,
)

PluginCommand.register(
    "RTC: Recover Names (Whole Binary)",
    "Walk _RTC_CheckStackVars frame descriptors across every function in "
    "the binary and rename matching stack variables to their original "
    "/RTC1 source names.",
    _run_on_binary,
)
