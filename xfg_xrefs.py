"""
xfg_xrefs.py - Binary Ninja plugin: Find and register XFG cross-references

XFG (eXtended Flow Guard) replaces indirect call sites with a type-hash-checked
dispatch, breaking BN's standard cross-reference tracking.  This plugin recovers
those call sites by searching for the `movabs r10, <hash>` instruction that MSVC
emits before every XFG-guarded indirect call (encoding: 49 BA <8 LE bytes>).

Hash convention (MSVC):
  - function_start - 8  : type hash with bit 0 SET   (the "valid XFG hash" marker)
  - call site R10       : type hash with bit 0 CLEARED (the pure type hash)

Results may include type-hash aliases - other functions sharing the same XFG type
signature (identical prototype).  Disambiguate by checking the vtable offset loaded
into RAX before each `movabs r10` at the reported call sites.

Commands added (grouped under Plugins -> XFG):

  XFG -> Cross-References:
    "Find Here"                       - right-click address; add xrefs for the function
                                        containing the cursor and log the count
    "Find in This Function"           - right-click function; same as above for func
    "Add All"                         - whole binary; add every resolvable xref
    "Remove All"                      - whole binary; remove all xrefs added by us

  XFG -> Indirect Calls:
    "Resolve Here"                    - right-click XFG call/movabs site; resolve one
    "Remove Here"                     - right-click XFG call/movabs site; clear one
    "Go to Target Here"               - right-click XFG site; navigate to target
                                        (chooser on hash collision); BN does not expose
                                        user-set indirect branches as a navigable token
                                        in HLIL, so this is the primary navigation aid
    "Resolve in This Function"        - right-click function; resolve every site in it
    "Remove in This Function"         - right-click function; clear every site in it
    "Resolve All"                     - whole binary; finds the indirect call (FF /2)
                                        after each movabs r10 and registers targets via
                                        set_user_indirect_branches so HLIL can resolve
                                        (*(*ptr+N))(ptr) patterns
    "Remove All"                      - whole binary; clear all targets set by Resolve All

  XFG -> Reset Hash Map Cache         - invalidate the cached XFG hash map (use after
                                        adding/removing functions mid-session; the cache
                                        also self-invalidates when a slow-path scan
                                        finds a target the cache was missing)

Recommended keybindings (set in Settings -> Keybindings; BN does not let plugins
register hotkeys directly, so this is a manual one-time step per workstation):
  PluginCommand: XFG\\Indirect Calls\\Go to Target Here   ->  Shift+G
  PluginCommand: XFG\\Indirect Calls\\Resolve Here        ->  Shift+R
  PluginCommand: XFG\\Cross-References\\Find Here         ->  Shift+X

Install: copy to %APPDATA%\\Binary Ninja\\plugins\\
"""

import json as _json

from binaryninja import BinaryView, Function, PluginCommand, log_info
from binaryninja.enums import (
    MessageBoxButtonSet,
    MessageBoxButtonResult,
    MessageBoxIcon,
    TypeClass,
)
from binaryninja.interaction import (
    show_message_box,
    get_choice_input,
)
from binaryninja.plugin import BackgroundTaskThread

try:
    from binaryninja import Settings as _Settings
    _bn_settings = _Settings()
except Exception:
    _bn_settings = None


def _check_arch(bv: BinaryView, title: str) -> bool:
    """Bail with a clean message if bv is not x86_64."""
    if bv.arch is None or bv.arch.name != "x86_64":
        show_message_box(title, "This plugin requires an x86_64 binary.")
        return False
    return True


def _confirm(title: str, prompt: str) -> bool:
    """Show a Yes/No confirmation dialog. Returns True iff the user clicked Yes."""
    return (
        show_message_box(
            title,
            prompt,
            MessageBoxButtonSet.YesNoButtonSet,
            MessageBoxIcon.QuestionIcon,
        )
        == MessageBoxButtonResult.YesButton
    )


def _start_bg(title: str, fn, bv: BinaryView) -> None:
    """Run fn(bv, task) on a BackgroundTaskThread so the UI stays responsive."""

    class _Task(BackgroundTaskThread):
        def __init__(self) -> None:
            super().__init__(title, True)

        def run(self) -> None:
            try:
                fn(bv, self)
            finally:
                self.finish()

    _Task().start()

# movabs r10, imm64  →  REX.W|REX.B (0x49), opcode 0xB8+r10(2) = 0xBA
_MOVABS_R10_PREFIX = b"\x49\xba"
_PATTERN_LEN = len(_MOVABS_R10_PREFIX) + 8  # prefix + 8-byte immediate
_MAX_LOOKAHEAD = 64  # bytes to scan ahead of movabs r10 for the XFG-guarded call


def _read_xfg_hash(bv: BinaryView, func_start: int):
    """Return the 8-byte XFG hash stored at func_start-8, or None on failure."""
    raw = bv.read(func_start - 8, 8)
    if not raw or len(raw) < 8:
        return None
    h = int.from_bytes(raw, "little")
    if h & 0x01 == 0 or h in (0, 0xFFFFFFFFFFFFFFFF):
        return None  # bit 0 must be set in the stored hash; 0/all-FF = no hash
    return h


def _build_hash_map(bv: BinaryView) -> dict:
    """Build {func_hash_bit0_set: [func_start, ...]} for all XFG-protected functions."""
    m: dict[int, list[int]] = {}
    for func in bv.functions:
        h = _read_xfg_hash(bv, func.start)
        if h is None:
            continue
        m.setdefault(h, []).append(func.start)
    return m


_HASH_MAP_KEY = "xfg_xrefs:hash_map"


def _get_hash_map(bv: BinaryView) -> dict:
    """Return the cached XFG hash map for bv, building it on first use.

    Stored on bv.session_data under a plugin-namespaced key. Returned dict is
    treated as immutable by callers; never mutate it. The cache self-invalidates
    when _find_targets_for_hash falls back to a binary scan and locates a hash
    the cache was missing (see _record_slow_path_hit).
    """
    cached = bv.session_data.get(_HASH_MAP_KEY)
    if cached is not None:
        return cached
    m = _build_hash_map(bv)
    bv.session_data[_HASH_MAP_KEY] = m
    return m


def _reset_hash_map(bv: BinaryView) -> None:
    """Invalidate the cached XFG hash map and vtable disambiguation context for bv."""
    bv.session_data.pop(_HASH_MAP_KEY, None)
    bv.session_data.pop(_VTABLE_DISAMBIG_KEY, None)
    log_info("xfg_xrefs: hash map and vtable disambig caches cleared")


def _record_slow_path_hit(bv: BinaryView, func_hash: int, target_addrs: list) -> None:
    """Patch the cached hash map after a slow-path scan found a missing entry.

    The slow path runs when _find_targets_for_hash misses the cache and resorts
    to scanning bytes for the function-hash. If it finds something, the cache is
    out of date - record the new entry so subsequent calls don't re-scan.
    """
    cached = bv.session_data.get(_HASH_MAP_KEY)
    if cached is None:
        return
    cached[func_hash] = list(target_addrs)


# XFG hashes are type-prototype hashes, so every function with the same C++
# prototype (e.g. every IUnknown::Release override) shares one hash.  Adding
# an xref / indirect branch from each call site to *every* alias makes 199 of
# 200 entries false positives at any given site, multiplies the BNDB metadata
# size by the alias count, and is the dominant driver of save time, RAM usage,
# and tab-switch latency on RTTI-rich binaries.
#
# Strategy (configurable via BN Settings, see _register_settings below):
#   1. If <= 1 target: trivial, write it.
#   2. Try to narrow to the actual concrete target via vtable dispatch
#      analysis (slot_off + class_off + typed `this`).  Works inside RTTI
#      class methods whose `this` is typed.  Collapses 200 aliases to 1.
#   3. If narrowing fails and target count <= alias threshold: keep current
#      behavior (small fan-out is tolerable; BN handles it cleanly).
#   4. If narrowing fails and target count > alias threshold: write nothing.
#      The "XFG -> ..." comment still records the alias family for the user.
#
# The `metadataMode` setting overlays this with a stricter / more permissive
# write policy:
#   - "narrowed"      : full strategy above (default)
#   - "disambig_only" : only write metadata when narrowing collapsed the
#                       alias set to a single concrete target.  Recommended
#                       for large RTTI-rich binaries — this is where the
#                       indirect-branch CFG cascade dominates analysis cost.
#   - "none"          : never write xrefs / indirect branches; comments only.
#                       Maximum perf; navigation via 'Go to Target Here'.

_S_ALIAS_THRESHOLD = "xfg_xrefs.aliasThreshold"
_S_METADATA_MODE = "xfg_xrefs.metadataMode"
_DEFAULT_ALIAS_THRESHOLD = 16
_DEFAULT_METADATA_MODE = "narrowed"
_VALID_METADATA_MODES = ("narrowed", "disambig_only", "none")

_VTABLE_DISAMBIG_KEY = "xfg_xrefs:vtable_disambig_ctx"


def _register_settings() -> None:
    """Register plugin settings with Binary Ninja's settings system.

    Settings register at module import time.  Re-registering with the same
    schema is a no-op; mismatched schemas raise, which is why each call is
    wrapped in its own try/except — we don't want a stale cached schema from
    an earlier plugin version to abort the rest of registration.
    """
    if _bn_settings is None:
        return
    try:
        _bn_settings.register_group("xfg_xrefs", "XFG Xrefs")
    except Exception:
        pass
    try:
        _bn_settings.register_setting(_S_ALIAS_THRESHOLD, _json.dumps({
            "title": "XFG Alias Threshold",
            "type": "number",
            "default": _DEFAULT_ALIAS_THRESHOLD,
            "minValue": 1,
            "maxValue": 1024,
            "description": (
                "Maximum number of XFG hash aliases before a call site falls back "
                "to comment-only.  Hashes with more aliases than this skip xrefs "
                "and indirect branches to reduce BNDB metadata bloat.  Lower "
                "values produce smaller databases at the cost of less complete "
                "cross-reference coverage on small fan-out hashes."
            ),
        }))
    except Exception:
        pass
    try:
        _bn_settings.register_setting(_S_METADATA_MODE, _json.dumps({
            "title": "XFG Metadata Write Mode",
            "type": "string",
            "default": _DEFAULT_METADATA_MODE,
            "enum": list(_VALID_METADATA_MODES),
            "enumDescriptions": [
                "Write metadata to all narrowed targets up to alias threshold (balanced default).",
                "Only write metadata when disambiguation collapsed the alias set to a single concrete target.",
                "Never write xrefs or indirect branches; comments only.  Maximum perf; navigation via 'Go to Target Here'.",
            ],
            "description": (
                "Controls when 'Resolve' / 'Add' commands write user xrefs and "
                "indirect branch targets.  'disambig_only' is the recommended "
                "setting for large RTTI-rich binaries where the indirect-branch "
                "CFG cascade dominates analysis cost."
            ),
        }))
    except Exception:
        pass


def _get_alias_threshold() -> int:
    if _bn_settings is None:
        return _DEFAULT_ALIAS_THRESHOLD
    try:
        v = _bn_settings.get_integer(_S_ALIAS_THRESHOLD)
        return v if isinstance(v, int) and v > 0 else _DEFAULT_ALIAS_THRESHOLD
    except Exception:
        return _DEFAULT_ALIAS_THRESHOLD


def _get_metadata_mode() -> str:
    if _bn_settings is None:
        return _DEFAULT_METADATA_MODE
    try:
        m = _bn_settings.get_string(_S_METADATA_MODE)
        return m if m in _VALID_METADATA_MODES else _DEFAULT_METADATA_MODE
    except Exception:
        return _DEFAULT_METADATA_MODE


_register_settings()


def _get_vtable_disambig_ctx(bv: BinaryView):
    """Return a context for vtable-based XFG target disambiguation, or None.

    Soft-imports vtable_autodefine — both plugins live in the same plugins/
    directory and BN loads them as top-level modules.  Returns None (cached as
    False) when vtable_autodefine isn't loaded or the binary has no RTTI vtable
    symbols, in which case _narrow_targets falls back to the threshold cap.
    """
    cached = bv.session_data.get(_VTABLE_DISAMBIG_KEY)
    if cached is not None:
        return cached if cached is not False else None
    try:
        import vtable_autodefine as vad  # type: ignore
    except Exception:
        bv.session_data[_VTABLE_DISAMBIG_KEY] = False
        return None
    try:
        vtable_map = vad._find_vtable_symbols(bv)
    except Exception:
        bv.session_data[_VTABLE_DISAMBIG_KEY] = False
        return None
    if not vtable_map:
        bv.session_data[_VTABLE_DISAMBIG_KEY] = False
        return None
    ctx = {"vad": vad, "vtable_map": vtable_map}
    bv.session_data[_VTABLE_DISAMBIG_KEY] = ctx
    return ctx


def _class_from_pointed_type(target, vtable_map: dict) -> str | None:
    """Return the vtable_map key for the type a pointer targets, else None.

    Accepts both NamedTypeReference (typical after vtable_autodefine retypes
    function prototypes) and inline StructureType with a registered_name
    (rarer; happens when types were stamped without going through a named ref).
    """
    if target is None:
        return None
    try:
        if target.type_class == TypeClass.NamedTypeReferenceClass:
            name = str(target.name)
            return name if name in vtable_map else None
        if target.type_class == TypeClass.StructureTypeClass:
            reg = getattr(target, "registered_name", None)
            if reg:
                name = str(reg)
                return name if name in vtable_map else None
    except Exception:
        return None
    return None


def _calling_class_from_call_first_arg(
    bv: BinaryView, call_addr: int, vtable_map: dict
) -> str | None:
    """Tier-2 fallback: derive the class from the type of the call's first argument.

    On x86_64 fastcall the first argument is the dispatched object — for a
    virtual call `obj->Method(args...)`, MLIL renders it as `Method(obj, args)`
    with `obj` as params[0].  This handles the common case where the calling
    function itself is *not* a method of an RTTI class (free functions, helpers,
    WRL template glue) but the dispatched object IS typed as a registered
    struct, e.g. `m_completedHandler->Invoke(...)` where m_completedHandler is
    typed as a named-ref to ICompletedHandler.

    Note this only succeeds when the dispatched object's static type is itself
    a class with an RTTI vtable in vtable_map.  Calls through abstract
    interfaces with no concrete vtable symbol (most pure-COM IFoo*) still fall
    through to comment-only.
    """
    funcs = bv.get_functions_containing(call_addr)
    if not funcs:
        return None
    func = funcs[0]
    try:
        mlil_insn = func.get_medium_level_il_at(call_addr)
    except Exception:
        return None
    if mlil_insn is None:
        return None

    # MLIL_CALL / MLIL_TAILCALL / MLIL_CALL_UNTYPED all expose .params; pull
    # them defensively since the exact operation set differs across BN
    # versions.  An empty params list (e.g. niladic call) means we can't help.
    params = None
    try:
        params = list(mlil_insn.params)
    except Exception:
        return None
    if not params:
        return None

    first = params[0]
    et = None
    try:
        et = first.expr_type
    except Exception:
        et = None
    if et is None:
        # Some MLIL forms expose the underlying variable directly; fall back to
        # the variable's declared type when expr_type isn't populated.
        try:
            et = first.var.type
        except Exception:
            et = None
    if et is None:
        return None
    try:
        if et.type_class != TypeClass.PointerTypeClass:
            return None
    except Exception:
        return None
    return _class_from_pointed_type(et.target, vtable_map)


def _try_vtable_disambig(
    bv: BinaryView, movabs_addr: int, targets: list, ctx
) -> list | None:
    """Resolve XFG aliases to a concrete single target via vtable dispatch.

    Returns [fp_addr] on success, or None if the call can't be narrowed (no
    vtable context, non-vtable dispatch shape, no class match, fp not in
    alias set, etc.).
    """
    if ctx is None:
        return None
    vad = ctx["vad"]
    vtable_map = ctx["vtable_map"]

    call_addr = _find_xfg_call(bv, movabs_addr)
    if call_addr is None:
        return None

    try:
        slot_offset, vtable_class_offset = vad._get_vtable_dispatch_info(bv, call_addr)
    except Exception:
        return None
    if slot_offset is None:
        return None

    # Tier 1: function name → class via RTTI prefix match.
    try:
        calling_class = vad._get_calling_class(bv, call_addr, vtable_map)
    except Exception:
        calling_class = None

    # Tier 2: type of the call's first MLIL argument (the dispatched object).
    # Catches dispatches through member fields and through interface pointers
    # in helper/free functions, where Tier 1 returns None.
    if not calling_class or calling_class not in vtable_map:
        calling_class = _calling_class_from_call_first_arg(bv, call_addr, vtable_map)
    if not calling_class or calling_class not in vtable_map:
        return None

    class_addrs = [a for a, _ in vtable_map[calling_class]]
    try:
        cache = vad._offset_cache(bv)
        missing = [a for a in class_addrs if a not in cache]
        if missing:
            for a, off in vad._find_class_offsets(bv, missing).items():
                cache[a] = off
    except Exception:
        return None

    matching_vtable = None
    if vtable_class_offset is not None:
        for a in class_addrs:
            if cache.get(a) == vtable_class_offset:
                matching_vtable = a
                break
    elif len(class_addrs) == 1:
        matching_vtable = class_addrs[0]
    if matching_vtable is None:
        return None

    raw = bv.read(matching_vtable + slot_offset, 8)
    if not raw or len(raw) < 8:
        return None
    fp_addr = int.from_bytes(raw, "little")
    if fp_addr == 0 or fp_addr not in targets:
        return None
    return [fp_addr]


def _narrow_targets(
    bv: BinaryView, movabs_addr: int, targets: list, ctx
) -> list | None:
    """Reduce alias-rich XFG target lists via vtable dispatch or threshold cap.

    Returns:
      * list[int] - targets to write metadata (xrefs / indirect branches) for
      * None      - alias-rich and undisambiguable; caller should write the
                    'XFG ->' comment but skip metadata to avoid BNDB bloat
    """
    if len(targets) <= 1:
        return list(targets)
    narrowed = _try_vtable_disambig(bv, movabs_addr, targets, ctx)
    if narrowed is not None:
        return narrowed
    if len(targets) <= _get_alias_threshold():
        return list(targets)
    return None


def _final_targets_to_write(
    bv: BinaryView, movabs_addr: int, targets: list, ctx, mode: str | None = None
) -> tuple[list, str]:
    """Apply alias threshold + metadata mode and return what should be written.

    Returns (targets_to_write, status):
      * status "ok"               - len>0, len(targets) <= 1 OR not a disambig case
      * status "ok-disambig"      - narrowed from many aliases to a single concrete
      * status "skip-mode-none"   - mode=none, write nothing
      * status "skip-alias"       - alias-rich and undisambiguable
      * status "skip-not-disambig"- mode=disambig_only and we couldn't narrow to 1

    Centralising the decision here keeps `_resolve_one_xfg_site`, `_do_add_all`,
    and `_run_for_func` consistent with each other and with the BN settings.
    """
    if mode is None:
        mode = _get_metadata_mode()
    if mode == "none":
        return [], "skip-mode-none"

    narrowed = _narrow_targets(bv, movabs_addr, targets, ctx)
    if narrowed is None:
        return [], "skip-alias"

    # "High confidence" means we know exactly one concrete target — either the
    # hash had one alias to begin with (trivial) or vtable disambig collapsed a
    # multi-alias set down to one.  `disambig_only` mode includes both: a
    # 1-alias hash is the highest-confidence case there is, and excluding it
    # would silently drop ~all single-target XFG calls from indirect-branch
    # metadata for no perf benefit.
    is_disambig = len(targets) > 1 and len(narrowed) == 1
    if mode == "disambig_only" and len(narrowed) > 1:
        return [], "skip-not-disambig"

    return narrowed, "ok-disambig" if is_disambig else "ok"


def _search_pattern(bv: BinaryView, call_hash: int) -> list[int]:
    """Return all addresses of `movabs r10, call_hash` in the binary."""
    pattern = _MOVABS_R10_PREFIX + call_hash.to_bytes(8, "little")
    hits: list[int] = []
    addr = bv.start
    while True:
        found = bv.find_next_data(addr, pattern)
        if found is None:
            break
        hits.append(found)
        addr = found + _PATTERN_LEN
    return hits


def _add_xref(bv: BinaryView, from_addr: int, to_addr: int) -> bool:
    """Add a user code xref from_addr -> to_addr. Returns True on success."""
    callers = bv.get_functions_containing(from_addr)
    if not callers:
        return False
    callers[0].add_user_code_ref(from_addr, to_addr)
    return True


def _remove_xref(bv: BinaryView, from_addr: int, to_addr: int) -> bool:
    """Remove a user code xref from_addr -> to_addr. Returns True on success."""
    callers = bv.get_functions_containing(from_addr)
    if not callers:
        return False
    callers[0].remove_user_code_ref(from_addr, to_addr)
    return True


def _is_indirect_call_at(bv: BinaryView, addr: int) -> bool:
    """Return True if addr holds an x86-64 indirect CALL (FF /2).

    XFG dispatches through `call qword [rip+offset]` (FF 15 ...) which is the
    __guard_xfg_dispatch_icall_fptr trampoline.  That encoding has ModRM 0x15
    (00 010 101), so reg==2 — caught by this check along with all other
    indirect call forms (call [reg], call [reg+disp8/32], etc.).
    """
    data = bv.read(addr, 8)
    if not data:
        return False
    i = 0
    while i < len(data) and 0x40 <= data[i] <= 0x4F:  # skip REX prefixes
        i += 1
    if i >= len(data) or data[i] != 0xFF:
        return False
    i += 1
    if i >= len(data):
        return False
    return ((data[i] >> 3) & 0x7) == 2  # ModRM reg == 2 → CALL r/m64


def _find_targets_for_hash(bv: BinaryView, call_hash: int, hash_map: dict) -> list[int]:
    """Return target function addresses for call_hash.

    Uses the pre-built hash map (fast path for already-analyzed functions) and
    falls back to a raw binary search for the stored hash value when the target
    hasn't been added to bv.functions yet.  The stored XFG hash is func_hash
    (bit 0 set) located 8 bytes before the function entry point.

    A successful slow-path scan also patches the session cache so repeated
    lookups for this hash don't re-scan the binary.
    """
    func_hash = call_hash | 0x01
    known = hash_map.get(func_hash)
    if known:
        return known

    hash_bytes = func_hash.to_bytes(8, "little")
    targets: list[int] = []
    addr = bv.start
    while True:
        found = bv.find_next_data(addr, hash_bytes)
        if found is None:
            break
        targets.append(found + 8)
        addr = found + 8

    if targets:
        _record_slow_path_hit(bv, func_hash, targets)
    return targets


def _find_xfg_call(bv: BinaryView, movabs_addr: int) -> int | None:
    """Find the indirect CALL that the movabs r10 at movabs_addr guards.

    MSVC places argument-setup instructions (MOV, LEA, etc.) between the
    `movabs r10, hash` and the `call qword [__guard_xfg_dispatch_icall_fptr]`.
    Walk forward instruction-by-instruction until we hit the first FF /2 call
    or a block terminator (ret, jmp, Jcc, another movabs r10).
    """
    arch = bv.arch
    addr = movabs_addr + _PATTERN_LEN
    end = addr + _MAX_LOOKAHEAD

    while addr < end:
        if _is_indirect_call_at(bv, addr):
            return addr

        data = bv.read(addr, 16)
        if not data:
            break

        # Strip optional REX prefix to examine the base opcode for terminators.
        i = 0
        while i < len(data) and 0x40 <= data[i] <= 0x4F:
            i += 1

        if i < len(data):
            b = data[i]
            if b in (0xC2, 0xC3, 0xCA, 0xCB):  # RET family
                break
            if b in (0xE9, 0xEB):  # near / short JMP
                break
            if 0x70 <= b <= 0x7F:  # short Jcc
                break
            if b == 0x0F and (i + 1) < len(data) and 0x80 <= data[i + 1] <= 0x8F:  # near Jcc
                break
            if b == 0xFF and (i + 1) < len(data) and ((data[i + 1] >> 3) & 7) == 4:  # JMP r/m64
                break

        # A second movabs r10 means a new XFG site — we've overshot.
        if data[:2] == _MOVABS_R10_PREFIX:
            break

        info = arch.get_instruction_info(data, addr)
        if info is None or info.length == 0:
            break
        addr += info.length

    return None


def _run_for_func(bv: BinaryView, func_start: int, func_name: str) -> None:
    """Find all XFG call sites for the function at func_start and register xrefs."""
    raw_hash = _read_xfg_hash(bv, func_start)
    if raw_hash is None:
        show_message_box(
            "XFG Xrefs",
            f"No valid XFG hash at {func_start - 8:#x}.\n"
            "The function may not be XFG-protected, or the bytes before it\n"
            "are unmapped / do not have bit 0 set.",
        )
        return

    call_hash = raw_hash & ~0x01  # call sites load hash with bit 0 cleared
    hits = _search_pattern(bv, call_hash)

    if not hits:
        log_info(
            f"xfg_xrefs: {func_name} @ {func_start:#x} - no XFG call sites "
            f"(call-site hash {call_hash:#018x})"
        )
        show_message_box(
            "XFG Xrefs",
            f"No XFG call sites found for {func_name}.\n\n"
            f"XFG hash      : {raw_hash:#018x}\n"
            f"Call-site hash: {call_hash:#018x}\n\n"
            "Note: results include type-hash aliases (same prototype, different function).",
        )
        return

    # Use _find_targets_for_hash so per-site narrowing can decide whether this
    # site's call actually dispatches to func_start vs another alias.
    hash_map = _get_hash_map(bv)
    targets = _find_targets_for_hash(bv, call_hash, hash_map)
    ctx = _get_vtable_disambig_ctx(bv)
    mode = _get_metadata_mode()

    bv.begin_undo_actions()
    added = 0
    skipped = 0
    skipped_by_mode: dict[str, int] = {}
    skipped_other_alias = 0  # narrowing identified a different alias as the target
    for site in sorted(hits):
        write_targets, write_status = _final_targets_to_write(
            bv, site, targets, ctx, mode
        )
        if not write_targets:
            skipped_by_mode[write_status] = skipped_by_mode.get(write_status, 0) + 1
            continue
        if func_start not in write_targets:
            skipped_other_alias += 1
            continue
        if _add_xref(bv, site, func_start):
            added += 1
        else:
            skipped += 1
    bv.commit_undo_actions()
    parts = [f"{added} xref(s) added"]
    if skipped:
        parts.append(f"{skipped} skipped (call site not in function)")
    if skipped_other_alias:
        parts.append(f"{skipped_other_alias} skipped (narrowed to a different alias)")
    skipped_alias = skipped_by_mode.get("skip-alias", 0)
    if skipped_alias:
        parts.append(f"{skipped_alias} skipped (>{_get_alias_threshold()} aliases, no vtable disambig)")
    if skipped_by_mode.get("skip-mode-none", 0):
        parts.append(f"{skipped_by_mode['skip-mode-none']} skipped (mode=none)")
    if skipped_by_mode.get("skip-not-disambig", 0):
        parts.append(f"{skipped_by_mode['skip-not-disambig']} skipped (mode=disambig_only, not unique)")
    log_info(f"xfg_xrefs: {func_name} (mode={mode}) - " + ", ".join(parts))


def _cmd_for_address(bv: BinaryView, addr: int) -> None:
    """Right-click command: find XFG xrefs for the function containing addr."""
    if not _check_arch(bv, "XFG Xrefs"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box("XFG Xrefs", f"No function found at {addr:#x}.")
        return
    _run_for_func(bv, funcs[0].start, funcs[0].name)


def _cmd_for_function(bv: BinaryView, func: Function) -> None:
    """Right-click command: find XFG xrefs for func."""
    if not _check_arch(bv, "XFG Xrefs"):
        return
    _run_for_func(bv, func.start, func.name)


def _do_add_all(bv: BinaryView, task: BackgroundTaskThread) -> None:
    """Background worker for Add All XFG Cross-References."""
    task.progress = "XFG: building function hash map..."
    hash_map = _get_hash_map(bv)
    if not hash_map:
        show_message_box(
            "Add All XFG Xrefs", "No XFG-protected functions found in this binary."
        )
        return

    log_info(
        f"xfg_xrefs: found {len(hash_map)} unique XFG hashes across {sum(len(v) for v in hash_map.values())} function(s)"
    )

    ctx = _get_vtable_disambig_ctx(bv)
    bv.begin_undo_actions()
    added = 0
    skipped = 0
    skipped_by_mode: dict[str, int] = {}
    disambiguated = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, _MOVABS_R10_PREFIX)
        if found is None:
            break

        hash_bytes = bv.read(found + 2, 8)
        if not hash_bytes or len(hash_bytes) < 8:
            addr = found + 1
            continue

        call_hash = int.from_bytes(hash_bytes, "little")
        func_hash = call_hash | 0x01

        targets = hash_map.get(func_hash)
        if targets:
            write_targets, write_status = _final_targets_to_write(
                bv, found, targets, ctx
            )
            if not write_targets:
                skipped_by_mode[write_status] = skipped_by_mode.get(write_status, 0) + 1
            else:
                if write_status == "ok-disambig":
                    disambiguated += 1
                for target in write_targets:
                    if _add_xref(bv, found, target):
                        added += 1
                    else:
                        skipped += 1

        sites += 1
        if sites % 64 == 0:
            task.progress = (
                f"XFG: scanning sites... {sites} found, "
                f"{added} xrefs added, {disambiguated} disambig"
            )
        addr = found + _PATTERN_LEN

    bv.commit_undo_actions()
    skipped_alias = skipped_by_mode.get("skip-alias", 0)
    skipped_mode_none = skipped_by_mode.get("skip-mode-none", 0)
    skipped_not_disambig = skipped_by_mode.get("skip-not-disambig", 0)
    mode = _get_metadata_mode()
    log_info(
        f"xfg_xrefs: done (mode={mode}) - {added} xref(s) added, "
        f"{disambiguated} site(s) disambiguated to 1, "
        f"{skipped_alias} skipped (alias-rich), "
        f"{skipped_mode_none} skipped (mode=none), "
        f"{skipped_not_disambig} skipped (mode=disambig_only, not unique), "
        f"{skipped} skipped (call site not in any function)"
    )
    show_message_box(
        "Add All XFG Xrefs",
        f"Scan complete (mode={mode}){' (cancelled)' if task.cancelled else ''}.\n\n"
        f"  Xrefs added            : {added}\n"
        f"  Disambiguated to 1     : {disambiguated}\n"
        f"  Skipped (alias-rich)   : {skipped_alias} (>{_get_alias_threshold()} aliases, no vtable disambig)\n"
        f"  Skipped (mode=none)    : {skipped_mode_none}\n"
        f"  Skipped (need disambig): {skipped_not_disambig}\n"
        f"  Skipped (no func)      : {skipped}\n\n"
        "Added xrefs are visible in the cross-references panel and can be\n"
        "undone via Edit -> Undo.",
    )


def _cmd_add_all(bv: BinaryView) -> None:
    """Scan the entire binary and register every resolvable XFG xref."""
    if not _check_arch(bv, "Add All XFG Xrefs"):
        return
    _start_bg("XFG: adding all cross-references...", _do_add_all, bv)


def _do_remove_all(bv: BinaryView, task: BackgroundTaskThread) -> None:
    """Background worker for Remove All XFG Cross-References."""
    task.progress = "XFG: building function hash map..."
    hash_map = _get_hash_map(bv)
    if not hash_map:
        show_message_box("Remove All XFG Xrefs", "No XFG-protected functions found.")
        return

    bv.begin_undo_actions()
    removed = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, _MOVABS_R10_PREFIX)
        if found is None:
            break

        hash_bytes = bv.read(found + 2, 8)
        if not hash_bytes or len(hash_bytes) < 8:
            addr = found + 1
            continue

        call_hash = int.from_bytes(hash_bytes, "little")
        func_hash = call_hash | 0x01

        targets = hash_map.get(func_hash)
        if targets:
            for target in targets:
                if _remove_xref(bv, found, target):
                    removed += 1

        sites += 1
        if sites % 64 == 0:
            task.progress = f"XFG: clearing xrefs... {removed} removed"
        addr = found + _PATTERN_LEN

    bv.commit_undo_actions()
    show_message_box(
        "Remove All XFG Xrefs",
        f"Removed {removed} XFG xref(s){' (cancelled)' if task.cancelled else ''}.",
    )


def _cmd_remove_all(bv: BinaryView) -> None:
    """Remove all XFG xrefs previously added by this plugin."""
    if not _check_arch(bv, "Remove All XFG Xrefs"):
        return
    if not _confirm(
        "Remove All XFG Cross-References",
        "Remove ALL XFG cross-references previously added by this plugin?\n\n"
        "This walks the entire binary and clears every user xref at a movabs r10 site.",
    ):
        return
    _start_bg("XFG: removing all cross-references...", _do_remove_all, bv)


def _comment_for_targets(bv: BinaryView, targets: list[int]) -> str:
    """Build a compact XFG comment, deduplicating type aliases by their short symbol name.

    Many XFG hashes map to dozens of identically-prototyped functions (e.g. every
    IUnknown::Release implementation).  Using the short symbol name collapses all
    of those aliases to a single token so the comment stays readable.
    """
    short_names: list[str] = []
    for t in targets:
        f = bv.get_function_at(t)
        if f is None:
            short_names.append(hex(t))
        else:
            sym = f.symbol
            short_names.append(sym.short_name if sym else f.name)

    unique = list(dict.fromkeys(short_names))  # deduplicate, preserve first-seen order

    if len(unique) == 1:
        suffix = f" ({len(targets)} implementations)" if len(targets) > 1 else ""
        return f"XFG -> {unique[0]}{suffix}"

    shown = unique[:3]
    rest = len(unique) - len(shown)
    label = ", ".join(shown) + (f" (+{rest} more)" if rest else "")
    return f"XFG -> {label}"


def _resolve_one_xfg_site(
    bv: BinaryView, movabs_addr: int, hash_map: dict, ctx=None
) -> tuple[str, str]:
    """Apply XFG branch targets and 'XFG -> ...' comment at one movabs r10 site.

    Returns (status, comment) where status is one of:
        "resolved", "resolved-disambig", "resolved-comment-only",
        "no-targets", "no-call", "no-func"

    "resolved-disambig"     : alias list narrowed to 1 concrete target via vtable
    "resolved-comment-only" : alias-rich, no vtable disambig - comment only,
                              no indirect branches written (avoids BNDB bloat)
    """
    hash_bytes = bv.read(movabs_addr + 2, 8)
    if not hash_bytes or len(hash_bytes) < 8:
        return "no-targets", ""
    call_hash = int.from_bytes(hash_bytes, "little")
    targets = _find_targets_for_hash(bv, call_hash, hash_map)
    if not targets:
        return "no-targets", ""
    call_addr = _find_xfg_call(bv, movabs_addr)
    if call_addr is None:
        return "no-call", ""
    funcs = bv.get_functions_containing(call_addr)
    if not funcs:
        return "no-func", ""
    # Comment always reflects the full alias family so the user sees the
    # prototype shape and total count, even when narrowing collapsed the
    # indirect-branch list to a single concrete target.
    comment = _comment_for_targets(bv, targets)
    bv.set_comment_at(call_addr, comment)

    write_targets, write_status = _final_targets_to_write(
        bv, movabs_addr, targets, ctx
    )
    if not write_targets:
        # Skipped writing indirect branches: mode=none, alias-rich, or
        # mode=disambig_only without a unique target.  All paths still keep
        # the comment so the user can navigate via 'Go to Target Here'.
        return "resolved-comment-only", comment
    funcs[0].set_user_indirect_branches(
        call_addr, [(bv.arch, t) for t in write_targets]
    )
    if write_status == "ok-disambig":
        return "resolved-disambig", comment
    return "resolved", comment


def _clear_one_xfg_site(bv: BinaryView, movabs_addr: int) -> str:
    """Clear XFG branch targets and comment at one movabs r10 site.

    Returns one of: "cleared", "no-call", "no-func".

    Does NOT require a hash match - cleanup must succeed even when the
    original target was renamed, deleted, or its function-hash byte changed.
    """
    call_addr = _find_xfg_call(bv, movabs_addr)
    if call_addr is None:
        return "no-call"
    funcs = bv.get_functions_containing(call_addr)
    if not funcs:
        return "no-func"
    funcs[0].set_user_indirect_branches(call_addr, [])
    bv.set_comment_at(call_addr, "")
    return "cleared"


def _enumerate_xfg_sites_in_range(
    bv: BinaryView, start: int, end: int
) -> list[tuple[int, int | None]]:
    """Return [(movabs_addr, call_addr_or_None), ...] for every movabs r10 in [start, end)."""
    sites: list[tuple[int, int | None]] = []
    addr = start
    while addr < end:
        found = bv.find_next_data(addr, _MOVABS_R10_PREFIX)
        if found is None or found >= end:
            break
        sites.append((found, _find_xfg_call(bv, found)))
        addr = found + _PATTERN_LEN
    return sites


def _xfg_site_at(
    bv: BinaryView, addr: int, func: Function
) -> tuple[int, int | None] | None:
    """Return (movabs_addr, call_addr) of the XFG site that owns addr, else None.

    Owning means cursor is on the movabs r10, on the guarded indirect call, or
    anywhere in between within the same function range.
    """
    try:
        ranges = list(func.address_ranges)
    except Exception:
        ranges = []
    if not ranges:
        ranges = [type("R", (), {"start": func.start, "end": func.start + func.total_bytes})()]
    for r in ranges:
        for movabs_addr, call_addr in _enumerate_xfg_sites_in_range(bv, r.start, r.end):
            upper = call_addr if call_addr is not None else movabs_addr + _MAX_LOOKAHEAD
            if movabs_addr <= addr <= upper:
                return (movabs_addr, call_addr)
    return None


def _do_resolve_indirect_calls(bv: BinaryView, task: BackgroundTaskThread) -> None:
    """Background worker for Resolve All XFG Indirect Call Targets."""
    task.progress = "XFG: building function hash map..."
    hash_map = _get_hash_map(bv)
    if not hash_map:
        show_message_box(
            "Resolve XFG Indirect Call Targets",
            "No XFG-protected functions found in this binary.",
        )
        return

    log_info(
        f"xfg_xrefs: found {len(hash_map)} unique XFG hashes across "
        f"{sum(len(v) for v in hash_map.values())} function(s)"
    )

    ctx = _get_vtable_disambig_ctx(bv)
    bv.begin_undo_actions()
    resolved = 0
    disambig = 0
    comment_only = 0
    skipped_no_call = 0
    skipped_no_func = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, _MOVABS_R10_PREFIX)
        if found is None:
            break

        status, _ = _resolve_one_xfg_site(bv, found, hash_map, ctx)
        if status == "resolved":
            resolved += 1
        elif status == "resolved-disambig":
            disambig += 1
            resolved += 1
        elif status == "resolved-comment-only":
            comment_only += 1
        elif status == "no-call":
            skipped_no_call += 1
        elif status == "no-func":
            skipped_no_func += 1

        sites += 1
        if sites % 32 == 0:
            task.progress = (
                f"XFG: resolving... {resolved}/{sites} resolved, "
                f"{disambig} disambig, {comment_only} comment-only"
            )
        addr = found + _PATTERN_LEN

    bv.commit_undo_actions()
    bv.update_analysis()
    mode = _get_metadata_mode()
    log_info(
        f"xfg_xrefs: indirect call resolution done (mode={mode}) - {resolved} site(s) resolved "
        f"({disambig} disambiguated to 1 via vtable), {comment_only} comment-only, "
        f"{skipped_no_call} skipped (no XFG call found), "
        f"{skipped_no_func} skipped (not in function)"
    )
    show_message_box(
        "Resolve XFG Indirect Call Targets",
        f"Scan complete (mode={mode}){' (cancelled)' if task.cancelled else ''}.\n\n"
        f"  Resolved (full)       : {resolved}\n"
        f"  -- of which disambig'd: {disambig} (alias-rich, narrowed to 1 via vtable)\n"
        f"  Comment only          : {comment_only} (alias>{_get_alias_threshold()} or mode-restricted)\n"
        f"  Skipped (no call)     : {skipped_no_call}\n"
        f"  Skipped (no func)     : {skipped_no_func}\n\n"
        "Resolved call sites have an 'XFG -> FuncName' comment in HLIL.  Sites with\n"
        "indirect branch targets also show CFG edges; comment-only sites skip those\n"
        "to avoid BNDB bloat / analysis cascade.  Adjust via Settings → XFG Xrefs.\n\n"
        "Undo via Edit -> Undo.",
    )


def _cmd_resolve_indirect_calls(bv: BinaryView) -> None:
    """Scan for XFG sites, annotate the guarded call with a comment, and set indirect branch targets."""
    if not _check_arch(bv, "Resolve XFG Indirect Call Targets"):
        return
    _start_bg(
        "XFG: resolving all indirect call targets...",
        _do_resolve_indirect_calls,
        bv,
    )


def _do_remove_indirect_calls(bv: BinaryView, task: BackgroundTaskThread) -> None:
    """Background worker for Remove All XFG Indirect Branch Targets."""
    task.progress = "XFG: clearing branch targets..."

    bv.begin_undo_actions()
    cleared = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, _MOVABS_R10_PREFIX)
        if found is None:
            break

        if _clear_one_xfg_site(bv, found) == "cleared":
            cleared += 1

        sites += 1
        if sites % 64 == 0:
            task.progress = f"XFG: clearing branch targets... {cleared} cleared"
        addr = found + _PATTERN_LEN

    bv.commit_undo_actions()
    bv.update_analysis()
    show_message_box(
        "Remove XFG Indirect Branch Targets",
        f"Cleared indirect branch targets at {cleared} call site(s)"
        f"{' (cancelled)' if task.cancelled else ''}.",
    )


def _cmd_remove_indirect_calls(bv: BinaryView) -> None:
    """Clear user-set indirect branch targets previously added at XFG call sites."""
    if not _check_arch(bv, "Remove XFG Indirect Branch Targets"):
        return
    if not _confirm(
        "Remove All XFG Indirect Branch Targets",
        "Clear ALL user-set indirect branch targets and 'XFG ->' comments at every "
        "XFG-guarded call site in this binary?",
    ):
        return
    _start_bg(
        "XFG: removing all indirect branch targets...",
        _do_remove_indirect_calls,
        bv,
    )


def _cmd_resolve_here(bv: BinaryView, addr: int) -> None:
    """Right-click: resolve the single XFG call site at the address under the cursor."""
    if not _check_arch(bv, "Resolve XFG Call Target Here"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box(
            "Resolve XFG Call Target Here",
            f"No function contains {addr:#x}.",
        )
        return
    site = _xfg_site_at(bv, addr, funcs[0])
    if site is None:
        show_message_box(
            "Resolve XFG Call Target Here",
            f"No XFG call site at {addr:#x}.\n\n"
            "Place the cursor on the 'movabs r10' or on the guarded indirect call.",
        )
        return
    movabs_addr, call_addr = site
    hash_map = _get_hash_map(bv)
    ctx = _get_vtable_disambig_ctx(bv)

    bv.begin_undo_actions()
    status, comment = _resolve_one_xfg_site(bv, movabs_addr, hash_map, ctx)
    bv.commit_undo_actions()
    bv.update_analysis()

    if status in ("resolved", "resolved-disambig", "resolved-comment-only") and call_addr is not None:
        log_info(f"xfg_xrefs: {status} @ {call_addr:#x} (movabs @ {movabs_addr:#x}) - {comment}")
    elif status == "no-call":
        show_message_box(
            "Resolve XFG Call Target Here",
            f"Found movabs r10 @ {movabs_addr:#x} but couldn't locate the guarded call.",
        )
    elif status == "no-func":
        show_message_box(
            "Resolve XFG Call Target Here",
            "The guarded call address is not inside any function.",
        )
    else:
        show_message_box(
            "Resolve XFG Call Target Here",
            f"No XFG targets matched the hash at {movabs_addr:#x}.",
        )


def _cmd_remove_here(bv: BinaryView, addr: int) -> None:
    """Right-click: clear the single XFG call site at the address under the cursor."""
    if not _check_arch(bv, "Remove XFG Call Target Here"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box(
            "Remove XFG Call Target Here",
            f"No function contains {addr:#x}.",
        )
        return
    site = _xfg_site_at(bv, addr, funcs[0])
    if site is None:
        show_message_box(
            "Remove XFG Call Target Here",
            f"No XFG call site at {addr:#x}.\n\n"
            "Place the cursor on the 'movabs r10' or on the guarded indirect call.",
        )
        return
    movabs_addr, call_addr = site

    bv.begin_undo_actions()
    status = _clear_one_xfg_site(bv, movabs_addr)
    bv.commit_undo_actions()
    bv.update_analysis()

    if status == "cleared" and call_addr is not None:
        log_info(f"xfg_xrefs: cleared XFG annotations at {call_addr:#x}")
    else:
        show_message_box(
            "Remove XFG Call Target Here",
            f"Could not clear XFG site at {movabs_addr:#x} ({status}).",
        )


def _cmd_goto_xfg_target(bv: BinaryView, addr: int) -> None:
    """Right-click: navigate to the target of the XFG-guarded call at the cursor.

    BN does not surface user-set indirect branches as a clickable affordance in
    HLIL, and even in disassembly view the XFG dispatch trampoline obscures the
    target.  This command resolves the type-hash for the call site under the
    cursor and navigates directly; on hash collisions it pops a chooser.
    """
    if not _check_arch(bv, "Go to XFG Target"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box("Go to XFG Target", f"No function contains {addr:#x}.")
        return
    site = _xfg_site_at(bv, addr, funcs[0])
    if site is None:
        show_message_box(
            "Go to XFG Target",
            f"No XFG call site at {addr:#x}.\n\n"
            "Place the cursor on the 'movabs r10' or on the guarded indirect call.",
        )
        return
    movabs_addr, _call_addr = site

    hash_bytes = bv.read(movabs_addr + 2, 8)
    if not hash_bytes or len(hash_bytes) < 8:
        show_message_box(
            "Go to XFG Target", f"Could not read XFG hash at {movabs_addr:#x}."
        )
        return
    call_hash = int.from_bytes(hash_bytes, "little")

    hash_map = _get_hash_map(bv)
    targets = _find_targets_for_hash(bv, call_hash, hash_map)
    if not targets:
        show_message_box(
            "Go to XFG Target",
            f"No target functions match the XFG hash at {movabs_addr:#x}.",
        )
        return

    # Try vtable disambiguation first - on alias-rich hashes this collapses
    # 200 candidates to the single function the call actually dispatches to.
    # If narrowing returns None (alias-rich AND undisambiguable) we fall back
    # to the full chooser since the user explicitly asked to navigate.
    ctx = _get_vtable_disambig_ctx(bv)
    narrowed = _try_vtable_disambig(bv, movabs_addr, targets, ctx)
    nav_targets = narrowed if narrowed is not None else targets

    if len(nav_targets) == 1:
        target = nav_targets[0]
    else:
        labels: list[str] = []
        for t in nav_targets:
            f = bv.get_function_at(t)
            if f is None:
                labels.append(f"<no function>  ({t:#x})")
                continue
            sym = f.symbol
            name = sym.short_name if sym else f.name
            labels.append(f"{name}  ({t:#x})")
        choice = get_choice_input(
            f"Multiple targets share XFG hash {call_hash:#018x}.\nSelect target:",
            "Go to XFG Target",
            labels,
        )
        if choice is None:
            return
        target = nav_targets[choice]

    try:
        bv.file.navigate(bv.file.view, target)
    except Exception as e:
        show_message_box(
            "Go to XFG Target",
            f"Resolved target {target:#x} but navigation failed: {e}",
        )


def _cmd_resolve_in_func(bv: BinaryView, func: Function) -> None:
    """Right-click: resolve every XFG call site inside func."""
    if not _check_arch(bv, "Resolve XFG Call Targets in This Function"):
        return
    hash_map = _get_hash_map(bv)
    if not hash_map:
        show_message_box(
            "Resolve XFG Call Targets in This Function",
            "No XFG-protected functions found in this binary.",
        )
        return

    ctx = _get_vtable_disambig_ctx(bv)
    bv.begin_undo_actions()
    resolved = 0
    disambig = 0
    comment_only = 0
    skipped_no_call = 0
    skipped_no_func = 0
    skipped_no_targets = 0

    try:
        ranges = list(func.address_ranges)
    except Exception:
        ranges = []
    if not ranges:
        ranges = [type("R", (), {"start": func.start, "end": func.start + func.total_bytes})()]

    for r in ranges:
        for movabs_addr, _call in _enumerate_xfg_sites_in_range(bv, r.start, r.end):
            status, _ = _resolve_one_xfg_site(bv, movabs_addr, hash_map, ctx)
            if status == "resolved":
                resolved += 1
            elif status == "resolved-disambig":
                disambig += 1
                resolved += 1
            elif status == "resolved-comment-only":
                comment_only += 1
            elif status == "no-call":
                skipped_no_call += 1
            elif status == "no-func":
                skipped_no_func += 1
            elif status == "no-targets":
                skipped_no_targets += 1

    bv.commit_undo_actions()
    bv.update_analysis()
    mode = _get_metadata_mode()
    log_info(
        f"xfg_xrefs: resolved {resolved} XFG site(s) inside {func.name} "
        f"(mode={mode}, {disambig} via vtable disambig, {comment_only} comment-only)"
    )
    show_message_box(
        "Resolve XFG Call Targets in This Function",
        f"Function: {func.name}  (mode={mode})\n\n"
        f"  Resolved (full)       : {resolved}\n"
        f"  -- of which disambig'd: {disambig}\n"
        f"  Comment only          : {comment_only} (alias-rich or mode-restricted)\n"
        f"  No call found         : {skipped_no_call}\n"
        f"  Call not in func      : {skipped_no_func}\n"
        f"  No matching hash      : {skipped_no_targets}\n\n"
        "Undo via Edit → Undo.",
    )


def _cmd_remove_in_func(bv: BinaryView, func: Function) -> None:
    """Right-click: clear every XFG call site inside func."""
    if not _check_arch(bv, "Remove XFG Call Targets in This Function"):
        return

    bv.begin_undo_actions()
    cleared = 0

    try:
        ranges = list(func.address_ranges)
    except Exception:
        ranges = []
    if not ranges:
        ranges = [type("R", (), {"start": func.start, "end": func.start + func.total_bytes})()]

    for r in ranges:
        for movabs_addr, _call in _enumerate_xfg_sites_in_range(bv, r.start, r.end):
            if _clear_one_xfg_site(bv, movabs_addr) == "cleared":
                cleared += 1

    bv.commit_undo_actions()
    bv.update_analysis()
    log_info(
        f"xfg_xrefs: cleared {cleared} XFG site(s) inside {func.name}"
    )
    show_message_box(
        "Remove XFG Call Targets in This Function",
        f"Cleared XFG annotations at {cleared} call site(s) in {func.name}.",
    )


# Menu hierarchy: backslash separates submenu levels in BN's PluginCommand registry.
# Top-level group is "XFG" with two subgroups - "Cross-References" (BN xrefs panel)
# and "Indirect Calls" (set_user_indirect_branches + comments).

# --- XFG\Cross-References --------------------------------------------------

PluginCommand.register_for_address(
    "XFG\\Cross-References\\Find Here",
    "Add XFG xrefs for the function at this address to the cross-references panel",
    _cmd_for_address,
)

PluginCommand.register_for_function(
    "XFG\\Cross-References\\Find in This Function",
    "Add XFG xrefs for this function to the cross-references panel",
    _cmd_for_function,
)

PluginCommand.register(
    "XFG\\Cross-References\\Add All",
    "Scan entire binary and add all resolvable XFG xrefs to the cross-references panel",
    _cmd_add_all,
)

PluginCommand.register(
    "XFG\\Cross-References\\Remove All",
    "Remove all XFG xrefs previously added by this plugin",
    _cmd_remove_all,
)

# --- XFG\Indirect Calls ----------------------------------------------------

PluginCommand.register_for_address(
    "XFG\\Indirect Calls\\Resolve Here",
    "Set indirect branch targets and 'XFG ->' comment on the XFG-guarded call at this address",
    _cmd_resolve_here,
)

PluginCommand.register_for_address(
    "XFG\\Indirect Calls\\Remove Here",
    "Clear indirect branch targets and 'XFG ->' comment on the XFG-guarded call at this address",
    _cmd_remove_here,
)

PluginCommand.register_for_address(
    "XFG\\Indirect Calls\\Go to Target Here",
    "Navigate to the target of the XFG-guarded call at this address (chooser on hash collision)",
    _cmd_goto_xfg_target,
)

PluginCommand.register_for_function(
    "XFG\\Indirect Calls\\Resolve in This Function",
    "Set indirect branch targets and 'XFG ->' comments on every XFG call site in this function",
    _cmd_resolve_in_func,
)

PluginCommand.register_for_function(
    "XFG\\Indirect Calls\\Remove in This Function",
    "Clear indirect branch targets and 'XFG ->' comments on every XFG call site in this function",
    _cmd_remove_in_func,
)

PluginCommand.register(
    "XFG\\Indirect Calls\\Resolve All",
    "Scan entire binary and register indirect branch targets at XFG-guarded call sites",
    _cmd_resolve_indirect_calls,
)

PluginCommand.register(
    "XFG\\Indirect Calls\\Remove All",
    "Remove user-set indirect branch targets previously added at XFG call sites",
    _cmd_remove_indirect_calls,
)

PluginCommand.register(
    "XFG\\Reset Hash Map Cache",
    "Invalidate the cached XFG hash map (use after adding/removing functions mid-session)",
    _reset_hash_map,
)
