"""
vtable_autodefine.py - Binary Ninja plugin: Auto-define vtable structs from RTTI symbols

For any class with RTTI-derived vtable symbols (e.g., CMsiEngine::`vftable'{for `IMsiEngine'}),
this plugin:
  1. Groups vtable symbols by class name
  2. Computes slot counts from address gaps + forward scan
  3. Creates typed VTable structs with function pointer fields
  4. Stamps the struct onto the vtable data variable
  5. Finds vtable pointer offsets via HLIL constructor analysis
  6. Updates the class struct with correctly-typed vtable pointer fields

Usage (grouped under Plugins -> VTables):
  "Auto-Define for All Classes"   - top-level menu
  "Auto-Define for This Class"    - right-click on a function or address
  "Navigate to Virtual Function"  - right-click on a call instruction address

Requires: RTTI symbols in the standard MSVC format produced by BN's RTTI analysis.

Recommended keybindings (set in Settings -> Keybindings; manual one-time step):
  PluginCommand: VTables\\Navigate to Virtual Function  ->  Ctrl+Shift+V

Install: copy to %APPDATA%\\Binary Ninja\\plugins\\
"""

import re
import struct
from binaryninja import (
    BinaryView,
    Function,
    PluginCommand,
    log_info,
    log_warn,
    demangle_ms,
)
from binaryninja.enums import (
    TypeClass,
    FunctionUpdateType,
    HighLevelILOperation,
    LowLevelILOperation,
    MediumLevelILOperation,
    SectionSemantics,
)
from binaryninja.types import Type, StructureBuilder, FunctionParameter
from binaryninja.interaction import show_message_box, get_choice_input
from binaryninja.plugin import BackgroundTaskThread

# Matches: "CMsiEngine::`vftable'" and "CMsiEngine::`vftable'{for `IMsiEngine'}"
_VTABLE_RE = re.compile(r"^(.+?)::`vftable'(?:\{for `(.+?)'\})?$")

# Maximum slots to scan forward when no bounding symbol is available
_MAX_SLOTS = 512

# Per-bv cache of {vtable_addr: class_byte_offset} stored on bv.session_data.
# Using session_data instead of a module-level dict avoids stale entries across
# different open binaries and clears automatically when a binary is closed.
_OFFSET_CACHE_KEY = "_vtable_class_offset_cache"


def _check_arch(bv: BinaryView, title: str) -> bool:
    """Bail with a clean message if bv is not x86_64."""
    if bv.arch is None or bv.arch.name != "x86_64":
        show_message_box(title, "This plugin requires an x86_64 binary.")
        return False
    return True


def _offset_cache(bv: BinaryView) -> dict:
    cache = bv.session_data.get(_OFFSET_CACHE_KEY)
    if cache is None:
        cache = {}
        bv.session_data[_OFFSET_CACHE_KEY] = cache
    return cache

# LLIL operations that form a basic-block boundary when scanning backward.
_LLIL_STOP_OPS = {
    LowLevelILOperation.LLIL_CALL,
    LowLevelILOperation.LLIL_TAILCALL,
    LowLevelILOperation.LLIL_JUMP,
    LowLevelILOperation.LLIL_JUMP_TO,
    LowLevelILOperation.LLIL_IF,
    LowLevelILOperation.LLIL_RET,
    LowLevelILOperation.LLIL_NORET,
}


def _find_vtable_symbols(bv: BinaryView) -> dict:
    """Return {class_name: [(addr, iface_name), ...]} sorted by address."""
    result: dict[str, list] = {}
    for sym in bv.get_symbols():
        m = _VTABLE_RE.match(sym.name)
        if m is None:
            continue
        class_name = m.group(1)
        iface_name = m.group(2) or class_name
        result.setdefault(class_name, []).append((sym.address, iface_name))
    for entries in result.values():
        entries.sort(key=lambda x: x[0])
    return result


def _all_vtable_addrs(vtable_map: dict) -> list:
    """Return all vtable start addresses sorted ascending."""
    addrs = []
    for entries in vtable_map.values():
        for addr, _ in entries:
            addrs.append(addr)
    return sorted(addrs)


def _is_code_pointer(bv: BinaryView, fp: int) -> bool:
    """Return True if fp is a vtable-eligible code pointer.

    Excludes external-section stubs (.extern / IAT thunks): they are
    executable and BN defines functions there, but they sit directly
    after vtables in .rdata and cause the slot scan to overshoot into
    unrelated data (including the XFG guard dispatch pointer).
    """
    if fp == 0:
        return False
    seg = bv.get_segment_at(fp)
    if seg is None or not seg.executable:
        return False
    if any(s.semantics == SectionSemantics.ExternalSectionSemantics
           for s in bv.get_sections_at(fp)):
        return False
    return True


def _scan_vtable_slots(bv: BinaryView, start: int, limit: int) -> int:
    """Count consecutive code pointers starting at start, stopping at limit.

    Accepts addresses in executable segments even if BN hasn't defined a
    function there yet - common for imported or not-yet-analyzed methods.
    """
    count = 0
    addr = start
    while addr < limit:
        raw = bv.read(addr, 8)
        if not raw or len(raw) < 8:
            break
        fp = int.from_bytes(raw, "little")
        if not _is_code_pointer(bv, fp):
            break
        count += 1
        addr += 8
    return count


def _compute_slot_counts(bv: BinaryView, entries: list, all_sorted_addrs: list) -> list:
    """Return [(addr, iface_name, n_slots), ...] using the next vtable address as an upper bound."""
    result = []
    for addr, iface_name in entries:
        next_addr = None
        for a in all_sorted_addrs:
            if a > addr:
                next_addr = a
                break
        limit = next_addr if next_addr is not None else addr + 8 * _MAX_SLOTS
        n_slots = _scan_vtable_slots(bv, addr, limit)
        result.append((addr, iface_name, n_slots))
    return result


def _strip_elaborated_type_keywords(name: str) -> str:
    """Remove C++ elaborated-type-specifier keywords (struct/class/enum) from a type name.

    BN's MSVC RTTI demangler includes these keywords verbatim (e.g.
    'struct IWeakReferenceSource'), which causes type names like
    'struct IFoo::VTable' and accumulates an extra 'struct ' prefix on
    every plugin run if the prior run's output is fed back as input.
    """
    return re.sub(r'\b(struct|class|enum|union)\s+', '', name).strip()


def _vtable_struct_name(iface_name: str) -> str:
    """Return a namespaced struct name like 'IMsiEngine::VTable'."""
    return f"{_strip_elaborated_type_keywords(iface_name)}::VTable"


def _slot_field_name(bv: BinaryView, func: "Function", slot_index: int) -> str:
    """Return a clean field name derived from the function's demangled last name component.

    Falls back to slot_<index> if the name can't be reduced to a valid identifier.
    """
    raw = func.name

    if raw.startswith("?"):
        try:
            _, name_parts = demangle_ms(bv.arch, raw)
            if name_parts:
                if isinstance(name_parts, str):
                    name_parts = name_parts.split("::")
                raw = name_parts[-1] if name_parts else raw
        except Exception:
            pass

    if "::" in raw:
        raw = raw.split("::")[-1]

    base = re.sub(r"[^a-zA-Z0-9_]", "_", raw).strip("_")
    if not base or base[0].isdigit():
        base = f"slot_{slot_index}"
    return base


def _create_vtable_struct(
    bv: BinaryView, vtable_addr: int, struct_name: str, n_slots: int
) -> set:
    """Define a packed struct with n_slots typed function pointer fields and stamp it onto the vtable data variable.

    Returns the set of Function objects whose signatures were used as field types
    so the caller can queue them for re-analysis.
    """
    builder = StructureBuilder.create()
    builder.packed = True
    updated_funcs: set = set()
    used_names: dict[str, int] = {}

    for i in range(n_slots):
        offset = i * 8
        raw = bv.read(vtable_addr + offset, 8)
        fp_addr = int.from_bytes(raw, "little") if raw and len(raw) == 8 else 0
        func = bv.get_function_at(fp_addr) if fp_addr else None

        if func is not None:
            base = _slot_field_name(bv, func, i)
            if base in used_names:
                used_names[base] += 1
                field_name = f"{base}_{used_names[base]}"
            else:
                used_names[base] = 0
                field_name = base
            ft = func.type
            if not ft.can_return:
                # Virtual overrides can return normally — don't let one
                # noreturn implementation poison every call through this slot.
                ft = Type.function(ft.return_value, list(ft.parameters), ft.calling_convention)
            field_type = Type.pointer(bv.arch, ft)
            updated_funcs.add(func)
        else:
            field_name = f"slot_{i}"
            field_type = Type.pointer(bv.arch, Type.void())

        builder.add_member_at_offset(field_name, field_type, offset)

    bv.define_user_type(struct_name, builder)

    struct_type = bv.get_type_by_name(struct_name)
    if struct_type is not None:
        bv.define_user_data_var(vtable_addr, struct_type)

    log_info(
        f"vtable_autodefine: defined {struct_name} ({n_slots} slots) @ {vtable_addr:#x}"
    )
    return updated_funcs


def _extract_store_offset(dest) -> int | None:
    """Extract the byte offset from an HLIL assignment destination expression.

    Returns the offset on success, or None for unrecognised patterns.
    HLIL_VAR reached via a HLIL_DEREF recursion represents a direct pointer
    dereference (*this), which is offset 0.
    """
    try:
        op = dest.operation

        if op == HighLevelILOperation.HLIL_DEREF:
            return _extract_store_offset(dest.src)

        if op == HighLevelILOperation.HLIL_STRUCT_FIELD:
            return dest.offset

        if op == HighLevelILOperation.HLIL_ADD:
            left, right = dest.left, dest.right
            if right.operation == HighLevelILOperation.HLIL_CONST:
                return right.constant
            if left.operation == HighLevelILOperation.HLIL_CONST:
                return left.constant

        if op in (HighLevelILOperation.HLIL_VAR, HighLevelILOperation.HLIL_CONST_PTR):
            return 0
    except Exception:
        pass
    return None


def _hlil_scan_for_vtable_assign(insn, target_addr: int) -> int | None:
    """Recursively walk an HLIL instruction tree looking for an assignment of target_addr.

    Returns the store offset on match, or None.
    Checks both HLIL_CONST_PTR and HLIL_CONST since BN uses either for addresses.
    """
    _const_ops = (HighLevelILOperation.HLIL_CONST_PTR, HighLevelILOperation.HLIL_CONST)
    try:
        if insn.operation == HighLevelILOperation.HLIL_ASSIGN:
            src = insn.src
            if src.operation in _const_ops and src.constant == target_addr:
                return _extract_store_offset(insn.dest)
        for op in insn.operands:
            if hasattr(op, "operation"):
                r = _hlil_scan_for_vtable_assign(op, target_addr)
                if r is not None:
                    return r
    except Exception:
        pass
    return None


def _mlil_find_vtable_store_offset(mlil, vtable_addr: int) -> int | None:
    """Scan MLIL for a store of vtable_addr and return the destination byte offset.

    Matches MLIL_STORE( ADD(reg, CONST(N)) | reg, CONST_PTR/CONST(vtable_addr) ).
    Returns N, or 0 for a direct-register store, or None if no match.
    """
    _const_ops = (
        MediumLevelILOperation.MLIL_CONST_PTR,
        MediumLevelILOperation.MLIL_CONST,
    )
    try:
        for block in mlil:
            for insn in block:
                if insn.operation != MediumLevelILOperation.MLIL_STORE:
                    continue
                try:
                    src = insn.src
                    if src.operation not in _const_ops or src.constant != vtable_addr:
                        continue
                    dest = insn.dest
                    if dest.operation == MediumLevelILOperation.MLIL_ADD:
                        l, r = dest.left, dest.right
                        if r.operation == MediumLevelILOperation.MLIL_CONST:
                            return r.constant
                        if l.operation == MediumLevelILOperation.MLIL_CONST:
                            return l.constant
                    elif dest.operation == MediumLevelILOperation.MLIL_VAR:
                        return 0
                except Exception:
                    continue
    except Exception:
        pass
    return None


def _find_class_offsets(bv: BinaryView, vtable_addrs: list) -> dict:
    """Find where each vtable address is stored into an object, returning {vtable_addr: class_byte_offset}.

    Scans referencing functions via HLIL first (typed struct field assignments),
    then falls back to MLIL (raw memory stores) for cases HLIL constant-folds away.
    """
    result: dict[int, int] = {}
    remaining = set(vtable_addrs)

    for vtable_addr in list(vtable_addrs):
        if vtable_addr not in remaining:
            continue
        for ref in bv.get_code_refs(vtable_addr):
            func = ref.function
            if func is None:
                continue

            if func.hlil is not None:
                for block in func.hlil:
                    for insn in block:
                        offset = _hlil_scan_for_vtable_assign(insn, vtable_addr)
                        if offset is not None:
                            result[vtable_addr] = offset
                            remaining.discard(vtable_addr)
                            break
                    if vtable_addr not in remaining:
                        break

            if vtable_addr not in remaining:
                break

            if func.mlil is not None:
                offset = _mlil_find_vtable_store_offset(func.mlil, vtable_addr)
                if offset is not None:
                    result[vtable_addr] = offset
                    remaining.discard(vtable_addr)

            if vtable_addr not in remaining:
                break

    return result


def _update_class_struct(bv: BinaryView, class_name: str, vtable_info: list) -> None:
    """Add typed vtable pointer fields to the class struct.

    vtable_info: [(vtable_addr, iface_name, struct_name, class_offset), ...]

    Overwrites existing fields at vtable offsets only for entries whose struct type
    resolves successfully - BN auto-generated fields (offset_0, field_0) that block
    our typed pointers are replaced; offsets where type lookup fails are left untouched
    rather than being cleared without a replacement.
    """
    resolved: list[tuple] = []
    for vtable_addr, iface_name, struct_name, class_offset in vtable_info:
        vtable_type = bv.get_type_by_name(struct_name)
        if vtable_type is None:
            log_warn(
                f"vtable_autodefine: type '{struct_name}' not found, skipping field in {class_name}"
            )
            continue
        resolved.append((class_offset, iface_name, vtable_type))

    if not resolved:
        return

    vtable_offsets = {co for co, _, _ in resolved}

    existing = bv.get_type_by_name(class_name)
    # Resolve a NamedTypeReference to its underlying struct so we don't drop
    # existing fields when the class is defined as a forward-declared ref.
    if existing is not None and existing.type_class == TypeClass.NamedTypeReferenceClass:
        existing = bv.get_type_by_name(str(existing.name))
    builder = StructureBuilder.create()

    if existing is not None and existing.type_class == TypeClass.StructureTypeClass:
        builder.packed = getattr(existing, "packed", False)
        for m in existing.members:
            if m.offset in vtable_offsets:
                continue
            builder.add_member_at_offset(m.name, m.type, m.offset)

    for class_offset, iface_name, vtable_type in resolved:
        ptr_type = Type.pointer(bv.arch, vtable_type)
        if class_offset == 0:
            field_name = "vtable"
        else:
            safe_iface = re.sub(r"[^a-zA-Z0-9_]", "_", _strip_elaborated_type_keywords(iface_name))
            field_name = f"vtable_{safe_iface}"
        builder.add_member_at_offset(field_name, ptr_type, class_offset)

    bv.define_user_type(class_name, builder)
    log_info(
        f"vtable_autodefine: updated {class_name} struct (+{len(resolved)} vtable pointer field(s))"
    )


def _update_interface_struct(bv: BinaryView, iface_name: str, struct_name: str) -> None:
    """Add a vtable pointer field at offset 0 to the interface struct.

    Callers that hold an interface pointer (IFoo*) rather than the concrete class
    pointer (Foo*) need the interface struct to have a vtable field so BN can
    promote raw pointer arithmetic to named field accesses in HLIL.  Without this,
    any function that receives IFulfillmentDataInfo* shows raw '(*(*ptr + N))(ptr)'
    even though FulfillmentDataInfo already has the vtable field defined.
    """
    vtable_type = bv.get_type_by_name(struct_name)
    if vtable_type is None:
        return

    clean_iface = _strip_elaborated_type_keywords(iface_name)
    if not clean_iface:
        return

    existing = bv.get_type_by_name(clean_iface)
    builder = StructureBuilder.create()

    if existing is not None and existing.type_class == TypeClass.StructureTypeClass:
        for m in existing.members:
            if m.offset == 0:
                continue  # will be replaced with our typed vtable pointer
            builder.add_member_at_offset(m.name, m.type, m.offset)

    ptr_type = Type.pointer(bv.arch, vtable_type)
    builder.add_member_at_offset("vtable", ptr_type, 0)
    bv.define_user_type(clean_iface, builder)
    log_info(f"vtable_autodefine: added vtable field to interface {clean_iface}")


def _set_this_param_type(func: "Function", ptr_type) -> bool:
    """Change the first parameter of func to ptr_type via function-prototype update.

    Using set_user_type (prototype level) rather than create_user_var (HLIL annotation
    level) because BN's HLIL lift derives parameter types from the function prototype.
    create_user_var only affects the display annotation and is ignored during HLIL
    re-lifting, so field-access promotion never fires.
    Returns True on success.
    """
    try:
        ft = func.type
        if ft.type_class != TypeClass.FunctionTypeClass:
            return False
        ft_params = list(ft.parameters)
        if not ft_params:
            return False
        new_params = [FunctionParameter(ptr_type, ft_params[0].name)] + [
            FunctionParameter(p.type, p.name) for p in ft_params[1:]
        ]
        new_ft = Type.function(ft.return_value, new_params, ft.calling_convention)
        func.set_user_type(new_ft)
        return True
    except Exception as e:
        log_warn(f"vtable_autodefine: couldn't retype 'this' prototype in {func.name}: {e}")
        return False


def _update_constructor_this_types(
    bv: BinaryView, class_name: str, vtable_info: list
) -> set:
    """Retype 'this' in every function that stores the primary vtable (class_offset == 0).

    Uses set_user_type to update the function prototype's first parameter type.
    create_user_var only sets an HLIL annotation; BN's HLIL lift reads the
    function prototype for parameter types, so prototype-level changes are
    required for field-access promotion to fire.
    Returns the set of retyped Function objects.
    """
    struct_type = bv.get_type_by_name(class_name)
    if struct_type is None:
        return set()

    ptr_type = Type.pointer(bv.arch, struct_type)
    updated: set = set()
    class_prefix = class_name + "::"

    for vtable_addr, iface_name, struct_name, class_offset in vtable_info:
        if class_offset != 0:
            continue
        for ref in bv.get_code_refs(vtable_addr):
            func = ref.function
            if func is None:
                continue

            # Only retype 'this' in functions that belong to this class.
            # Callers with the constructor inlined also appear as code refs but
            # must not have their first parameter changed to the wrong type.
            fname = func.name
            if fname.startswith("?"):
                try:
                    _, parts = demangle_ms(bv.arch, fname)
                    if isinstance(parts, list):
                        fname = "::".join(parts)
                    elif isinstance(parts, str):
                        fname = parts
                except Exception:
                    pass
            if not fname.startswith(class_prefix):
                continue

            if _set_this_param_type(func, ptr_type):
                updated.add(func)
                log_info(
                    f"vtable_autodefine: retyped 'this' in {func.name} → {class_name}*"
                )

    return updated


def _update_vtable_method_this_types(
    bv: BinaryView, class_name: str, vtable_info: list
) -> set:
    """Retype 'this' parameter of every virtual method in the primary vtable to ClassName*.

    Only processes primary vtable entries (class_offset == 0).  Secondary vtables
    have an adjusted 'this' pointer, so retyping them to ClassName* would be wrong.
    Uses set_user_type on the function prototype rather than create_user_var so that
    HLIL lifting picks up the new type and promotes field accesses.
    Returns the set of retyped Function objects.
    """
    struct_type = bv.get_type_by_name(class_name)
    if struct_type is None:
        return set()
    ptr_type = Type.pointer(bv.arch, struct_type)
    updated: set = set()

    for vtable_addr, iface_name, struct_name, class_offset in vtable_info:
        if class_offset != 0:
            continue
        vtable_struct = bv.get_type_by_name(struct_name)
        if vtable_struct is None:
            continue
        for member in vtable_struct.members:
            slot_raw = bv.read(vtable_addr + member.offset, 8)
            if not slot_raw or len(slot_raw) < 8:
                continue
            fp_addr = int.from_bytes(slot_raw, "little")
            if fp_addr == 0:
                continue
            func = bv.get_function_at(fp_addr)
            if func is None:
                continue
            if _set_this_param_type(func, ptr_type):
                updated.add(func)
                log_info(
                    f"vtable_autodefine: retyped 'this' in {func.name} → {class_name}*"
                )
    return updated


def _is_hlil_call_to_addr(expr, target_addr: int) -> bool:
    """Return True if expr is HLIL_CALL whose destination is the constant target_addr."""
    try:
        if expr.operation != HighLevelILOperation.HLIL_CALL:
            return False
        dest = expr.dest
        return (
            dest.operation == HighLevelILOperation.HLIL_CONST_PTR
            and dest.constant == target_addr
        )
    except Exception:
        return False


def _hlil_call_result_var(insn, target_addr: int):
    """Return the Variable initialized from `call(target_addr)(...)` in insn, or None.

    Matches HLIL_VAR_INIT(var, HLIL_CALL(HLIL_CONST_PTR(target_addr), [...]))
    and HLIL_ASSIGN(HLIL_VAR(var), HLIL_CALL(HLIL_CONST_PTR(target_addr), [...])).
    """
    try:
        op = insn.operation
        if op == HighLevelILOperation.HLIL_VAR_INIT:
            return insn.dest if _is_hlil_call_to_addr(insn.src, target_addr) else None
        if op == HighLevelILOperation.HLIL_ASSIGN:
            dest = insn.dest
            if (
                dest.operation == HighLevelILOperation.HLIL_VAR
                and _is_hlil_call_to_addr(insn.src, target_addr)
            ):
                return dest.var
    except Exception:
        pass
    return None


def _retype_call_result_vars(caller, target_addr: int, ptr_type) -> int:
    """Walk caller's HLIL and retype variables initialized from a call to target_addr.

    Setting the called function's prototype is not sufficient to make BN's HLIL
    re-lift the caller with the new return type — the caller's expression tree
    retains its pre-prototype variable typing, leaving constructs like
    `(*(*string_3 + 8))(string_3)` un-promoted even when string_3's display
    annotation already shows the correct class pointer type.  Calling
    create_user_var on the variable that captures the call result forces a full
    re-lift; BN then splits SSA copies and field promotion fires on the typed
    copy.

    Returns the number of variables retyped.
    """
    try:
        hlil = caller.hlil
    except Exception:
        return 0
    if hlil is None:
        return 0

    retyped = 0
    for block in hlil:
        for insn in block:
            var = _hlil_call_result_var(insn, target_addr)
            if var is None:
                continue
            try:
                caller.create_user_var(var, ptr_type, var.name)
                retyped += 1
            except Exception as e:
                log_warn(
                    f"vtable_autodefine: couldn't retype {var.name} in {caller.name}: {e}"
                )
    return retyped


def _process_class(
    bv: BinaryView, class_name: str, entries: list, all_sorted_addrs: list
) -> tuple:
    """Run the full vtable pipeline for one class.

    Returns (n_structs_created, set_of_updated_funcs, summary_str).
    """
    # Invalidate cached class offsets for these vtables; we may stamp new
    # types that change how HLIL lifts the storing functions.
    cache = _offset_cache(bv)
    for addr, _ in entries:
        cache.pop(addr, None)

    sized = _compute_slot_counts(bv, entries, all_sorted_addrs)

    all_funcs: set = set()
    created: list = []

    # Capture pre-existing data var type names BEFORE we stamp new types.
    # BN's RTTI or PDB analysis may have created types with a canonical name
    # that differs from what we'd derive from the RTTI symbol text (e.g.,
    # different template-argument order in WRL helper classes). Using BN's
    # canonical name ensures class struct fields reference a resolvable type,
    # which is required for HLIL to promote raw pointer arithmetic to named
    # field accesses.
    pre_existing_names: dict[int, str] = {}
    for vtable_addr, iface_name, n_slots in sized:
        dv = bv.get_data_var_at(vtable_addr)
        if dv is not None:
            t = dv.type
            if t.type_class == TypeClass.PointerTypeClass:
                t = t.target
            if t.type_class == TypeClass.NamedTypeReferenceClass:
                name = _strip_elaborated_type_keywords(str(t.name))
                if "VTable" in name:
                    pre_existing_names[vtable_addr] = name
            elif t.type_class == TypeClass.StructureTypeClass:
                reg = getattr(t, "registered_name", None)
                if reg:
                    name = _strip_elaborated_type_keywords(str(reg))
                    if "VTable" in name:
                        pre_existing_names[vtable_addr] = name

    for vtable_addr, iface_name, n_slots in sized:
        if n_slots == 0:
            log_warn(
                f"vtable_autodefine: {class_name}/{iface_name} @ {vtable_addr:#x} - 0 slots, skipping"
            )
            continue
        struct_name = pre_existing_names.get(vtable_addr) or _vtable_struct_name(iface_name)
        funcs = _create_vtable_struct(bv, vtable_addr, struct_name, n_slots)
        all_funcs.update(funcs)
        created.append((vtable_addr, iface_name, struct_name, n_slots))

    if not created:
        return 0, set(), f"{class_name}: no valid vtables found"

    vtable_addrs_only = [addr for addr, _, _, _ in created]
    offset_map = _find_class_offsets(bv, vtable_addrs_only)

    vtable_info = []
    for addr, iface_name, struct_name, n_slots in created:
        class_offset = offset_map.get(addr)
        if class_offset is None:
            log_warn(
                f"vtable_autodefine: {class_name}/{iface_name} @ {addr:#x} - "
                "couldn't determine class offset; vtable struct defined but class struct not updated"
            )
            continue
        vtable_info.append((addr, iface_name, struct_name, class_offset))

    if vtable_info:
        _update_class_struct(bv, class_name, vtable_info)
        # Add vtable pointer at offset 0 to each interface struct so that callers
        # holding interface pointers (IFoo*) also get HLIL field-access promotion.
        for _addr, iface_name, struct_name, _class_off in vtable_info:
            _update_interface_struct(bv, iface_name, struct_name)
        ctor_funcs = _update_constructor_this_types(bv, class_name, vtable_info)
        all_funcs.update(ctor_funcs)
        # Walk every caller's HLIL and explicitly retype the variable that
        # captures the constructor's return value.  Setting the constructor
        # prototype alone is not enough: BN updates the variable's display
        # annotation but does NOT re-lift the caller's HLIL expression tree, so
        # `(*(*string_3 + 8))(string_3)` stays raw even when string_3 already
        # shows as ClassName*.  create_user_var forces a full HLIL re-lift on
        # each caller and triggers SSA copy splitting so field promotion fires
        # on the typed copy.
        struct_type = bv.get_type_by_name(class_name)
        ptr_to_class = (
            Type.pointer(bv.arch, struct_type) if struct_type is not None else None
        )
        for ctor in ctor_funcs:
            for ref in bv.get_code_refs(ctor.start):
                caller = ref.function
                if caller is None:
                    continue
                all_funcs.add(caller)
                if ptr_to_class is not None:
                    _retype_call_result_vars(caller, ctor.start, ptr_to_class)
        method_funcs = _update_vtable_method_this_types(bv, class_name, vtable_info)
        all_funcs.update(method_funcs)

        # Ensure mark_caller_updates_required cascades to every factory/call site
        # that constructs this class, even when the function that actually writes
        # the vtable pointer is a WRL template base constructor whose demangled
        # name does NOT start with class_name + "::" and therefore wasn't picked
        # up by _update_constructor_this_types above.
        for vtable_addr, _iface, _sname, class_offset in vtable_info:
            if class_offset != 0:
                continue
            for ref in bv.get_code_refs(vtable_addr):
                if ref.function is not None:
                    all_funcs.add(ref.function)

    slot_counts = ", ".join(f"{iface}={n}" for _, iface, _, n in created)
    return (
        len(created),
        all_funcs,
        f"{class_name}: {len(created)} vtable(s) [{slot_counts}]",
    )


def _class_name_from_func(fname: str, vtable_map: dict) -> str | None:
    """Extract the class name from a qualified function name by trying progressively longer prefixes.

    Handles namespaced names like NS::Class::Method → NS::Class, matching against vtable_map keys.
    """
    parts = fname.split("::")
    for i in range(len(parts) - 1, 0, -1):
        candidate = "::".join(parts[:i])
        if candidate in vtable_map:
            return candidate
    return None


def _do_process_all(bv: BinaryView, task: BackgroundTaskThread) -> None:
    """Background worker for Auto-Define Vtable Structs for All Classes."""
    task.progress = "VTables: scanning for RTTI vtable symbols..."
    vtable_map = _find_vtable_symbols(bv)
    if not vtable_map:
        show_message_box(
            "Auto-Define Vtable Structs",
            "No RTTI vtable symbols found.\n\n"
            "Binary Ninja must have already run its RTTI analysis and produced\n"
            "symbols in the format: ClassName::`vftable'{for `IInterface'}",
        )
        return

    all_sorted = _all_vtable_addrs(vtable_map)

    bv.begin_undo_actions()
    all_funcs: set = set()
    summaries = []
    total_structs = 0
    total_classes = len(vtable_map)

    for i, (class_name, entries) in enumerate(sorted(vtable_map.items()), 1):
        if task.cancelled:
            break
        task.progress = f"VTables: processing {i}/{total_classes} - {class_name}"
        n, funcs, msg = _process_class(bv, class_name, entries, all_sorted)
        total_structs += n
        all_funcs.update(funcs)
        summaries.append(msg)
        log_info(f"vtable_autodefine: {msg}")

    task.progress = f"VTables: queueing re-analysis for {len(all_funcs)} function(s)..."
    for func in all_funcs:
        func.mark_caller_updates_required(FunctionUpdateType.UserFunctionUpdate)
    if all_funcs:
        bv.update_analysis()
        log_info(
            f"vtable_autodefine: queued re-analysis for {len(all_funcs)} function(s)"
        )

    bv.commit_undo_actions()

    show_message_box(
        "Auto-Define Vtable Structs",
        f"Processed {total_classes} class(es), {total_structs} vtable struct(s)"
        f"{' (cancelled)' if task.cancelled else ''}.\n\n"
        "Re-analysis queued - wait for BN's analysis indicator to finish,\n"
        "then check HLIL for promoted vtable field accesses.",
    )


def _cmd_process_all(bv: BinaryView) -> None:
    """Process every class with RTTI vtable symbols in the binary."""
    if not _check_arch(bv, "Auto-Define Vtable Structs"):
        return

    class _Task(BackgroundTaskThread):
        def __init__(self) -> None:
            super().__init__("VTables: auto-defining structs for all classes...", True)

        def run(self) -> None:
            try:
                _do_process_all(bv, self)
            finally:
                self.finish()

    _Task().start()


def _do_process_for_address(bv: BinaryView, addr: int, task: BackgroundTaskThread) -> None:
    """Background worker for Auto-Define Vtable Structs for one class."""
    task.progress = "VTables: scanning for RTTI vtable symbols..."
    vtable_map = _find_vtable_symbols(bv)
    all_sorted = _all_vtable_addrs(vtable_map)

    class_name = None
    funcs = bv.get_functions_containing(addr)
    if funcs:
        class_name = _class_name_from_func(funcs[0].name, vtable_map)

    if not (class_name and class_name in vtable_map):
        names = ", ".join(sorted(vtable_map.keys())[:10])
        show_message_box(
            "Auto-Define Vtable Structs",
            f"Could not determine class from address {addr:#x}.\n\n"
            f"Classes with vtable symbols: {names}{'...' if len(vtable_map) > 10 else ''}\n\n"
            "Use VTables -> Auto-Define for All Classes from the Plugins menu.",
        )
        return

    task.progress = f"VTables: processing {class_name}"
    bv.begin_undo_actions()
    n, funcs_set, msg = _process_class(
        bv, class_name, vtable_map[class_name], all_sorted
    )
    for func in funcs_set:
        func.mark_caller_updates_required(FunctionUpdateType.UserFunctionUpdate)
    if funcs_set:
        bv.update_analysis()
    bv.commit_undo_actions()
    show_message_box("Auto-Define Vtable Structs", msg)


def _cmd_process_for_address(bv: BinaryView, addr: int) -> None:
    """Process the vtable structs for the class whose method contains addr."""
    if not _check_arch(bv, "Auto-Define Vtable Structs"):
        return

    class _Task(BackgroundTaskThread):
        def __init__(self) -> None:
            super().__init__("VTables: auto-defining structs for class...", True)

        def run(self) -> None:
            try:
                _do_process_for_address(bv, addr, self)
            finally:
                self.finish()

    _Task().start()


def _cmd_process_for_function(bv: BinaryView, func: Function) -> None:
    """Process the vtable structs for the class this function belongs to."""
    _cmd_process_for_address(bv, func.start)


def _find_vtable_data_vars(bv: BinaryView) -> dict:
    """Return {vtable_addr: struct_name} for all data variables typed as *_VTable structs."""
    result = {}
    for addr, var in bv.data_vars.items():
        t = var.type
        name = None
        if t.type_class == TypeClass.NamedTypeReferenceClass:
            name = str(t.name)
        elif t.type_class == TypeClass.StructureTypeClass:
            reg = getattr(t, "registered_name", None)
            name = str(reg) if reg else None
        if name and "VTable" in name:
            result[addr] = name
    return result


def _get_vtable_dispatch_info(bv: BinaryView, addr: int) -> tuple:
    """Return (slot_offset, vtable_class_offset) for the call instruction at addr.

    slot_offset        : byte offset within the vtable (e.g. 0x128)
    vtable_class_offset: byte offset of the vtable pointer in the class struct
                         (0 = primary vtable, 8 = first secondary, …),
                         or None if it could not be determined.

    Handles two patterns:

    Standard vtable call (slot encoded in call.dest):
      CALL( LOAD( ADD( LOAD(base+class_off), CONST(slot_off) ) ) )

    XFG-guarded call (slot in a SET_REG before the guard dispatch):
      mov rax, [base + class_off]
      movabs r10, <hash>
      mov rax, [rax + slot_off]
      call [rip + guard_offset]
    """
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        return None, None
    func = funcs[0]
    try:
        call_il = func.get_low_level_il_at(addr)
    except Exception:
        return None, None
    if call_il is None or call_il.operation != LowLevelILOperation.LLIL_CALL:
        return None, None

    slot = _llil_slot_from_dest(call_il.dest)
    if slot is not None:
        class_off = _llil_class_offset_from_dest(call_il.dest)
        return slot, class_off

    # XFG: scan backward for the slot load (rax = [vtable + slot_off]),
    # then keep scanning for the vtable load (rax = [this + class_off]).
    llil = func.llil
    slot = None
    vtable_reg: str | None = None

    for i in range(call_il.instr_index - 1, -1, -1):
        try:
            insn = llil[i]
        except Exception:
            break
        if insn.operation in _LLIL_STOP_OPS:
            break
        if insn.operation != LowLevelILOperation.LLIL_SET_REG:
            continue

        if slot is None:
            s, vr = _llil_extract_slot_and_vtable_reg(insn)
            if s is not None:
                slot = s
                vtable_reg = vr
        else:
            try:
                dest_name = insn.dest.name
            except Exception:
                dest_name = str(insn.dest)
            if dest_name == vtable_reg:
                class_off = _llil_class_offset_from_load_src(insn.src)
                return slot, class_off

    return slot, None


def _llil_slot_from_dest(expr) -> int | None:
    """Extract the vtable slot byte offset from a standard call destination expression."""
    try:
        if expr.operation == LowLevelILOperation.LLIL_LOAD:
            inner = expr.src
            if inner.operation == LowLevelILOperation.LLIL_ADD:
                left, right = inner.left, inner.right
                if right.operation == LowLevelILOperation.LLIL_CONST:
                    return right.constant
                if left.operation == LowLevelILOperation.LLIL_CONST:
                    return left.constant
            if inner.operation == LowLevelILOperation.LLIL_REG:
                return 0
    except Exception:
        pass
    return None


def _llil_class_offset_from_dest(dest) -> int | None:
    """Extract the class-struct byte offset of the vtable pointer from a call destination.

    Expects dest = LOAD( ADD( LOAD(base+N), slot_off ) ) and returns N.
    """
    try:
        if dest.operation != LowLevelILOperation.LLIL_LOAD:
            return None
        add = dest.src
        if add.operation == LowLevelILOperation.LLIL_ADD:
            for side in (add.left, add.right):
                if side.operation == LowLevelILOperation.LLIL_LOAD:
                    return _llil_class_offset_from_load_src(side)
        elif add.operation == LowLevelILOperation.LLIL_LOAD:
            return _llil_class_offset_from_load_src(add)
        elif add.operation == LowLevelILOperation.LLIL_REG:
            return 0
    except Exception:
        pass
    return None


def _llil_class_offset_from_load_src(load_expr) -> int | None:
    """Extract the class-struct byte offset from a LOAD expression.

    LOAD(REG) → 0, LOAD(ADD(REG, CONST)) → CONST.
    """
    try:
        if load_expr.operation != LowLevelILOperation.LLIL_LOAD:
            return None
        inner = load_expr.src
        if inner.operation == LowLevelILOperation.LLIL_REG:
            return 0
        if inner.operation == LowLevelILOperation.LLIL_ADD:
            l, r = inner.left, inner.right
            if r.operation == LowLevelILOperation.LLIL_CONST:
                return r.constant
            if l.operation == LowLevelILOperation.LLIL_CONST:
                return l.constant
    except Exception:
        pass
    return None


def _llil_extract_slot_and_vtable_reg(insn) -> tuple:
    """Extract (slot_byte_offset, vtable_register_name) from a SET_REG that loads a vtable slot.

    Matches SET_REG(dest, LOAD(ADD(reg, CONST(slot_off)))).
    """
    try:
        src = insn.src
        if src.operation != LowLevelILOperation.LLIL_LOAD:
            return None, None
        inner = src.src
        if inner.operation != LowLevelILOperation.LLIL_ADD:
            return None, None
        left, right = inner.left, inner.right
        if right.operation == LowLevelILOperation.LLIL_CONST:
            slot_off = right.constant
            reg_expr = left
        elif left.operation == LowLevelILOperation.LLIL_CONST:
            slot_off = left.constant
            reg_expr = right
        else:
            return None, None
        if reg_expr.operation == LowLevelILOperation.LLIL_REG:
            try:
                vtable_reg = reg_expr.src.name
            except Exception:
                vtable_reg = str(reg_expr.src)
            return slot_off, vtable_reg
    except Exception:
        pass
    return None, None


def _get_calling_class(bv: BinaryView, addr: int, vtable_map: dict) -> str | None:
    """Return the vtable_map key matching the class of the function containing addr."""
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        return None
    name = funcs[0].name
    if name.startswith("?"):
        try:
            _, parts = demangle_ms(bv.arch, name)
            if isinstance(parts, str):
                name = parts
        except Exception:
            pass
    return _class_name_from_func(name, vtable_map)


def _cmd_navigate_to_virtual(bv: BinaryView, addr: int) -> None:
    """Resolve the virtual call at addr and navigate to the target function.

    Narrows candidates by calling class and vtable class offset; navigates
    directly when the result is unambiguous, otherwise shows a ranked choice dialog.
    """
    if not _check_arch(bv, "Navigate to Virtual Function"):
        return
    slot_offset, vtable_class_offset = _get_vtable_dispatch_info(bv, addr)
    if slot_offset is None:
        show_message_box(
            "Navigate to Virtual Function",
            f"No call instruction found at {addr:#x}, or couldn't determine vtable slot.\n\n"
            "Place the cursor on the call instruction in disassembly view.",
        )
        return

    vtable_vars = _find_vtable_data_vars(bv)
    if not vtable_vars:
        show_message_box(
            "Navigate to Virtual Function",
            "No typed VTable data variables found.\n\n"
            "Run VTables -> Auto-Define for All Classes first.",
        )
        return

    vtable_map = _find_vtable_symbols(bv)
    calling_class = _get_calling_class(bv, addr, vtable_map)
    class_vtable_addrs: set[int] = set()
    vtable_to_class_offset: dict[int, int] = {}

    if calling_class and calling_class in vtable_map:
        addrs = [a for a, _ in vtable_map[calling_class]]
        class_vtable_addrs = set(addrs)

        cache = _offset_cache(bv)
        missing = [a for a in addrs if a not in cache]
        if missing:
            computed = _find_class_offsets(bv, missing)
            for a, off in computed.items():
                cache[a] = off
        vtable_to_class_offset = {a: cache[a] for a in addrs if a in cache}

    candidates: list[tuple] = []
    seen_fp: set[int] = set()

    for vtable_addr, struct_name in vtable_vars.items():
        raw = bv.read(vtable_addr + slot_offset, 8)
        if not raw or len(raw) < 8:
            continue
        fp_addr = struct.unpack_from("<Q", raw)[0]
        if not fp_addr or fp_addr in seen_fp:
            continue
        func = bv.get_function_at(fp_addr)
        if func is None:
            continue
        seen_fp.add(fp_addr)
        candidates.append((fp_addr, func.name, struct_name, vtable_addr))

    if not candidates:
        show_message_box(
            "Navigate to Virtual Function",
            f"No function found at slot offset {slot_offset:#x} in any known VTable.\n\n"
            "The call may not be a vtable dispatch, or run VTables -> Auto-Define for All Classes first.",
        )
        return

    def _score(c: tuple) -> int:
        _, _, _, vtable_addr = c
        in_class = vtable_addr in class_vtable_addrs
        off_match = (
            vtable_class_offset is not None
            and vtable_to_class_offset.get(vtable_addr) == vtable_class_offset
        )
        if in_class and off_match:
            return 0
        if in_class:
            return 1
        if off_match:
            return 2
        return 3

    candidates.sort(key=_score)

    best_score = _score(candidates[0])
    if len(candidates) == 1 or best_score == 0:
        bv.file.navigate(bv.file.view, candidates[0][0])
        return

    score_labels = {0: "✓✓", 1: "✓ ", 2: "~ ", 3: "  "}
    choices = [
        f"{score_labels[_score(c)]} {name}  [{sname}]  ({fp:#x})"
        for fp, name, sname, _ in candidates
    ]
    idx = get_choice_input(
        "Navigate to Virtual Function", "Multiple candidates:", choices
    )
    if idx is not None:
        bv.file.navigate(bv.file.view, candidates[idx][0])


PluginCommand.register(
    "VTables\\Auto-Define for All Classes",
    "Create typed VTable structs from RTTI symbols and update class structs",
    _cmd_process_all,
)

PluginCommand.register_for_address(
    "VTables\\Auto-Define for This Class",
    "Auto-define vtable structs for the class at this address",
    _cmd_process_for_address,
)

PluginCommand.register_for_function(
    "VTables\\Auto-Define for This Class",
    "Auto-define vtable structs for the class this function belongs to",
    _cmd_process_for_function,
)

PluginCommand.register_for_address(
    "VTables\\Navigate to Virtual Function",
    "Resolve the vtable dispatch at this address and navigate to the target function",
    _cmd_navigate_to_virtual,
)
