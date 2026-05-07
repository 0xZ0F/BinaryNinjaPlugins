from typing import Dict, Optional

from binaryninja import (
    BinaryView,
    StructureBuilder,
    Type,
    log,
)

from .fields import _class_from_var_type, _collect_var_aliases, _var_key, _vars_eq
from .util import qn as _qn

_CALL_OPS = {"MLIL_CALL", "MLIL_CALL_UNTYPED", "MLIL_TAILCALL", "MLIL_TAILCALL_UNTYPED",
             "MLIL_CALL_SSA", "MLIL_CALL_UNTYPED_SSA", "MLIL_TAILCALL_SSA"}
_VAR_OPS = {"MLIL_VAR_SSA", "MLIL_VAR"}
_LOAD_OPS = {"MLIL_LOAD_SSA", "MLIL_LOAD"}
_LOAD_STRUCT_OPS = {"MLIL_LOAD_STRUCT_SSA", "MLIL_LOAD_STRUCT"}


def discover_vtable_slots(bv: BinaryView) -> int:
    """Walk every typed-this method; find indirect calls of shape
    `(*(*(this) + slot_offset))(args)`; record (class, slot_offset) per class.
    For each class whose VTable struct is empty (placeholder, no scan content),
    populate it with `slot_<offset>` members so HLIL renders
    `this->vtable->slot_<offset>(args)` instead of `this->vtable->__offset(N).q(args)`.
    """
    per_class: Dict[str, set[int]] = {}
    n_typed_funcs = 0

    for func in bv.functions:
        params = func.parameter_vars
        if params is None or len(params) == 0:
            continue
        this_var = params[0]
        cls = _class_from_var_type(this_var.type)
        if cls is None:
            continue
        n_typed_funcs += 1
        try:
            mlil = func.medium_level_il
            if mlil is not None:
                mlil_ssa = mlil.ssa_form
            else:
                continue
        except Exception:
            continue
        if mlil_ssa is None:
            continue
        try:
            mlil_nonssa = func.medium_level_il
        except Exception:
            mlil_nonssa = None
        aliases = _collect_var_aliases(mlil_nonssa, this_var) if mlil_nonssa is not None else {_var_key(this_var)}
        slots = per_class.setdefault(cls, set())
        for inst in mlil_ssa.instructions:
            _walk_for_vtable_call(inst, this_var, aliases, slots, mlil_ssa)

    n_classes = 0
    n_slots = 0
    for cls, slot_offsets in per_class.items():
        if not slot_offsets:
            continue
        added = _populate_vtable_struct(bv, cls, slot_offsets)
        if added > 0:
            n_classes += 1
            n_slots += added

    log.log_info(
        f"[MSVC C++] vtable slot discovery: {n_typed_funcs} typed funcs scanned, "
        f"{n_classes} vtables extended with {n_slots} slots"
    )
    return n_slots


def _op(expr) -> str:
    op = getattr(expr, "operation", None)
    if op is None:
        return ""
    return getattr(op, "name", str(op))


def _walk_for_vtable_call(inst, this_var, aliases: set, slots: set, mlil_ssa) -> None:
    if inst is None or not hasattr(inst, "operation"):
        return
    op = _op(inst)
    if op in _CALL_OPS:
        dest = getattr(inst, "dest", None)
        offset = _resolve_vtable_slot(dest, this_var, aliases, mlil_ssa, depth=0)
        if offset is not None:
            slots.add(offset)
    for operand in getattr(inst, "operands", []) or []:
        if hasattr(operand, "operation"):
            _walk_for_vtable_call(operand, this_var, aliases, slots, mlil_ssa)


def _resolve_vtable_slot(expr, this_var, aliases: set, mlil_ssa, depth: int) -> Optional[int]:
    if depth > 8 or expr is None or not hasattr(expr, "operation"):
        return None
    op = _op(expr)

    if op in _VAR_OPS:
        rhs = _follow_var_def(expr, mlil_ssa)
        if rhs is None:
            return None
        return _resolve_vtable_slot(rhs, this_var, aliases, mlil_ssa, depth + 1)

    if op in _LOAD_OPS:
        src = getattr(expr, "src", None)
        if src is None or not hasattr(src, "operation"):
            return None
        slot_offset = 0
        base = src
        if _op(src) == "MLIL_ADD":
            left = getattr(src, "left", None)
            right = getattr(src, "right", None)
            if right is not None and _op(right) == "MLIL_CONST":
                slot_offset = int(getattr(right, "constant", 0) or 0)
                base = left
            elif left is not None and _op(left) == "MLIL_CONST":
                slot_offset = int(getattr(left, "constant", 0) or 0)
                base = right
            else:
                return None
        return _check_inner_load_is_this(base, aliases, mlil_ssa, slot_offset)

    if op in _LOAD_STRUCT_OPS:
        slot_offset = int(getattr(expr, "offset", 0) or 0)
        base = getattr(expr, "src", None)
        return _check_inner_load_is_this(base, aliases, mlil_ssa, slot_offset)

    return None


def _check_inner_load_is_this(base, aliases: set, mlil_ssa, slot_offset: int) -> Optional[int]:
    if base is None or not hasattr(base, "operation"):
        return None
    op = _op(base)
    inner_load = base
    if op in _VAR_OPS:
        inner_load = _follow_var_def(base, mlil_ssa)
        if inner_load is None or not hasattr(inner_load, "operation"):
            return None
    if _op(inner_load) not in _LOAD_OPS and _op(inner_load) not in _LOAD_STRUCT_OPS:
        return None
    inner = getattr(inner_load, "src", None)
    if inner is None or not hasattr(inner, "operation"):
        return None
    inner_op = _op(inner)
    if inner_op in _VAR_OPS:
        if _var_key(_expr_var(inner)) in aliases:
            return slot_offset
    return None


def _follow_var_def(var_expr, mlil_ssa):
    op = _op(var_expr)
    try:
        if op == "MLIL_VAR_SSA":
            ssa_var = getattr(var_expr, "src", None)
            if ssa_var is None:
                return None
            return getattr(mlil_ssa.get_ssa_var_definition(ssa_var), "src", None)
        var = getattr(var_expr, "var", None)
        if var is None:
            return None
        defs = mlil_ssa.get_var_definitions(var)
        if not defs:
            return None
        return getattr(defs[-1], "src", None)
    except Exception:
        return None


def _expr_var(expr):
    op = _op(expr)
    if op == "MLIL_VAR":
        return getattr(expr, "var", None)
    if op == "MLIL_VAR_SSA":
        ssa = getattr(expr, "src", None)
        return getattr(ssa, "var", None) if ssa is not None else None
    return None


def _populate_vtable_struct(bv: BinaryView, cls_name: str, slot_offsets: set) -> int:
    qn = _qn(f"{cls_name}::VTable")
    existing = bv.get_type_by_name(qn)
    if existing is None:
        return 0

    structure = getattr(existing, "structure", None)
    if structure is not None:
        try:
            if list(getattr(structure, "members", None) or []):
                return 0
        except Exception:
            return 0

    builder = StructureBuilder.create()
    builder.packed = True
    void_ptr = Type.pointer(bv.arch, Type.void())
    added = 0
    for offset in sorted(slot_offsets):
        try:
            builder.insert(offset, void_ptr, f"slot_{offset:x}")
            added += 1
        except Exception as e:
            log.log_debug(f"[MSVC C++] vtable-slot insert {cls_name}.slot_{offset:x} failed: {e}")
    if added == 0:
        return 0
    try:
        bv.define_user_type(qn, Type.structure_type(builder))
    except Exception as e:
        log.log_debug(f"[MSVC C++] vtable-slot redefine {cls_name}::VTable failed: {e}")
        return 0
    return added
