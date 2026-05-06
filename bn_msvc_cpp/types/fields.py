from typing import Dict, List, Optional, Tuple

from binaryninja import (
    BinaryView,
    QualifiedName,
    StructureBuilder,
    Type,
    log,
)

from ..rtti import ClassGraph
from .classes import _attach_base_structures
from .vtables import VtableScan


_LOAD_OPS = {"MLIL_LOAD", "MLIL_LOAD_SSA"}
_LOAD_STRUCT_OPS = {"MLIL_LOAD_STRUCT", "MLIL_LOAD_STRUCT_SSA"}
_STORE_OPS = {"MLIL_STORE", "MLIL_STORE_SSA"}
_STORE_STRUCT_OPS = {"MLIL_STORE_STRUCT", "MLIL_STORE_STRUCT_SSA"}
_VAR_OPS = {"MLIL_VAR", "MLIL_VAR_SSA"}


def _op(expr) -> str:
    op = getattr(expr, "operation", None)
    if op is None:
        return ""
    return getattr(op, "name", str(op))


def discover_fields(bv: BinaryView, scans: List[VtableScan], rtti: ClassGraph) -> int:
    """Walk MLIL of typed virtual methods; collect this+N field accesses;
    extend each class struct with `field_<offset>` members so HLIL can promote
    raw offset arithmetic into named field references (including vtable slots).
    """
    accesses: Dict[str, Dict[int, int]] = {}
    seen_targets: set[int] = set()
    debug_budget = 0
    walk_dump_budget = 0
    n_typed_funcs = 0

    for scan in scans:
        for slot in scan.slots:
            if slot.target in seen_targets:
                continue
            seen_targets.add(slot.target)
            func = bv.get_function_at(slot.target)
            if func is None:
                continue
            params = func.parameter_vars
            if params is None or len(params) == 0:
                continue
            this_var = params[0]
            t = this_var.type
            cls = _class_from_var_type(t)
            if cls is None:
                if debug_budget > 0 and t is not None:
                    log.log_info(
                        f"[MSVC C++] field-discovery: skipped fn {hex(slot.target)} "
                        f"this_var.type repr={repr(t)[:120]} target={getattr(t, 'target', None)!r}"
                    )
                    debug_budget -= 1
                continue
            n_typed_funcs += 1
            try:
                mlil = func.medium_level_il
            except Exception:
                continue
            if mlil is None:
                continue
            class_offsets = accesses.setdefault(cls, {})
            if walk_dump_budget > 0:
                walk_dump_budget -= 1
                _dump_mlil(mlil, this_var, cls, slot.target)
            for inst in mlil.instructions:
                _walk_expr(inst, this_var, class_offsets)
    nonempty = sum(1 for v in accesses.values() if v)
    log.log_info(
        f"[MSVC C++] field-discovery: scanned {n_typed_funcs} typed functions, "
        f"{len(accesses)} classes encountered, {nonempty} with observed offsets"
    )

    n_added = 0
    n_classes_extended = 0
    for cls, off_widths in accesses.items():
        if not off_widths:
            continue
        added = _rebuild_class_with_fields(bv, cls, rtti, off_widths)
        if added > 0:
            n_added += added
            n_classes_extended += 1

    log.log_info(
        f"[MSVC C++] field discovery: {n_classes_extended} classes extended, "
        f"{n_added} fields added"
    )
    return n_added


def _dump_mlil(mlil, this_var, cls, addr):
    log.log_info(f"[MSVC C++] field-discovery: dumping MLIL for {cls} @ {hex(addr)} (this_var={this_var})")
    n = 0
    for inst in mlil.instructions:
        if n >= 12:
            break
        op = _op(inst)
        log.log_info(f"  [{n}] addr={hex(inst.address)} op={op} repr={repr(inst)[:160]}")
        n += 1


_PRIMS = {"int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
          "uint32_t", "uint64_t", "char", "void", "bool"}


def _class_from_var_type(var_type) -> Optional[str]:
    if var_type is None:
        return None
    candidates: list[str] = []
    target = getattr(var_type, "target", None)
    if target is not None:
        candidates.append(str(target))
    candidates.append(str(var_type))
    for raw in candidates:
        cleaned = _clean_type_name(raw)
        if cleaned:
            return cleaned
    return None


def _clean_type_name(raw: str) -> Optional[str]:
    s = (raw or "").strip()
    while s.endswith("*"):
        s = s[:-1].strip()
    while s.endswith("__ptr64"):
        s = s[: -len("__ptr64")].strip()
    while s.endswith("*"):
        s = s[:-1].strip()
    s = s.strip("`'")
    for prefix in ("struct ", "class ", "union "):
        if s.startswith(prefix):
            s = s[len(prefix):].strip()
    s = s.strip("`'")
    if not s or s in _PRIMS:
        return None
    if s.endswith("::VTable") or "::VTable_for_" in s:
        return None
    return s


def _walk_expr(expr, this_var, offsets: Dict[int, int]) -> None:
    if expr is None or not hasattr(expr, "operation"):
        return
    op = _op(expr)

    if op in _LOAD_OPS:
        offset = _check_this_address(getattr(expr, "src", None), this_var)
        if offset is not None and offset > 0:
            size = int(getattr(expr, "size", 0) or 0)
            if size > 0:
                offsets[offset] = max(offsets.get(offset, 0), size)
    elif op in _LOAD_STRUCT_OPS:
        base_offset = _check_this_address(getattr(expr, "src", None), this_var)
        if base_offset is not None:
            field_off = int(getattr(expr, "offset", 0) or 0)
            actual = base_offset + field_off
            size = int(getattr(expr, "size", 0) or 0)
            if size > 0 and actual > 0:
                offsets[actual] = max(offsets.get(actual, 0), size)
    elif op in _STORE_OPS:
        offset = _check_this_address(getattr(expr, "dest", None), this_var)
        if offset is not None and offset > 0:
            size = int(getattr(expr, "size", 0) or 0)
            if size > 0:
                offsets[offset] = max(offsets.get(offset, 0), size)
    elif op in _STORE_STRUCT_OPS:
        base_offset = _check_this_address(getattr(expr, "dest", None), this_var)
        if base_offset is not None:
            field_off = int(getattr(expr, "offset", 0) or 0)
            actual = base_offset + field_off
            size = int(getattr(expr, "size", 0) or 0)
            if size > 0 and actual > 0:
                offsets[actual] = max(offsets.get(actual, 0), size)

    for operand in getattr(expr, "operands", []) or []:
        if hasattr(operand, "operation"):
            _walk_expr(operand, this_var, offsets)


def _check_this_address(addr_expr, this_var) -> Optional[int]:
    if addr_expr is None or not hasattr(addr_expr, "operation"):
        return None
    op = _op(addr_expr)
    if op in _VAR_OPS:
        if _vars_eq(_expr_var(addr_expr), this_var):
            return 0
        return None
    if op == "MLIL_ADD":
        left = getattr(addr_expr, "left", None)
        right = getattr(addr_expr, "right", None)
        if left is None or right is None:
            return None
        if _op(right) == "MLIL_CONST" and _vars_eq(_expr_var(left), this_var):
            return int(getattr(right, "constant", 0) or 0)
        if _op(left) == "MLIL_CONST" and _vars_eq(_expr_var(right), this_var):
            return int(getattr(left, "constant", 0) or 0)
    return None


def _vars_eq(a, b) -> bool:
    if a is None or b is None:
        return False
    if a is b:
        return True
    try:
        return a == b
    except Exception:
        pass
    a_id = (getattr(a, "source_type", None), getattr(a, "index", None), getattr(a, "storage", None))
    b_id = (getattr(b, "source_type", None), getattr(b, "index", None), getattr(b, "storage", None))
    return a_id == b_id and a_id[1] is not None


def _expr_var(expr):
    op = _op(expr)
    if op == "MLIL_VAR":
        return getattr(expr, "var", None)
    if op == "MLIL_VAR_SSA":
        ssa_var = getattr(expr, "src", None)
        return getattr(ssa_var, "var", None) if ssa_var is not None else None
    return None


_EXTEND_DEBUG = [3]


def _vt_ptr_for_class(bv: BinaryView, cls_name: str, existing_cls):
    """Read the existing class's first member type to recover the vtable pointer type."""
    structure = getattr(existing_cls, "structure", None)
    if structure is not None:
        try:
            members = list(getattr(structure, "members", None) or [])
            if members:
                first = members[0]
                ftype = getattr(first, "type", None)
                if ftype is not None:
                    return ftype
        except Exception:
            pass
    primary_qn = QualifiedName(f"{cls_name}::VTable")
    if bv.get_type_by_name(primary_qn) is not None:
        try:
            return Type.pointer(bv.arch, Type.named_type_from_registered_type(bv, primary_qn))
        except Exception:
            pass
    return None


def _rebuild_class_with_fields(bv: BinaryView, cls_name: str, rtti: ClassGraph, off_widths: Dict[int, int]) -> int:
    existing_cls = bv.get_type_by_name(QualifiedName(cls_name))
    if existing_cls is None:
        return 0

    vt_ptr = _vt_ptr_for_class(bv, cls_name, existing_cls)
    if vt_ptr is None:
        return 0

    builder = StructureBuilder.create()
    builder.append(vt_ptr, "vtable")
    _attach_base_structures(bv, builder, cls_name, rtti)

    base_offsets: set[int] = set()
    try:
        for bs in (builder.base_structures or []):
            base_offsets.add(int(getattr(bs, "offset", -1)))
    except Exception:
        pass

    added = 0
    for offset in sorted(off_widths.keys()):
        if offset == 0 or offset in base_offsets:
            continue
        width = off_widths[offset]
        ftype = _width_to_type(bv, width)
        try:
            builder.insert(offset, ftype, f"field_{offset:x}")
            added += 1
        except Exception as e:
            if _EXTEND_DEBUG[0] > 0:
                log.log_debug(f"[MSVC C++] field-discovery: insert {cls_name}.field_{offset:x} (w={width}) failed: {e}")
                _EXTEND_DEBUG[0] -= 1

    if added == 0:
        return 0
    try:
        bv.define_user_type(QualifiedName(cls_name), Type.structure_type(builder))
    except Exception as e:
        log.log_warn(f"[MSVC C++] field-discovery: redefine {cls_name} failed: {e}")
        return 0
    return added


def _extend_class(bv: BinaryView, cls_name: str, off_widths: Dict[int, int]) -> int:
    qn = QualifiedName(cls_name)
    existing = bv.get_type_by_name(qn)
    if existing is None:
        if _EXTEND_DEBUG[0] > 0:
            log.log_info(f"[MSVC C++] field-discovery: {cls_name} not found via get_type_by_name")
            _EXTEND_DEBUG[0] -= 1
        return 0
    structure = getattr(existing, "structure", None)
    if structure is None:
        if _EXTEND_DEBUG[0] > 0:
            attrs = [a for a in dir(existing) if not a.startswith("_")][:30]
            log.log_info(
                f"[MSVC C++] field-discovery: {cls_name} type has no .structure; "
                f"type_class={type(existing).__name__} attrs={attrs}"
            )
            _EXTEND_DEBUG[0] -= 1
        return 0
    try:
        builder = structure.mutable_copy()
    except Exception as e:
        if _EXTEND_DEBUG[0] > 0:
            log.log_info(f"[MSVC C++] field-discovery: {cls_name} mutable_copy failed: {e}")
            _EXTEND_DEBUG[0] -= 1
        return 0

    existing_offsets: set[int] = set()
    try:
        for member in builder.members:
            existing_offsets.add(int(member.offset))
    except Exception:
        pass

    base_offsets: set[int] = set()
    try:
        for bs in (builder.base_structures or []):
            base_offsets.add(int(getattr(bs, "offset", -1)))
    except Exception:
        pass

    added = 0
    insert_failures = 0
    last_err = None
    for offset in sorted(off_widths.keys()):
        if offset in existing_offsets or offset in base_offsets:
            continue
        width = off_widths[offset]
        ftype = _width_to_type(bv, width)
        try:
            builder.insert(offset, ftype, f"field_{offset:x}")
            added += 1
        except Exception as e:
            insert_failures += 1
            last_err = e
    if insert_failures > 0 and _EXTEND_DEBUG[0] > 0:
        log.log_info(
            f"[MSVC C++] field-discovery: {cls_name}: {added} ok, "
            f"{insert_failures} insert failures (last={last_err!r})"
        )
        _EXTEND_DEBUG[0] -= 1

    if added == 0:
        return 0

    try:
        bv.define_user_type(qn, Type.structure_type(builder))
    except Exception as e:
        log.log_warn(f"[MSVC C++] redefine {cls_name} after field discovery failed: {e}")
        return 0
    return added


def _width_to_type(bv: BinaryView, width: int) -> Type:
    if width == 1:
        return Type.int(1, sign=False)
    if width == 2:
        return Type.int(2, sign=False)
    if width == 4:
        return Type.int(4, sign=False)
    if width == 8:
        return Type.int(8, sign=False)
    return Type.array(Type.int(1, sign=False), width)
