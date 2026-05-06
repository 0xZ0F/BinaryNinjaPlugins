from typing import Dict, List, Optional, Tuple

from binaryninja import BinaryView, log

from ..rtti import ClassGraph
from ..types import VtableScan
from .scan import XfgSite

_CALL_OPS = {"MLIL_CALL", "MLIL_CALL_UNTYPED", "MLIL_TAILCALL", "MLIL_TAILCALL_UNTYPED",
             "MLIL_CALL_SSA", "MLIL_CALL_UNTYPED_SSA", "MLIL_TAILCALL_SSA"}


def crossfeed_types(
    bv: BinaryView,
    scans: List[VtableScan],
    sites: List[XfgSite],
    rtti: ClassGraph,
) -> int:
    cls_slot_index: Dict[Tuple[str, int], int] = {}
    for scan in scans:
        if scan.mi_for_base is not None:
            continue
        for slot in scan.slots:
            cls_slot_index[(scan.class_name, slot.offset)] = slot.target
    log.log_info(f"[MSVC C++] crossfeed index: {len(cls_slot_index)} (class, slot) entries")

    n_narrowed = 0
    n_inspected = 0
    n_pattern_match = 0

    for site in sites:
        if len(site.targets) <= 1:
            continue
        n_inspected += 1
        info = _resolve_call_context(bv, site, debug=False)
        if info is None:
            continue
        n_pattern_match += 1
        cls_name, slot_offset = info
        target = cls_slot_index.get((cls_name, slot_offset))
        if target is None or target not in site.targets:
            continue
        site.targets = [target]
        n_narrowed += 1

    log.log_info(
        f"[MSVC C++] crossfeed: inspected {n_inspected} aliased sites, "
        f"{n_pattern_match} matched the vtable pattern, "
        f"{n_narrowed} narrowed to unique"
    )
    return n_narrowed


def _op_name(expr) -> str:
    op = getattr(expr, "operation", None)
    if op is None:
        return ""
    return getattr(op, "name", str(op))


_PRIMITIVES = {"int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
               "uint32_t", "uint64_t", "char", "void", "bool"}


def _resolve_call_context(bv: BinaryView, site: XfgSite, debug: bool = False) -> Optional[Tuple[str, int]]:
    if site.func_start is None:
        return None
    func = bv.get_function_at(site.func_start)
    if func is None:
        return None
    try:
        mlil_ssa = func.medium_level_il.ssa_form
    except Exception:
        return None
    if mlil_ssa is None:
        return None

    inst = _find_inst_at(mlil_ssa, site.call_addr)
    if inst is None:
        return None
    if _op_name(inst) not in _CALL_OPS:
        return None

    dest = getattr(inst, "dest", None)
    if dest is None:
        return None

    if debug:
        log.log_info(
            f"[MSVC C++] crossfeed @ {hex(site.call_addr)} "
            f"({len(site.targets)} candidates): dest_op={_op_name(dest)}"
        )

    result = _resolve_expr(dest, mlil_ssa, depth=0, debug=debug)
    if debug:
        log.log_info(f"[MSVC C++] crossfeed @ {hex(site.call_addr)}: result={result}")
    return result


def _find_inst_at(mlil, addr: int):
    for inst in mlil.instructions:
        if inst.address == addr:
            return inst
    return None


def _resolve_expr(expr, mlil_ssa, depth: int, debug: bool) -> Optional[Tuple[str, int]]:
    if depth > 8 or expr is None or not hasattr(expr, "operation"):
        return None
    op = _op_name(expr)

    if op in ("MLIL_VAR_SSA", "MLIL_VAR"):
        rhs = _follow_var_def(expr, mlil_ssa, debug)
        if rhs is None:
            return None
        return _resolve_expr(rhs, mlil_ssa, depth + 1, debug)

    if op in ("MLIL_LOAD_SSA", "MLIL_LOAD"):
        return _extract_vtable_pattern(expr, mlil_ssa, depth, debug)

    if op in ("MLIL_LOAD_STRUCT_SSA", "MLIL_LOAD_STRUCT"):
        slot_offset = int(getattr(expr, "offset", 0) or 0)
        base = getattr(expr, "src", None)
        return _resolve_with_known_offset(base, slot_offset, mlil_ssa, depth, debug)

    return None


def _resolve_with_known_offset(base, slot_offset: int, mlil_ssa, depth: int, debug: bool) -> Optional[Tuple[str, int]]:
    if base is None or not hasattr(base, "operation"):
        return None
    op = _op_name(base)
    if op in ("MLIL_LOAD_SSA", "MLIL_LOAD"):
        receiver_expr = getattr(base, "src", None)
    elif op in ("MLIL_LOAD_STRUCT_SSA", "MLIL_LOAD_STRUCT"):
        receiver_expr = getattr(base, "src", None)
    elif op in ("MLIL_VAR_SSA", "MLIL_VAR"):
        underlying = _follow_var_def(base, mlil_ssa, debug)
        if underlying is None or not hasattr(underlying, "operation"):
            return None
        return _resolve_with_known_offset(underlying, slot_offset, mlil_ssa, depth + 1, debug)
    else:
        return None
    cls_name = _class_from_receiver_expr(receiver_expr, mlil_ssa, depth + 1, debug)
    if cls_name is None:
        return None
    return cls_name, slot_offset


def _follow_var_def(var_expr, mlil_ssa, debug: bool):
    op = _op_name(var_expr)
    try:
        if op == "MLIL_VAR_SSA":
            ssa_var = getattr(var_expr, "src", None)
            if ssa_var is None:
                return None
            def_inst = mlil_ssa.get_ssa_var_definition(ssa_var)
        else:
            var = getattr(var_expr, "var", None)
            if var is None:
                return None
            defs = mlil_ssa.get_var_definitions(var)
            if not defs:
                return None
            def_inst = defs[-1]
    except Exception:
        return None
    if def_inst is None:
        return None
    rhs = getattr(def_inst, "src", None)
    if debug and rhs is not None:
        log.log_info(f"[MSVC C++]   def: {_op_name(def_inst)} -> rhs={_op_name(rhs)}")
    return rhs


def _extract_vtable_pattern(load_expr, mlil_ssa, depth: int, debug: bool) -> Optional[Tuple[str, int]]:
    src = getattr(load_expr, "src", None)
    if src is None or not hasattr(src, "operation"):
        return None
    op = _op_name(src)

    slot_offset = 0
    base = src
    if op == "MLIL_ADD":
        left = getattr(src, "left", None)
        right = getattr(src, "right", None)
        if right is not None and _op_name(right) == "MLIL_CONST":
            slot_offset = int(getattr(right, "constant", 0))
            base = left
        elif left is not None and _op_name(left) == "MLIL_CONST":
            slot_offset = int(getattr(left, "constant", 0))
            base = right
        else:
            return None
    return _resolve_with_known_offset(base, slot_offset, mlil_ssa, depth, debug)


def _class_from_receiver_expr(expr, mlil_ssa, depth: int, debug: bool) -> Optional[str]:
    if depth > 8 or expr is None or not hasattr(expr, "operation"):
        return None
    op = _op_name(expr)
    if op in ("MLIL_VAR_SSA", "MLIL_VAR"):
        var = None
        if op == "MLIL_VAR_SSA":
            ssa_var = getattr(expr, "src", None)
            if ssa_var is not None:
                var = getattr(ssa_var, "var", None)
        else:
            var = getattr(expr, "var", None)
        if var is None:
            return None
        cls = _class_from_var_type(var.type)
        if cls is not None:
            return cls
        next_rhs = _follow_var_def(expr, mlil_ssa, debug)
        if next_rhs is not None and hasattr(next_rhs, "operation"):
            return _class_from_receiver_expr(next_rhs, mlil_ssa, depth + 1, debug)
    return None


def _class_from_var_type(var_type) -> Optional[str]:
    if var_type is None:
        return None
    target = getattr(var_type, "target", None)
    if target is None:
        return None
    s = str(target).strip()
    while s.endswith("*"):
        s = s[:-1].strip()
    s = s.strip("`'")
    if s.startswith("struct "):
        s = s[len("struct "):].strip().strip("`'")
    if s.endswith("::VTable"):
        s = s[: -len("::VTable")]
    elif "::VTable_for_" in s:
        s = s.split("::VTable_for_", 1)[0]
    s = s.strip().strip("`'")
    if not s or s in _PRIMITIVES:
        return None
    return s
