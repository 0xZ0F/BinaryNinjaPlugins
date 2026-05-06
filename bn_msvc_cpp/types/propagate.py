from typing import List, Optional

from binaryninja import BinaryView, QualifiedName, Type, log

from ..rtti import ClassGraph
from .vtables import VtableScan


def propagate_this_types(bv: BinaryView, scans: List[VtableScan], rtti: ClassGraph) -> int:
    targets: set[int] = set()
    for s in scans:
        for slot in s.slots:
            targets.add(slot.target)

    n_retyped = 0
    n_no_class = 0
    n_class_unknown = 0
    n_failed = 0
    cls_ref_cache: dict[str, object] = {}

    for target in targets:
        func = bv.get_function_at(target)
        if func is None:
            continue
        class_name = _extract_class_from_function(bv, target, func)
        if not class_name:
            n_no_class += 1
            continue
        if not _is_registered_class(bv, class_name):
            n_class_unknown += 1
            continue

        this_ptr = cls_ref_cache.get(class_name)
        if this_ptr is None:
            try:
                qn = QualifiedName(class_name)
                this_ptr = Type.pointer(bv.arch, Type.named_type_from_registered_type(bv, qn))
                cls_ref_cache[class_name] = this_ptr
            except Exception as e:
                log.log_debug(f"[MSVC C++] cls ref {class_name} failed: {e}")
                n_failed += 1
                continue

        try:
            params = func.parameter_vars
            if params is None or len(params) == 0:
                continue
            params[0].type = this_ptr
            n_retyped += 1
        except Exception as e:
            log.log_debug(f"[MSVC C++] retype {hex(target)} failed: {e}")
            n_failed += 1

    log.log_info(
        f"[MSVC C++] propagate: {n_retyped} this-retyped, "
        f"{n_no_class} no-class, {n_class_unknown} class-unknown, {n_failed} failed"
    )
    return n_retyped


def _extract_class_from_function(bv: BinaryView, target: int, func) -> Optional[str]:
    sym = bv.get_symbol_at(target)
    full = ""
    if sym is not None:
        full = getattr(sym, "full_name", None) or ""
    if not full and func is not None:
        full = getattr(func, "name", None) or ""
    if not full:
        return None
    if full.startswith("[thunk]:"):
        full = full[len("[thunk]:"):]
    full = full.split("(", 1)[0].strip()
    if "::" not in full:
        return None
    parts = full.rsplit("::", 1)
    if len(parts) != 2:
        return None
    cls = parts[0].strip()
    method = parts[1].strip()
    if not cls or not method:
        return None
    if cls.startswith("?") or "@" in cls:
        return None
    return cls


def _is_registered_class(bv: BinaryView, class_name: str) -> bool:
    try:
        return bv.get_type_by_name(QualifiedName(class_name)) is not None
    except Exception:
        return False
