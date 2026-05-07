from typing import List, Optional

from binaryninja import (
    BinaryView,
    QualifiedName,
    StructureBuilder,
    Type,
    log,
)

from binaryninja import SymbolType

from ..rtti import ClassGraph
from .util import class_from_full_name, qn as _qn
from .vtables import VtableScan, _vtable_struct_name


def ensure_class_placeholders(bv: BinaryView) -> int:
    """Walk every function symbol; extract the owning class from its demangled name;
    ensure each class has at least an empty struct registered. Templated abstract
    bases like `Microsoft::WRL::AsyncBase<...>` have no vftable but do have methods,
    and BN auto-generates a `typedef void` placeholder for the type name when first
    referenced. We replace that with an empty struct so users (and our field-discovery
    pass) can populate it.
    """
    discovered: set[str] = set()
    for sym in bv.get_symbols_of_type(SymbolType.FunctionSymbol):
        full = getattr(sym, "full_name", None) or ""
        cls = class_from_full_name(full)
        if not cls:
            continue
        if cls.startswith("?") or "@" in cls or "::~" in cls or "::`" in cls:
            continue
        discovered.add(cls)

    n_created = 0
    n_vtable_created = 0
    n_undefined = 0
    for cls_name in discovered:
        if _ensure_struct(bv, cls_name):
            n_created += 1
        if _ensure_struct(bv, f"{cls_name}::VTable"):
            n_vtable_created += 1
    log.log_info(
        f"[MSVC C++] class placeholders: {n_created} class structs, "
        f"{n_vtable_created} vtable placeholders, {n_undefined} typedefs replaced"
    )
    return n_created


def _ensure_struct(bv: BinaryView, name: str) -> bool:
    qn = _qn(name)
    existing = bv.get_type_by_name(qn)
    if existing is not None:
        structure = getattr(existing, "structure", None)
        if structure is not None:
            try:
                if list(getattr(structure, "members", None) or []):
                    return False
            except Exception:
                return False
        try:
            bv.undefine_user_type(qn)
        except Exception:
            pass
    try:
        builder = StructureBuilder.create()
        bv.define_user_type(qn, Type.structure_type(builder))
        return True
    except Exception as e:
        log.log_debug(f"[MSVC C++] _ensure_struct({name}) failed: {e}")
        return False


def build_class_types(bv: BinaryView, scans: List[VtableScan], rtti: ClassGraph) -> int:
    primary_by_class: dict[str, VtableScan] = {}
    secondaries_by_class: dict[str, list[VtableScan]] = {}
    for s in scans:
        if s.mi_for_base is None:
            existing = primary_by_class.get(s.class_name)
            if existing is None or len(s.slots) > len(existing.slots):
                primary_by_class[s.class_name] = s
        else:
            secondaries_by_class.setdefault(s.class_name, []).append(s)

    n_mi_promoted = 0
    for cls_name, secs in secondaries_by_class.items():
        if cls_name in primary_by_class:
            continue
        primary_by_class[cls_name] = max(secs, key=lambda x: len(x.slots))
        n_mi_promoted += 1

    n_built = 0
    n_skipped_no_vt = 0

    for class_name, scan in primary_by_class.items():
        vt_name = _vtable_struct_name(class_name, scan.mi_for_base)
        vt_qn = _qn(vt_name)
        if bv.get_type_by_name(vt_qn) is None:
            n_skipped_no_vt += 1
            continue
        try:
            vt_ref = Type.named_type_from_registered_type(bv, vt_qn)
        except Exception as e:
            log.log_debug(f"[MSVC C++] named ref for {vt_qn} failed: {e}")
            continue
        vt_ptr = Type.pointer(bv.arch, vt_ref)
        builder = StructureBuilder.create()
        builder.append(vt_ptr, "vtable")
        try:
            bv.define_user_type(_qn(class_name), Type.structure_type(builder))
            n_built += 1
        except Exception as e:
            log.log_warn(f"[MSVC C++] pass1 failed to define class {class_name}: {e}")

    n_with_bases = 0
    for class_name, scan in primary_by_class.items():
        node = rtti.by_name.get(class_name)
        if node is None or not node.bases:
            continue
        vt_name = _vtable_struct_name(class_name, scan.mi_for_base)
        vt_qn = _qn(vt_name)
        if bv.get_type_by_name(vt_qn) is None:
            continue
        vt_ref = Type.named_type_from_registered_type(bv, vt_qn)
        vt_ptr = Type.pointer(bv.arch, vt_ref)
        builder = StructureBuilder.create()
        builder.append(vt_ptr, "vtable")
        if _attach_base_structures(bv, builder, class_name, rtti):
            n_with_bases += 1
            try:
                bv.define_user_type(_qn(class_name), Type.structure_type(builder))
            except Exception as e:
                log.log_warn(f"[MSVC C++] pass2 redefine of {class_name} failed: {e}")

    log.log_info(
        f"[MSVC C++] class structs: {n_built} built ({n_mi_promoted} from MI-only), "
        f"{n_with_bases} with BaseStructures, "
        f"{n_skipped_no_vt} skipped (no VTable type)"
    )
    return n_built


_BaseStructure = None
def _import_base_structure():
    global _BaseStructure
    if _BaseStructure is not None:
        return _BaseStructure
    for path in ("binaryninja.types", "binaryninja"):
        try:
            mod = __import__(path, fromlist=["BaseStructure"])
            bs = getattr(mod, "BaseStructure", None)
            if bs is not None:
                _BaseStructure = bs
                return bs
        except Exception:
            continue
    return None


def _attach_base_structures(
    bv: BinaryView,
    builder: StructureBuilder,
    class_name: str,
    rtti: ClassGraph,
) -> bool:
    node = rtti.by_name.get(class_name)
    if node is None or not node.bases:
        return False

    BaseStructure = _import_base_structure()
    if BaseStructure is None:
        log.log_warn(f"[MSVC C++] BaseStructure type not importable; skipping bases for {class_name}")
        return False

    bases = []
    for b in node.bases:
        base_qn = _qn(b.class_name)
        base_t = bv.get_type_by_name(base_qn)
        if base_t is None:
            log.log_info(f"[MSVC C++] base {b.class_name} not yet registered (deferred); skipping for {class_name}")
            continue
        try:
            base_ref = Type.named_type_from_registered_type(bv, base_qn)
        except Exception as e:
            log.log_debug(f"[MSVC C++] named ref for base {b.class_name} failed: {e}")
            continue
        width = getattr(base_t, "width", 0) or 0
        if width <= 0:
            log.log_info(f"[MSVC C++] base {b.class_name} width=0; using 8")
            width = 8
        try:
            bases.append(BaseStructure(base_ref, b.class_offset, width))
        except Exception as e:
            log.log_warn(f"[MSVC C++] BaseStructure({b.class_name}, +{b.class_offset:#x}, w={width}) failed: {e}")

    if not bases:
        return False
    try:
        builder.base_structures = bases
        log.log_info(
            f"[MSVC C++] {class_name}: attached {len(bases)} base(s) "
            + ", ".join(f"{b.class_name}@+{b.class_offset:#x}" for b in node.bases)
        )
        return True
    except Exception as e:
        log.log_warn(f"[MSVC C++] base_structures setter failed for {class_name}: {e}")
        return False
