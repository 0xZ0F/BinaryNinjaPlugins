"""Class struct + interface struct manipulation, and locating where each
vtable address is stored into an object (so the class struct's vtable
pointer field can be placed at the right offset).

Verbatim port of the relevant logic from `vtable_autodefine.py`.
"""

import re

from binaryninja import BinaryView, log_info, log_warn
from binaryninja.enums import (
    HighLevelILOperation,
    MediumLevelILOperation,
    TypeClass,
)
from binaryninja.types import StructureBuilder, Type

from ..util import strip_elaborated_type_keywords


# Patterns BN's "Create All Members" / structure-from-offset analysis emits
# for fields it inferred without a name. Replacing these with our typed
# vtable pointers is desirable; replacing a field a user has hand-named is
# not (idempotency).
_AUTO_FIELD_RE = re.compile(
    r"^(?:offset_[0-9a-fA-F]+|field_[0-9a-fA-F]+|__offset\(.*\)\.[a-z]+|vtable(?:_[A-Za-z0-9_]+)?)$"
)


def is_replaceable_field_name(name: str) -> bool:
    """Return True if `name` is a BN-auto-generated placeholder OR our own
    previous-run output (`vtable`, `vtable_<iface>`).
    """
    if not name:
        return True
    return bool(_AUTO_FIELD_RE.match(name))


# ---- Locate vtable-pointer offsets in the class struct -----------------

def _extract_store_offset(dest):
    """Extract the byte offset from an HLIL assignment destination expression."""
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


def _hlil_scan_for_vtable_assign(insn, target_addr: int):
    """Recursively walk an HLIL instruction tree looking for an assignment of target_addr."""
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


def _mlil_find_vtable_store_offset(mlil, vtable_addr: int):
    """Scan MLIL for a store of vtable_addr and return the destination byte offset."""
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


def find_class_offsets(bv: BinaryView, vtable_addrs: list) -> dict:
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


# Per-bv cache of {vtable_addr: class_byte_offset} stored on bv.session_data.
_OFFSET_CACHE_KEY = "bn_msvc_cpp:class_offset_cache"


def offset_cache(bv: BinaryView) -> dict:
    cache = bv.session_data.get(_OFFSET_CACHE_KEY)
    if cache is None:
        cache = {}
        bv.session_data[_OFFSET_CACHE_KEY] = cache
    return cache


# ---- Class + interface struct updates ---------------------------------

def update_class_struct(bv: BinaryView, class_name: str, vtable_info: list) -> None:
    """Add typed vtable pointer fields to the class struct.

    vtable_info: [(vtable_addr, iface_name, struct_name, class_offset), ...]

    Existing fields at vtable offsets are replaced ONLY if their name matches
    a BN-auto-generated placeholder or our own previous-run output. Hand-named
    fields are preserved so re-runs don't clobber user edits.
    """
    resolved: list[tuple] = []
    for vtable_addr, iface_name, struct_name, class_offset in vtable_info:
        if bv.get_type_by_name(struct_name) is None:
            log_warn(
                f"bn_msvc_cpp: type '{struct_name}' not found, skipping field in {class_name}"
            )
            continue
        resolved.append((class_offset, iface_name, struct_name))

    if not resolved:
        return

    vtable_offsets = {co for co, _, _ in resolved}

    existing = bv.get_type_by_name(class_name)
    if existing is not None and existing.type_class == TypeClass.NamedTypeReferenceClass:
        existing = bv.get_type_by_name(str(existing.name))
    builder = StructureBuilder.create()

    existing_at: dict[int, str] = {}
    if existing is not None and existing.type_class == TypeClass.StructureTypeClass:
        builder.packed = getattr(existing, "packed", False)
        for m in existing.members:
            if m.offset in vtable_offsets:
                existing_at[m.offset] = m.name
                if not is_replaceable_field_name(m.name):
                    builder.add_member_at_offset(m.name, m.type, m.offset)
                continue
            builder.add_member_at_offset(m.name, m.type, m.offset)

    for class_offset, iface_name, struct_name in resolved:
        if (
            class_offset in existing_at
            and not is_replaceable_field_name(existing_at[class_offset])
        ):
            continue
        nt = Type.named_type_from_registered_type(bv, struct_name)
        ptr_type = Type.pointer(bv.arch, nt)
        if class_offset == 0:
            field_name = "vtable"
        else:
            safe_iface = re.sub(r"[^a-zA-Z0-9_]", "_", strip_elaborated_type_keywords(iface_name))
            field_name = f"vtable_{safe_iface}"
        builder.add_member_at_offset(field_name, ptr_type, class_offset)

    bv.define_user_type(class_name, builder)
    log_info(
        f"bn_msvc_cpp: updated {class_name} struct (+{len(resolved)} vtable pointer field(s))"
    )


def update_interface_struct(bv: BinaryView, iface_name: str, struct_name: str) -> None:
    """Add a vtable pointer field at offset 0 to the interface struct.

    Callers that hold an interface pointer (IFoo*) rather than the concrete class
    pointer (Foo*) need the interface struct to have a vtable field so BN can
    promote raw pointer arithmetic to named field accesses in HLIL.
    """
    if bv.get_type_by_name(struct_name) is None:
        return

    clean_iface = strip_elaborated_type_keywords(iface_name)
    if not clean_iface:
        return

    existing = bv.get_type_by_name(clean_iface)
    builder = StructureBuilder.create()
    preserve_offset_0 = False

    if existing is not None and existing.type_class == TypeClass.StructureTypeClass:
        for m in existing.members:
            if m.offset == 0:
                if is_replaceable_field_name(m.name):
                    continue
                preserve_offset_0 = True
                builder.add_member_at_offset(m.name, m.type, m.offset)
                continue
            builder.add_member_at_offset(m.name, m.type, m.offset)

    if preserve_offset_0:
        bv.define_user_type(clean_iface, builder)
        return

    nt = Type.named_type_from_registered_type(bv, struct_name)
    ptr_type = Type.pointer(bv.arch, nt)
    builder.add_member_at_offset("vtable", ptr_type, 0)
    bv.define_user_type(clean_iface, builder)
    log_info(f"bn_msvc_cpp: added vtable field to interface {clean_iface}")


def auto_populate_class_struct(bv: BinaryView, class_name: str) -> bool:
    """Run BN's "Create All Members for Structure" equivalent on the named class.

    Calls bv.create_structure_from_offset_access (the public Python API behind the
    'S' UI command) to infer field types from observed accesses through any
    pointer typed as a NamedTypeReference to class_name, then re-registers the
    result. This is what makes class struct fields appear at the offsets HLIL
    was previously rendering as `__offset(N).d`.

    Defensive: refuses to re-define if the inferred struct would drop any of the
    existing members (vtable pointers in particular).

    Returns True if the struct was populated (one or more new members added).
    """
    try:
        existing = bv.get_type_by_name(class_name)
        if existing is None or existing.type_class != TypeClass.StructureTypeClass:
            return False
        existing_offsets = {m.offset for m in existing.members}
        new_struct = bv.create_structure_from_offset_access(class_name)
        new_offsets = {m.offset for m in new_struct.members}

        if not existing_offsets.issubset(new_offsets):
            log_warn(
                f"bn_msvc_cpp: auto-populate would drop existing fields in "
                f"{class_name}, skipping (existing={sorted(existing_offsets)} "
                f"new={sorted(new_offsets)})"
            )
            return False
        added = new_offsets - existing_offsets
        if not added:
            return False
        bv.define_user_type(class_name, new_struct)
        log_info(
            f"bn_msvc_cpp: auto-populated {class_name} (+{len(added)} field(s) "
            f"from observed accesses)"
        )
        return True
    except Exception as e:
        log_warn(f"bn_msvc_cpp: auto-populate failed for {class_name}: {e}")
        return False
