from typing import Optional

from binaryninja import (
    BinaryView,
    NamedTypeReferenceType,
    QualifiedName,
    StructureBuilder,
    Type,
)


def named_ref(bv: BinaryView, name: str) -> Optional[Type]:
    qn = QualifiedName(name)
    t = bv.get_type_by_name(qn)
    if t is None:
        return None
    return Type.named_type_from_registered_type(bv, qn)


def named_ref_qn(bv: BinaryView, qn: QualifiedName) -> Optional[Type]:
    if bv.get_type_by_name(qn) is None:
        return None
    return Type.named_type_from_registered_type(bv, qn)


def get_struct_builder(bv: BinaryView, name: str) -> Optional[StructureBuilder]:
    t = bv.get_type_by_name(QualifiedName(name))
    if t is None:
        return None
    structure = t.structure if hasattr(t, "structure") else None
    if structure is None:
        return None
    return structure.mutable_copy()


def is_member_user(member) -> bool:
    src = getattr(member, "source_type", None)
    if src is None:
        return False
    name = getattr(src, "name", str(src))
    return "User" in name
