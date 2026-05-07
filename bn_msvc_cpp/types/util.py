import re
from typing import List, Optional  # noqa: F401

from binaryninja import (
    BinaryView,
    NamedTypeReferenceType,
    QualifiedName,
    StructureBuilder,
    Type,
)


_COMMA_SPACE = re.compile(r",\s+")
_OPEN_SPACE = re.compile(r"([<(])\s+")
_CLOSE_SPACE = re.compile(r"\s+([>)])")


def normalize_template_spacing(name: str) -> str:
    """Collapse `, ` -> `,`, `< X` -> `<X`, `X >` -> `X>` so two paths producing
    the same logical type name (different whitespace from BN's display vs internal
    representation) hash to the same qualified name."""
    if not name:
        return name
    out = _COMMA_SPACE.sub(",", name)
    out = _OPEN_SPACE.sub(r"\1", out)
    out = _CLOSE_SPACE.sub(r"\1", out)
    return out


def split_qn(name: str) -> List[str]:
    """Split a fully-qualified C++ name into namespace parts, respecting template brackets.

    `Microsoft::WRL::AsyncBase<X, Y::Z>` -> ['Microsoft', 'WRL', 'AsyncBase<X, Y::Z>']
    """
    parts: List[str] = []
    depth = 0
    last = 0
    i = 0
    n = len(name)
    while i < n:
        c = name[i]
        if c == "<" or c == "(":
            depth += 1
        elif c == ">" or c == ")":
            if depth > 0:
                depth -= 1
        elif depth == 0 and c == ":" and i + 1 < n and name[i + 1] == ":":
            parts.append(name[last:i])
            i += 2
            last = i
            continue
        i += 1
    parts.append(name[last:])
    return [p for p in parts if p]


def qn(name: str) -> QualifiedName:
    parts = [normalize_template_spacing(p) for p in split_qn(name)]
    return QualifiedName(parts)


def class_from_full_name(full: str) -> Optional[str]:
    """Extract the class portion from a fully-qualified C++ method's display name.

    Handles destructors and operators correctly by walking depth-aware segments
    and stopping at the first segment that starts with `~`, `` ` ``, or `operator`.
    Falls back to "all but last" when no such marker is present.
    """
    if not full:
        return None
    if full.startswith("[thunk]:"):
        full = full[len("[thunk]:"):]
    full = full.split("(", 1)[0].strip()
    parts = split_qn(full)
    if not parts:
        return None

    cls_parts: List[str] = []
    for p in parts:
        ps = p.strip()
        if not ps:
            continue
        if ps.startswith("~") or ps.startswith("`") or ps.startswith("operator"):
            break
        cls_parts.append(ps)

    if cls_parts and len(cls_parts) < len([p for p in parts if p.strip()]):
        return normalize_template_spacing("::".join(cls_parts))
    if len(parts) <= 1:
        return None
    return normalize_template_spacing("::".join(parts[:-1]))


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
