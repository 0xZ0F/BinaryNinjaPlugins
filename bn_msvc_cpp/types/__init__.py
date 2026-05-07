from .classes import build_class_types, ensure_class_placeholders
from .vtables import enrich_vtables, scan_vtables, VtableScan, VtableSlot
from .propagate import propagate_this_types
from .fields import discover_fields
from .vtable_slots import discover_vtable_slots

__all__ = [
    "build_class_types",
    "ensure_class_placeholders",
    "enrich_vtables",
    "scan_vtables",
    "VtableScan",
    "VtableSlot",
    "propagate_this_types",
    "discover_fields",
    "discover_vtable_slots",
]

