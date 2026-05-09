"""Type-system manipulation: vtable structs, class structs, this-typing,
and the slot-typing post-pass."""

from . import classes, improve, propagate, vtables

__all__ = ["classes", "improve", "propagate", "vtables"]
