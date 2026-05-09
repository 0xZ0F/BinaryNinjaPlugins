"""`Navigate to Virtual Function` command: resolve the vtable dispatch at the
cursor and jump to the target function (chooser on hash collisions).

Verbatim port from `vtable_autodefine.py`.
"""

import struct

from binaryninja import BinaryView
from binaryninja.interaction import get_choice_input, show_message_box

from ..types.classes import find_class_offsets, offset_cache
from ..types.vtables import (
    attach_orphan_col_vtables,
    find_vtable_data_vars,
    find_vtable_symbols,
    invalidate_col_cache,
)
from ..util import check_arch, class_name_from_func, demangled_function_name
from ..xfg.dispatch import get_vtable_dispatch_info


def cmd_navigate_to_virtual(bv: BinaryView, addr: int) -> None:
    """Resolve the virtual call at addr and navigate to the target function.

    Narrows candidates by calling class and vtable class offset; navigates
    directly when the result is unambiguous, otherwise shows a ranked choice dialog.
    """
    if not check_arch(bv, "Navigate to Virtual Function"):
        return
    invalidate_col_cache(bv)
    slot_offset, vtable_class_offset = get_vtable_dispatch_info(bv, addr)
    if slot_offset is None:
        show_message_box(
            "Navigate to Virtual Function",
            f"No call instruction found at {addr:#x}, or couldn't determine vtable slot.\n\n"
            "Place the cursor on the call instruction in disassembly view.",
        )
        return

    vtable_vars = find_vtable_data_vars(bv)
    if not vtable_vars:
        show_message_box(
            "Navigate to Virtual Function",
            "No typed VTable data variables found.\n\n"
            "Run VTables -> Auto-Define for All Classes first.",
        )
        return

    vtable_map = find_vtable_symbols(bv)
    # Pull orphan COL-derived vtables in so the narrow-by-calling-class step
    # sees every sibling vtable (primary + secondary), not only the ones BN's
    # RTTI labeled.
    attach_orphan_col_vtables(bv, vtable_map)

    funcs = bv.get_functions_containing(addr)
    calling_class = None
    if funcs:
        fname = demangled_function_name(bv.arch, funcs[0].name)
        calling_class = class_name_from_func(fname, vtable_map)

    class_vtable_addrs: set = set()
    vtable_to_class_offset: dict[int, int] = {}

    if calling_class and calling_class in vtable_map:
        addrs = [a for a, _ in vtable_map[calling_class]]
        class_vtable_addrs = set(addrs)

        cache = offset_cache(bv)
        missing = [a for a in addrs if a not in cache]
        if missing:
            for a, off in find_class_offsets(bv, missing).items():
                cache[a] = off
        vtable_to_class_offset = {a: cache[a] for a in addrs if a in cache}

    candidates: list[tuple] = []
    seen_fp: set[int] = set()

    for vtable_addr, struct_name in vtable_vars.items():
        raw = bv.read(vtable_addr + slot_offset, 8)
        if not raw or len(raw) < 8:
            continue
        fp_addr = struct.unpack_from("<Q", raw)[0]
        if not fp_addr or fp_addr in seen_fp:
            continue
        f = bv.get_function_at(fp_addr)
        if f is None:
            continue
        seen_fp.add(fp_addr)
        candidates.append((fp_addr, f.name, struct_name, vtable_addr))

    if not candidates:
        show_message_box(
            "Navigate to Virtual Function",
            f"No function found at slot offset {slot_offset:#x} in any known VTable.\n\n"
            "The call may not be a vtable dispatch, or run VTables -> Auto-Define for All Classes first.",
        )
        return

    def _score(c: tuple) -> int:
        _, _, _, vtable_addr = c
        in_class = vtable_addr in class_vtable_addrs
        off_match = (
            vtable_class_offset is not None
            and vtable_to_class_offset.get(vtable_addr) == vtable_class_offset
        )
        if in_class and off_match:
            return 0
        if in_class:
            return 1
        if off_match:
            return 2
        return 3

    candidates.sort(key=_score)

    best_score = _score(candidates[0])
    if len(candidates) == 1 or best_score == 0:
        bv.file.navigate(bv.file.view, candidates[0][0])
        return

    score_labels = {0: "++", 1: "+ ", 2: "~ ", 3: "  "}
    choices = [
        f"{score_labels[_score(c)]} {name}  [{sname}]  ({fp:#x})"
        for fp, name, sname, _ in candidates
    ]
    idx = get_choice_input(
        "Multiple candidates:", "Navigate to Virtual Function", choices
    )
    if idx is not None:
        bv.file.navigate(bv.file.view, candidates[idx][0])
