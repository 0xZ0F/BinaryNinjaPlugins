"""Per-site XFG resolution: write `XFG -> ...` comment + (optionally) set
indirect-branch targets, or clear them.

Verbatim port from `xfg_xrefs.py` apart from the comment text, which now
goes through the compact `comment.format_comment`.
"""

from binaryninja import BinaryView

from .comment import format_comment
from .crossfeed import final_targets_to_write
from .hash_index import find_targets_for_hash
from .sites import find_xfg_call


def resolve_one_xfg_site(
    bv: BinaryView, movabs_addr: int, hash_map: dict, ctx=None
) -> tuple:
    """Apply XFG branch targets and 'XFG -> ...' comment at one movabs r10 site.

    Returns (status, comment) where status is one of:
        "resolved", "resolved-disambig", "resolved-comment-only",
        "no-targets", "no-call", "no-func"

    "resolved-disambig"     : alias list narrowed to 1 concrete target via vtable
    "resolved-comment-only" : alias-rich, no vtable disambig - comment only,
                              no indirect branches written (avoids BNDB bloat)
    """
    hash_bytes = bv.read(movabs_addr + 2, 8)
    if not hash_bytes or len(hash_bytes) < 8:
        return "no-targets", ""
    call_hash = int.from_bytes(hash_bytes, "little")
    targets = find_targets_for_hash(bv, call_hash, hash_map)
    if not targets:
        return "no-targets", ""
    call_addr = find_xfg_call(bv, movabs_addr)
    if call_addr is None:
        return "no-call", ""
    funcs = bv.get_functions_containing(call_addr)
    if not funcs:
        return "no-func", ""

    # Comment always reflects the full alias family — even when narrowing
    # collapsed the indirect-branch list to a single concrete target, the
    # comment shows whether the call site is alias-rich.
    comment = format_comment(bv, call_hash, targets)
    bv.set_comment_at(call_addr, comment)

    write_targets, write_status = final_targets_to_write(
        bv, movabs_addr, targets, ctx
    )
    if not write_targets:
        return "resolved-comment-only", comment
    funcs[0].set_user_indirect_branches(
        call_addr, [(bv.arch, t) for t in write_targets]
    )
    if write_status == "ok-disambig":
        return "resolved-disambig", comment
    return "resolved", comment


def clear_one_xfg_site(bv: BinaryView, movabs_addr: int) -> str:
    """Clear XFG branch targets and comment at one movabs r10 site.

    Returns one of: "cleared", "no-call", "no-func".

    Does NOT require a hash match — cleanup must succeed even when the
    original target was renamed, deleted, or its function-hash byte changed.
    """
    call_addr = find_xfg_call(bv, movabs_addr)
    if call_addr is None:
        return "no-call"
    funcs = bv.get_functions_containing(call_addr)
    if not funcs:
        return "no-func"
    funcs[0].set_user_indirect_branches(call_addr, [])
    bv.set_comment_at(call_addr, "")
    return "cleared"
