"""All XFG user commands and their background workers.

The full XFG menu tree from `xfg_xrefs.py`:

  XFG -> Cross-References:
    Find Here / Find in This Function / Add All / Remove All

  XFG -> Indirect Calls:
    Resolve Here / Remove Here / Go to Target Here / View Candidates Here
    Resolve in This Function / Remove in This Function
    Resolve All / Remove All

  XFG -> Reset Hash Map Cache

The compact comment formatter (`xfg.comment.format_comment`) and the
View Candidates command are the only deliberate divergences from the old
plugin; everything else is verbatim.
"""

from binaryninja import BinaryView, Function, log_info
from binaryninja.interaction import (
    get_choice_input,
    show_message_box,
    show_plain_text_report,
)
from binaryninja.plugin import BackgroundTaskThread

from ..util import check_arch, confirm, start_bg
from ..xfg.apply import clear_one_xfg_site, resolve_one_xfg_site
from ..xfg.crossfeed import (
    final_targets_to_write,
    get_vtable_disambig_ctx,
    try_vtable_disambig,
)
from ..xfg.hash_index import (
    find_targets_for_hash,
    get_hash_map,
    read_xfg_hash,
    reset_hash_map,
)
from ..xfg.settings import get_alias_threshold, get_metadata_mode
from ..xfg.sites import (
    MOVABS_R10_PREFIX,
    PATTERN_LEN,
    add_xref,
    enumerate_xfg_sites_in_range,
    find_xfg_call,
    remove_xref,
    search_pattern,
    xfg_site_at,
)


# ---- Cross-References: per-function ------------------------------------

def _run_for_func(bv: BinaryView, func_start: int, func_name: str) -> None:
    """Find all XFG call sites for the function at func_start and register xrefs."""
    raw_hash = read_xfg_hash(bv, func_start)
    if raw_hash is None:
        show_message_box(
            "XFG Xrefs",
            f"No valid XFG hash at {func_start - 8:#x}.\n"
            "The function may not be XFG-protected, or the bytes before it\n"
            "are unmapped / do not have bit 0 set.",
        )
        return

    call_hash = raw_hash & ~0x01  # call sites load hash with bit 0 cleared
    hits = search_pattern(bv, call_hash)

    if not hits:
        log_info(
            f"bn_msvc_cpp: {func_name} @ {func_start:#x} - no XFG call sites "
            f"(call-site hash {call_hash:#018x})"
        )
        show_message_box(
            "XFG Xrefs",
            f"No XFG call sites found for {func_name}.\n\n"
            f"XFG hash      : {raw_hash:#018x}\n"
            f"Call-site hash: {call_hash:#018x}\n\n"
            "Note: results include type-hash aliases (same prototype, different function).",
        )
        return

    hash_map = get_hash_map(bv)
    targets = find_targets_for_hash(bv, call_hash, hash_map)
    ctx = get_vtable_disambig_ctx(bv)
    mode = get_metadata_mode()

    bv.begin_undo_actions()
    added = 0
    skipped = 0
    skipped_by_mode: dict = {}
    skipped_other_alias = 0
    for site in sorted(hits):
        write_targets, write_status = final_targets_to_write(
            bv, site, targets, ctx, mode
        )
        if not write_targets:
            skipped_by_mode[write_status] = skipped_by_mode.get(write_status, 0) + 1
            continue
        if func_start not in write_targets:
            skipped_other_alias += 1
            continue
        if add_xref(bv, site, func_start):
            added += 1
        else:
            skipped += 1
    bv.commit_undo_actions()
    parts = [f"{added} xref(s) added"]
    if skipped:
        parts.append(f"{skipped} skipped (call site not in function)")
    if skipped_other_alias:
        parts.append(f"{skipped_other_alias} skipped (narrowed to a different alias)")
    skipped_alias = skipped_by_mode.get("skip-alias", 0)
    if skipped_alias:
        parts.append(f"{skipped_alias} skipped (>{get_alias_threshold()} aliases, no vtable disambig)")
    if skipped_by_mode.get("skip-mode-none", 0):
        parts.append(f"{skipped_by_mode['skip-mode-none']} skipped (mode=none)")
    if skipped_by_mode.get("skip-not-disambig", 0):
        parts.append(f"{skipped_by_mode['skip-not-disambig']} skipped (mode=disambig_only, not unique)")
    log_info(f"bn_msvc_cpp: {func_name} (mode={mode}) - " + ", ".join(parts))


def cmd_xref_for_address(bv: BinaryView, addr: int) -> None:
    if not check_arch(bv, "XFG Xrefs"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box("XFG Xrefs", f"No function found at {addr:#x}.")
        return
    _run_for_func(bv, funcs[0].start, funcs[0].name)


def cmd_xref_for_function(bv: BinaryView, func: Function) -> None:
    if not check_arch(bv, "XFG Xrefs"):
        return
    _run_for_func(bv, func.start, func.name)


# ---- Cross-References: whole-binary ------------------------------------

def _do_add_all(bv: BinaryView, task: BackgroundTaskThread) -> None:
    task.progress = "XFG: building function hash map..."
    hash_map = get_hash_map(bv)
    if not hash_map:
        show_message_box(
            "Add All XFG Xrefs", "No XFG-protected functions found in this binary."
        )
        return

    log_info(
        f"bn_msvc_cpp: found {len(hash_map)} unique XFG hashes across "
        f"{sum(len(v) for v in hash_map.values())} function(s)"
    )

    ctx = get_vtable_disambig_ctx(bv)
    bv.begin_undo_actions()
    added = 0
    skipped = 0
    skipped_by_mode: dict = {}
    disambiguated = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, MOVABS_R10_PREFIX)
        if found is None:
            break

        hash_bytes = bv.read(found + 2, 8)
        if not hash_bytes or len(hash_bytes) < 8:
            addr = found + 1
            continue

        call_hash = int.from_bytes(hash_bytes, "little")
        func_hash = call_hash | 0x01

        targets = hash_map.get(func_hash)
        if targets:
            write_targets, write_status = final_targets_to_write(
                bv, found, targets, ctx
            )
            if not write_targets:
                skipped_by_mode[write_status] = skipped_by_mode.get(write_status, 0) + 1
            else:
                if write_status == "ok-disambig":
                    disambiguated += 1
                for target in write_targets:
                    if add_xref(bv, found, target):
                        added += 1
                    else:
                        skipped += 1

        sites += 1
        if sites % 64 == 0:
            task.progress = (
                f"XFG: scanning sites... {sites} found, "
                f"{added} xrefs added, {disambiguated} disambig"
            )
        addr = found + PATTERN_LEN

    bv.commit_undo_actions()
    skipped_alias = skipped_by_mode.get("skip-alias", 0)
    skipped_mode_none = skipped_by_mode.get("skip-mode-none", 0)
    skipped_not_disambig = skipped_by_mode.get("skip-not-disambig", 0)
    mode = get_metadata_mode()
    log_info(
        f"bn_msvc_cpp: done (mode={mode}) - {added} xref(s) added, "
        f"{disambiguated} site(s) disambiguated to 1, "
        f"{skipped_alias} skipped (alias-rich), "
        f"{skipped_mode_none} skipped (mode=none), "
        f"{skipped_not_disambig} skipped (mode=disambig_only, not unique), "
        f"{skipped} skipped (call site not in any function)"
    )
    show_message_box(
        "Add All XFG Xrefs",
        f"Scan complete (mode={mode}){' (cancelled)' if task.cancelled else ''}.\n\n"
        f"  Xrefs added            : {added}\n"
        f"  Disambiguated to 1     : {disambiguated}\n"
        f"  Skipped (alias-rich)   : {skipped_alias} (>{get_alias_threshold()} aliases, no vtable disambig)\n"
        f"  Skipped (mode=none)    : {skipped_mode_none}\n"
        f"  Skipped (need disambig): {skipped_not_disambig}\n"
        f"  Skipped (no func)      : {skipped}\n\n"
        "Added xrefs are visible in the cross-references panel and can be\n"
        "undone via Edit -> Undo.",
    )


def cmd_xref_add_all(bv: BinaryView) -> None:
    if not check_arch(bv, "Add All XFG Xrefs"):
        return
    start_bg("XFG: adding all cross-references...", _do_add_all, bv)


def _do_remove_all_xrefs(bv: BinaryView, task: BackgroundTaskThread) -> None:
    task.progress = "XFG: building function hash map..."
    hash_map = get_hash_map(bv)
    if not hash_map:
        show_message_box("Remove All XFG Xrefs", "No XFG-protected functions found.")
        return

    bv.begin_undo_actions()
    removed = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, MOVABS_R10_PREFIX)
        if found is None:
            break

        hash_bytes = bv.read(found + 2, 8)
        if not hash_bytes or len(hash_bytes) < 8:
            addr = found + 1
            continue

        call_hash = int.from_bytes(hash_bytes, "little")
        func_hash = call_hash | 0x01

        targets = hash_map.get(func_hash)
        if targets:
            for target in targets:
                if remove_xref(bv, found, target):
                    removed += 1

        sites += 1
        if sites % 64 == 0:
            task.progress = f"XFG: clearing xrefs... {removed} removed"
        addr = found + PATTERN_LEN

    bv.commit_undo_actions()
    show_message_box(
        "Remove All XFG Xrefs",
        f"Removed {removed} XFG xref(s){' (cancelled)' if task.cancelled else ''}.",
    )


def cmd_xref_remove_all(bv: BinaryView) -> None:
    if not check_arch(bv, "Remove All XFG Xrefs"):
        return
    if not confirm(
        "Remove All XFG Cross-References",
        "Remove ALL XFG cross-references previously added by this plugin?\n\n"
        "This walks the entire binary and clears every user xref at a movabs r10 site.",
    ):
        return
    start_bg("XFG: removing all cross-references...", _do_remove_all_xrefs, bv)


# ---- Indirect Calls: per-site ------------------------------------------

def cmd_resolve_here(bv: BinaryView, addr: int) -> None:
    if not check_arch(bv, "Resolve XFG Call Target Here"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box(
            "Resolve XFG Call Target Here",
            f"No function contains {addr:#x}.",
        )
        return
    site = xfg_site_at(bv, addr, funcs[0])
    if site is None:
        show_message_box(
            "Resolve XFG Call Target Here",
            f"No XFG call site at {addr:#x}.\n\n"
            "Place the cursor on the 'movabs r10' or on the guarded indirect call.",
        )
        return
    movabs_addr, call_addr = site
    hash_map = get_hash_map(bv)
    ctx = get_vtable_disambig_ctx(bv)

    bv.begin_undo_actions()
    status, comment = resolve_one_xfg_site(bv, movabs_addr, hash_map, ctx)
    bv.commit_undo_actions()
    bv.update_analysis()

    if status in ("resolved", "resolved-disambig", "resolved-comment-only") and call_addr is not None:
        log_info(f"bn_msvc_cpp: {status} @ {call_addr:#x} (movabs @ {movabs_addr:#x}) - {comment}")
    elif status == "no-call":
        show_message_box(
            "Resolve XFG Call Target Here",
            f"Found movabs r10 @ {movabs_addr:#x} but couldn't locate the guarded call.",
        )
    elif status == "no-func":
        show_message_box(
            "Resolve XFG Call Target Here",
            "The guarded call address is not inside any function.",
        )
    else:
        show_message_box(
            "Resolve XFG Call Target Here",
            f"No XFG targets matched the hash at {movabs_addr:#x}.",
        )


def cmd_remove_here(bv: BinaryView, addr: int) -> None:
    if not check_arch(bv, "Remove XFG Call Target Here"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box(
            "Remove XFG Call Target Here",
            f"No function contains {addr:#x}.",
        )
        return
    site = xfg_site_at(bv, addr, funcs[0])
    if site is None:
        show_message_box(
            "Remove XFG Call Target Here",
            f"No XFG call site at {addr:#x}.\n\n"
            "Place the cursor on the 'movabs r10' or on the guarded indirect call.",
        )
        return
    movabs_addr, call_addr = site

    bv.begin_undo_actions()
    status = clear_one_xfg_site(bv, movabs_addr)
    bv.commit_undo_actions()
    bv.update_analysis()

    if status == "cleared" and call_addr is not None:
        log_info(f"bn_msvc_cpp: cleared XFG annotations at {call_addr:#x}")
    else:
        show_message_box(
            "Remove XFG Call Target Here",
            f"Could not clear XFG site at {movabs_addr:#x} ({status}).",
        )


def cmd_goto_xfg_target(bv: BinaryView, addr: int) -> None:
    """Right-click: navigate to the target of the XFG-guarded call at the cursor."""
    if not check_arch(bv, "Go to XFG Target"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box("Go to XFG Target", f"No function contains {addr:#x}.")
        return
    site = xfg_site_at(bv, addr, funcs[0])
    if site is None:
        show_message_box(
            "Go to XFG Target",
            f"No XFG call site at {addr:#x}.\n\n"
            "Place the cursor on the 'movabs r10' or on the guarded indirect call.",
        )
        return
    movabs_addr, _call_addr = site

    hash_bytes = bv.read(movabs_addr + 2, 8)
    if not hash_bytes or len(hash_bytes) < 8:
        show_message_box(
            "Go to XFG Target", f"Could not read XFG hash at {movabs_addr:#x}."
        )
        return
    call_hash = int.from_bytes(hash_bytes, "little")

    hash_map = get_hash_map(bv)
    targets = find_targets_for_hash(bv, call_hash, hash_map)
    if not targets:
        show_message_box(
            "Go to XFG Target",
            f"No target functions match the XFG hash at {movabs_addr:#x}.",
        )
        return

    # Try vtable disambiguation first - on alias-rich hashes this collapses
    # 200 candidates to the single function the call actually dispatches to.
    ctx = get_vtable_disambig_ctx(bv)
    narrowed = try_vtable_disambig(bv, movabs_addr, targets, ctx)
    nav_targets = narrowed if narrowed is not None else targets

    if len(nav_targets) == 1:
        target = nav_targets[0]
    else:
        labels: list[str] = []
        for t in nav_targets:
            f = bv.get_function_at(t)
            if f is None:
                labels.append(f"<no function>  ({t:#x})")
                continue
            sym = f.symbol
            name = sym.short_name if sym else f.name
            labels.append(f"{name}  ({t:#x})")
        choice = get_choice_input(
            f"Multiple targets share XFG hash {call_hash:#018x}.\nSelect target:",
            "Go to XFG Target",
            labels,
        )
        if choice is None:
            return
        target = nav_targets[choice]

    try:
        bv.file.navigate(bv.file.view, target)
    except Exception as e:
        show_message_box(
            "Go to XFG Target",
            f"Resolved target {target:#x} but navigation failed: {e}",
        )


def cmd_view_candidates(bv: BinaryView, addr: int) -> None:
    """Right-click: show every candidate for the XFG hash at the cursor.

    Lists EVERY hash-matching function (no vtable narrowing — the user
    explicitly asked to see everything). Sorted by address; rendered as a
    plain-text report.
    """
    if not check_arch(bv, "View XFG Candidates"):
        return
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        show_message_box("View XFG Candidates", f"No function contains {addr:#x}.")
        return
    site = xfg_site_at(bv, addr, funcs[0])
    if site is None:
        show_message_box(
            "View XFG Candidates",
            f"No XFG call site at {addr:#x}.\n\n"
            "Place the cursor on the 'movabs r10' or on the guarded indirect call.",
        )
        return
    movabs_addr, call_addr = site

    hash_bytes = bv.read(movabs_addr + 2, 8)
    if not hash_bytes or len(hash_bytes) < 8:
        show_message_box(
            "View XFG Candidates",
            f"Could not read XFG hash at {movabs_addr:#x}.",
        )
        return
    call_hash = int.from_bytes(hash_bytes, "little")

    hash_map = get_hash_map(bv)
    targets = find_targets_for_hash(bv, call_hash, hash_map)
    if not targets:
        show_message_box(
            "View XFG Candidates",
            f"No target functions match XFG hash {call_hash:#018x}.",
        )
        return

    targets_sorted = sorted(targets)
    lines = [
        f"XFG call site:   {(call_addr or movabs_addr):#x}",
        f"XFG hash:        {call_hash:#018x}",
        f"Candidates:      {len(targets_sorted)}",
        "",
    ]
    for t in targets_sorted:
        f = bv.get_function_at(t)
        if f is None:
            lines.append(f"  {t:#x}    <no function>")
            continue
        sym = f.symbol
        full = sym.full_name if sym and sym.full_name else f.name
        lines.append(f"  {t:#x}    {full}")
    show_plain_text_report("XFG Candidates", "\n".join(lines))


# ---- Indirect Calls: per-function --------------------------------------

def cmd_resolve_in_func(bv: BinaryView, func: Function) -> None:
    if not check_arch(bv, "Resolve XFG Call Targets in This Function"):
        return
    hash_map = get_hash_map(bv)
    if not hash_map:
        show_message_box(
            "Resolve XFG Call Targets in This Function",
            "No XFG-protected functions found in this binary.",
        )
        return

    ctx = get_vtable_disambig_ctx(bv)
    bv.begin_undo_actions()
    resolved = 0
    disambig = 0
    comment_only = 0
    skipped_no_call = 0
    skipped_no_func = 0
    skipped_no_targets = 0

    try:
        ranges = list(func.address_ranges)
    except Exception:
        ranges = []
    if not ranges:
        ranges = [type("R", (), {"start": func.start, "end": func.start + func.total_bytes})()]

    for r in ranges:
        for movabs_addr, _call in enumerate_xfg_sites_in_range(bv, r.start, r.end):
            status, _ = resolve_one_xfg_site(bv, movabs_addr, hash_map, ctx)
            if status == "resolved":
                resolved += 1
            elif status == "resolved-disambig":
                disambig += 1
                resolved += 1
            elif status == "resolved-comment-only":
                comment_only += 1
            elif status == "no-call":
                skipped_no_call += 1
            elif status == "no-func":
                skipped_no_func += 1
            elif status == "no-targets":
                skipped_no_targets += 1

    bv.commit_undo_actions()
    bv.update_analysis()
    mode = get_metadata_mode()
    log_info(
        f"bn_msvc_cpp: resolved {resolved} XFG site(s) inside {func.name} "
        f"(mode={mode}, {disambig} via vtable disambig, {comment_only} comment-only)"
    )
    show_message_box(
        "Resolve XFG Call Targets in This Function",
        f"Function: {func.name}  (mode={mode})\n\n"
        f"  Resolved (full)       : {resolved}\n"
        f"  -- of which disambig'd: {disambig}\n"
        f"  Comment only          : {comment_only} (alias-rich or mode-restricted)\n"
        f"  No call found         : {skipped_no_call}\n"
        f"  Call not in func      : {skipped_no_func}\n"
        f"  No matching hash      : {skipped_no_targets}\n\n"
        "Undo via Edit -> Undo.",
    )


def cmd_remove_in_func(bv: BinaryView, func: Function) -> None:
    if not check_arch(bv, "Remove XFG Call Targets in This Function"):
        return

    bv.begin_undo_actions()
    cleared = 0

    try:
        ranges = list(func.address_ranges)
    except Exception:
        ranges = []
    if not ranges:
        ranges = [type("R", (), {"start": func.start, "end": func.start + func.total_bytes})()]

    for r in ranges:
        for movabs_addr, _call in enumerate_xfg_sites_in_range(bv, r.start, r.end):
            if clear_one_xfg_site(bv, movabs_addr) == "cleared":
                cleared += 1

    bv.commit_undo_actions()
    bv.update_analysis()
    log_info(f"bn_msvc_cpp: cleared {cleared} XFG site(s) inside {func.name}")
    show_message_box(
        "Remove XFG Call Targets in This Function",
        f"Cleared XFG annotations at {cleared} call site(s) in {func.name}.",
    )


# ---- Indirect Calls: whole-binary --------------------------------------

def do_resolve_indirect_calls(bv: BinaryView, task: BackgroundTaskThread) -> None:
    """Whole-binary worker. Public so Run Full Analysis can chain it."""
    task.progress = "XFG: building function hash map..."
    hash_map = get_hash_map(bv)
    if not hash_map:
        show_message_box(
            "Resolve XFG Indirect Call Targets",
            "No XFG-protected functions found in this binary.",
        )
        return

    log_info(
        f"bn_msvc_cpp: found {len(hash_map)} unique XFG hashes across "
        f"{sum(len(v) for v in hash_map.values())} function(s)"
    )

    ctx = get_vtable_disambig_ctx(bv)
    bv.begin_undo_actions()
    resolved = 0
    disambig = 0
    comment_only = 0
    skipped_no_call = 0
    skipped_no_func = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, MOVABS_R10_PREFIX)
        if found is None:
            break

        status, _ = resolve_one_xfg_site(bv, found, hash_map, ctx)
        if status == "resolved":
            resolved += 1
        elif status == "resolved-disambig":
            disambig += 1
            resolved += 1
        elif status == "resolved-comment-only":
            comment_only += 1
        elif status == "no-call":
            skipped_no_call += 1
        elif status == "no-func":
            skipped_no_func += 1

        sites += 1
        if sites % 32 == 0:
            task.progress = (
                f"XFG: resolving... {resolved}/{sites} resolved, "
                f"{disambig} disambig, {comment_only} comment-only"
            )
        addr = found + PATTERN_LEN

    bv.commit_undo_actions()
    bv.update_analysis()
    mode = get_metadata_mode()
    log_info(
        f"bn_msvc_cpp: indirect call resolution done (mode={mode}) - "
        f"{resolved} site(s) resolved ({disambig} disambiguated to 1), "
        f"{comment_only} comment-only, "
        f"{skipped_no_call} skipped (no XFG call), "
        f"{skipped_no_func} skipped (not in function)"
    )
    show_message_box(
        "Resolve XFG Indirect Call Targets",
        f"Scan complete (mode={mode}){' (cancelled)' if task.cancelled else ''}.\n\n"
        f"  Resolved (full)       : {resolved}\n"
        f"  -- of which disambig'd: {disambig}\n"
        f"  Comment only          : {comment_only} (alias>{get_alias_threshold()} or mode-restricted)\n"
        f"  Skipped (no call)     : {skipped_no_call}\n"
        f"  Skipped (no func)     : {skipped_no_func}\n\n"
        "Resolved call sites have an 'XFG -> ...' comment in HLIL. Sites with\n"
        "indirect branch targets also show CFG edges; comment-only sites skip\n"
        "those to avoid BNDB bloat / analysis cascade. Adjust via\n"
        "Settings -> MSVC C++.\n\n"
        "Undo via Edit -> Undo.",
    )


def cmd_resolve_all(bv: BinaryView) -> None:
    if not check_arch(bv, "Resolve XFG Indirect Call Targets"):
        return
    start_bg(
        "XFG: resolving all indirect call targets...",
        do_resolve_indirect_calls,
        bv,
    )


def _do_remove_indirect_calls(bv: BinaryView, task: BackgroundTaskThread) -> None:
    task.progress = "XFG: clearing branch targets..."

    bv.begin_undo_actions()
    cleared = 0
    sites = 0
    addr = bv.start

    while True:
        if task.cancelled:
            break
        found = bv.find_next_data(addr, MOVABS_R10_PREFIX)
        if found is None:
            break

        if clear_one_xfg_site(bv, found) == "cleared":
            cleared += 1

        sites += 1
        if sites % 64 == 0:
            task.progress = f"XFG: clearing branch targets... {cleared} cleared"
        addr = found + PATTERN_LEN

    bv.commit_undo_actions()
    bv.update_analysis()
    show_message_box(
        "Remove XFG Indirect Branch Targets",
        f"Cleared indirect branch targets at {cleared} call site(s)"
        f"{' (cancelled)' if task.cancelled else ''}.",
    )


def cmd_remove_all(bv: BinaryView) -> None:
    if not check_arch(bv, "Remove XFG Indirect Branch Targets"):
        return
    if not confirm(
        "Remove All XFG Indirect Branch Targets",
        "Clear ALL user-set indirect branch targets and 'XFG ->' comments at every "
        "XFG-guarded call site in this binary?",
    ):
        return
    start_bg(
        "XFG: removing all indirect branch targets...",
        _do_remove_indirect_calls,
        bv,
    )


# ---- Reset Hash Map Cache ----------------------------------------------

def cmd_reset_hash_map(bv: BinaryView) -> None:
    if not check_arch(bv, "Reset XFG Hash Map Cache"):
        return
    reset_hash_map(bv)
