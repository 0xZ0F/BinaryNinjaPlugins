from typing import List

from binaryninja import BinaryView, log

from .scan import XfgSite


def apply_resolutions(bv: BinaryView, sites: List[XfgSite]) -> int:
    n_unique = 0
    n_aliased = 0
    n_unresolved = 0
    n_skipped = 0

    for site in sites:
        if site.func_start is None:
            n_skipped += 1
            continue
        func = bv.get_function_at(site.func_start)
        if func is None:
            n_skipped += 1
            continue

        if len(site.targets) == 1:
            target = site.targets[0]
            target_func = bv.get_function_at(target)
            target_name = target_func.name if target_func else hex(target)
            try:
                func.set_user_indirect_branches(site.call_addr, [(bv.arch, target)])
                func.add_user_code_ref(site.call_addr, target)
                func.set_comment_at(site.call_addr, f"XFG -> {target_name}")
                n_unique += 1
            except Exception as e:
                log.log_debug(f"[MSVC C++] xfg.apply unique {hex(site.call_addr)} failed: {e}")
                n_skipped += 1
        elif len(site.targets) > 1:
            try:
                preview_count = min(8, len(site.targets))
                names: list[str] = []
                for t in site.targets[:preview_count]:
                    tf = bv.get_function_at(t)
                    names.append(tf.name if tf else hex(t))
                more = len(site.targets) - preview_count
                comment = f"XFG hash {hex(site.hash_value)} ({len(site.targets)} candidates): " + ", ".join(names)
                if more > 0:
                    comment += f" ... +{more} more"
                func.set_comment_at(site.call_addr, comment)
                n_aliased += 1
            except Exception as e:
                log.log_debug(f"[MSVC C++] xfg.apply aliased {hex(site.call_addr)} failed: {e}")
                n_skipped += 1
        else:
            try:
                func.set_comment_at(site.call_addr, f"XFG hash {hex(site.hash_value)} unresolved")
                n_unresolved += 1
            except Exception as e:
                log.log_debug(f"[MSVC C++] xfg.apply unresolved {hex(site.call_addr)} failed: {e}")
                n_skipped += 1

    log.log_info(
        f"[MSVC C++] XFG applied: {n_unique} CFG edges, "
        f"{n_aliased} aliased comments, {n_unresolved} unresolved comments, "
        f"{n_skipped} skipped"
    )
    return n_unique + n_aliased + n_unresolved
