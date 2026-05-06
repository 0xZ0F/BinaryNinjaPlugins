from dataclasses import dataclass, field
from typing import List, Optional

from binaryninja import BinaryView, log

from .hash_index import HashIndex


@dataclass
class XfgSite:
    movabs_addr: int
    call_addr: int
    hash_value: int
    targets: List[int] = field(default_factory=list)
    func_start: Optional[int] = None


def scan_xfg_sites(bv: BinaryView, hash_index: HashIndex) -> List[XfgSite]:
    """Byte-scan .text for `49 BA <imm64>` (mov r10, imm64) followed shortly by an
    indirect call (FF 15 / FF 25). Each match is an XFG dispatch site.
    """
    text = bv.get_section_by_name(".text")
    if text is None:
        return []
    try:
        buf = bv.read(text.start, text.end - text.start)
    except Exception as e:
        log.log_warn(f"[MSVC C++] xfg.scan: read .text failed: {e}")
        return []
    if not buf:
        return []

    sites: List[XfgSite] = []
    n_resolved_unique = 0
    n_resolved_multi = 0
    n_unresolved = 0

    i = 0
    end = len(buf) - 16
    while i < end:
        if buf[i] == 0x49 and buf[i + 1] == 0xBA:
            hash_val = int.from_bytes(buf[i + 2:i + 10], "little")
            call_off = _find_indirect_call(buf, i + 10, min(len(buf), i + 10 + 24))
            if call_off is None:
                i += 1
                continue

            movabs_addr = text.start + i
            call_addr = text.start + call_off

            targets = list(hash_index.get(hash_val, ()))
            site = XfgSite(
                movabs_addr=movabs_addr,
                call_addr=call_addr,
                hash_value=hash_val,
                targets=targets,
            )
            func = bv.get_functions_containing(call_addr)
            if func:
                site.func_start = func[0].start
            sites.append(site)

            if len(targets) == 1:
                n_resolved_unique += 1
            elif len(targets) > 1:
                n_resolved_multi += 1
            else:
                n_unresolved += 1

            i = call_off + 6
            continue
        i += 1

    log.log_info(
        f"[MSVC C++] XFG sites: {len(sites)} ({n_resolved_unique} unique, "
        f"{n_resolved_multi} aliased, {n_unresolved} unresolved)"
    )
    return sites


def _find_indirect_call(buf: bytes, start: int, end: int) -> Optional[int]:
    """Locate FF 15 (call [rip+disp32]) within [start, end) — typical XFG dispatch."""
    j = start
    while j < end - 5:
        if buf[j] == 0xFF and buf[j + 1] == 0x15:
            return j
        j += 1
    return None
