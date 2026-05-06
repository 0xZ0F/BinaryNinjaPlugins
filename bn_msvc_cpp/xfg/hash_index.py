from typing import Dict, List

from binaryninja import BinaryView, log


HashIndex = Dict[int, List[int]]


def build_hash_index(bv: BinaryView) -> HashIndex:
    """Map XFG call-site hash (low bit cleared) -> list of function addresses.
    The hash sits 8 bytes before each function. Stored form has bit 0 set;
    call-site immediate has bit 0 cleared. We index by the call-site form.
    """
    index: HashIndex = {}
    for func in bv.functions:
        try:
            data = bv.read(func.start - 8, 8)
        except Exception:
            continue
        if len(data) < 8:
            continue
        h_stored = int.from_bytes(data, "little")
        if h_stored == 0 or (h_stored & 1) == 0:
            continue
        h_call = h_stored & ~1
        index.setdefault(h_call, []).append(func.start)
    log.log_info(
        f"[MSVC C++] XFG hash index: {len(index)} unique hashes "
        f"covering {sum(len(v) for v in index.values())} functions"
    )
    return index
