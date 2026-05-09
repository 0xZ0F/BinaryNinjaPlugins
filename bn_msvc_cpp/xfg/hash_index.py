"""XFG hash map: function-start -> hash -> target list.

Stored on `bv.session_data` and treated as immutable by callers; never mutate
the returned dict. Self-invalidates when `find_targets_for_hash` falls back to
a binary scan and locates a hash the cache was missing.

Verbatim port of the relevant logic from `xfg_xrefs.py`.
"""

from binaryninja import BinaryView, log_info


def read_xfg_hash(bv: BinaryView, func_start: int):
    """Return the 8-byte XFG hash stored at func_start - 8, or None on failure."""
    raw = bv.read(func_start - 8, 8)
    if not raw or len(raw) < 8:
        return None
    h = int.from_bytes(raw, "little")
    if h & 0x01 == 0 or h in (0, 0xFFFFFFFFFFFFFFFF):
        return None  # bit 0 must be set in the stored hash; 0/all-FF = no hash
    return h


def _build_hash_map(bv: BinaryView) -> dict:
    """Build {func_hash_bit0_set: [func_start, ...]} for all XFG-protected functions."""
    m: dict[int, list[int]] = {}
    for func in bv.functions:
        h = read_xfg_hash(bv, func.start)
        if h is None:
            continue
        m.setdefault(h, []).append(func.start)
    return m


_HASH_MAP_KEY = "bn_msvc_cpp:xfg_hash_map"


def get_hash_map(bv: BinaryView) -> dict:
    """Return the cached XFG hash map for bv, building it on first use.

    Returned dict is treated as immutable by callers; never mutate it. The cache
    self-invalidates when `find_targets_for_hash` falls back to a binary scan
    and locates a hash the cache was missing.
    """
    cached = bv.session_data.get(_HASH_MAP_KEY)
    if cached is not None:
        return cached
    m = _build_hash_map(bv)
    bv.session_data[_HASH_MAP_KEY] = m
    return m


def reset_hash_map(bv: BinaryView) -> None:
    """Invalidate the cached XFG hash map and disambiguation context for bv."""
    bv.session_data.pop(_HASH_MAP_KEY, None)
    # Imported lazily to avoid a circular import; crossfeed owns its key.
    from .crossfeed import VTABLE_DISAMBIG_KEY
    bv.session_data.pop(VTABLE_DISAMBIG_KEY, None)
    log_info("bn_msvc_cpp: XFG hash map and vtable disambig caches cleared")


def _record_slow_path_hit(bv: BinaryView, func_hash: int, target_addrs: list) -> None:
    """Patch the cached hash map after a slow-path scan found a missing entry."""
    cached = bv.session_data.get(_HASH_MAP_KEY)
    if cached is None:
        return
    cached[func_hash] = list(target_addrs)


def find_targets_for_hash(bv: BinaryView, call_hash: int, hash_map: dict) -> list:
    """Return target function addresses for call_hash.

    Uses the pre-built hash map (fast path for already-analyzed functions) and
    falls back to a raw binary search for the stored hash value when the target
    hasn't been added to bv.functions yet. The stored XFG hash is func_hash
    (bit 0 set) located 8 bytes before the function entry point.

    A successful slow-path scan also patches the session cache so repeated
    lookups for this hash don't re-scan the binary.
    """
    func_hash = call_hash | 0x01
    known = hash_map.get(func_hash)
    if known:
        return known

    hash_bytes = func_hash.to_bytes(8, "little")
    targets: list[int] = []
    addr = bv.start
    while True:
        found = bv.find_next_data(addr, hash_bytes)
        if found is None:
            break
        targets.append(found + 8)
        addr = found + 8

    if targets:
        _record_slow_path_hit(bv, func_hash, targets)
    return targets
