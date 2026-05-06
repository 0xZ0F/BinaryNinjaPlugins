import struct

from binaryninja import BinaryView, log

from .model import BaseEdge, ClassGraph, ClassNode

_RTTI_METADATA_KEY = "rtti"


def walk_rtti(bv: BinaryView) -> ClassGraph:
    """Read BN's bundled RTTI metadata if present; fall back to scanning COLs in .rdata."""
    graph = ClassGraph()
    n_meta = _consume_metadata(bv, graph)
    if n_meta == 0:
        n_scan = _scan_cols(bv, graph)
        log.log_info(f"[MSVC C++] rtti: {n_meta} from BN metadata, {n_scan} from COL scan; total {len(graph)}")
    else:
        log.log_info(f"[MSVC C++] rtti: {n_meta} from BN metadata; total {len(graph)}")
    return graph


def _consume_metadata(bv: BinaryView, graph: ClassGraph) -> int:
    try:
        meta = bv.query_metadata(_RTTI_METADATA_KEY)
    except Exception as e:
        log.log_debug(f"[MSVC C++] no 'rtti' metadata ({type(e).__name__}: {e})")
        return 0

    classes = _get(meta, "classes")
    if classes is None:
        return 0

    n = 0
    for rtti_obj_addr_key, info in _items(classes):
        try:
            rtti_obj_addr = int(rtti_obj_addr_key)
        except (TypeError, ValueError):
            continue
        class_name = _as_str(_get(info, "className"))
        if not class_name:
            continue
        vft_addr = _vft_addr(_get(info, "vft"))
        bases = []
        for b in _iter(_get(info, "bases") or []):
            b_name = _as_str(_get(b, "className"))
            if not b_name:
                continue
            bases.append(BaseEdge(
                class_name=b_name,
                class_offset=int(_get(b, "classOffset") or 0),
                vft_addr=_vft_addr(_get(b, "vft")),
            ))
        graph.add(ClassNode(
            class_name=class_name,
            rtti_obj_addr=rtti_obj_addr,
            vft_addr=vft_addr,
            bases=bases,
        ))
        n += 1
    return n


def _scan_cols(bv: BinaryView, graph: ClassGraph) -> int:
    """Find COL pointers in .rdata, parse the chain to recover ClassNode + bases."""
    rdata = bv.get_section_by_name(".rdata")
    if rdata is None:
        return 0
    image_lo, image_hi = bv.start, bv.end
    try:
        buf = bv.read(rdata.start, rdata.end - rdata.start)
    except Exception:
        return 0
    if not buf:
        return 0

    td_cache: dict[int, str] = {}
    seen_cols = set()
    n = 0

    for off in range(0, len(buf) - 8, 8):
        q = int.from_bytes(buf[off:off + 8], "little")
        if q < image_lo or q >= image_hi or q in seen_cols:
            continue
        col_buf = bv.read(q, 20)
        if len(col_buf) < 20:
            continue
        sig, _coff, _cd, td_rva, chd_rva = struct.unpack("<IIIII", col_buf)
        if sig not in (0, 1):
            continue
        td_addr = bv.start + td_rva
        chd_addr = bv.start + chd_rva
        if not (image_lo <= td_addr < image_hi and image_lo <= chd_addr < image_hi):
            continue
        td_marker = bv.read(td_addr + 16, 4)
        if len(td_marker) < 4 or not td_marker.startswith(b".?A"):
            continue
        chd_buf = bv.read(chd_addr, 16)
        if len(chd_buf) < 16:
            continue
        _csig, _attr, num_bases, _bca = struct.unpack("<IIII", chd_buf)
        if num_bases < 1 or num_bases > 1024:
            continue

        class_name = _read_class_name(bv, td_addr, td_cache)
        if not class_name:
            continue
        vft_addr = rdata.start + off + 8
        bases = _walk_chd(bv, chd_addr, td_cache)

        seen_cols.add(q)
        graph.add(ClassNode(
            class_name=class_name,
            rtti_obj_addr=q,
            vft_addr=vft_addr,
            bases=bases,
        ))
        n += 1
    return n


def _walk_chd(bv: BinaryView, chd_addr: int, td_cache: dict) -> list[BaseEdge]:
    data = bv.read(chd_addr, 16)
    if len(data) < 16:
        return []
    _sig, _attr, num_bases, bca_rva = struct.unpack("<IIII", data)
    if num_bases <= 1:
        return []
    bca_addr = bv.start + bca_rva
    bca_data = bv.read(bca_addr, num_bases * 4)
    if len(bca_data) < num_bases * 4:
        return []
    bcd_rvas = struct.unpack(f"<{num_bases}I", bca_data)

    bases: list[BaseEdge] = []
    i = 1
    while i < num_bases:
        bcd_addr = bv.start + bcd_rvas[i]
        edge, num_contained = _parse_bcd(bv, bcd_addr, td_cache)
        if edge is not None:
            bases.append(edge)
        i += max(1, num_contained)
    return bases


def _parse_bcd(bv: BinaryView, bcd_addr: int, td_cache: dict):
    if not (bv.start <= bcd_addr < bv.end):
        return None, 1
    data = bv.read(bcd_addr, 24)
    if len(data) < 24:
        return None, 1
    td_rva, num_contained, mdisp, _pdisp, _vdisp, _attr = struct.unpack("<IIiiiI", data)
    td_addr = bv.start + td_rva
    if not (bv.start <= td_addr < bv.end):
        return None, num_contained
    name = _read_class_name(bv, td_addr, td_cache)
    if not name:
        return None, num_contained
    return BaseEdge(class_name=name, class_offset=mdisp, vft_addr=None), num_contained


def _read_class_name(bv: BinaryView, td_addr: int, cache: dict) -> str:
    if td_addr in cache:
        return cache[td_addr]
    raw_buf = bv.read(td_addr + 16, 512)
    if not raw_buf:
        cache[td_addr] = ""
        return ""
    end = raw_buf.find(b"\x00")
    raw = raw_buf[:end if end >= 0 else len(raw_buf)].decode("ascii", errors="replace")
    name = _td_name_to_class(raw)
    cache[td_addr] = name
    return name


def _td_name_to_class(raw: str) -> str:
    """`.?AVClassName@ns@@` -> `ns::ClassName`; templates kept as-is."""
    if not raw or not raw.startswith(".?A"):
        return raw
    body = raw[3:]
    if body.startswith("W4"):
        body = body[2:]
    elif body and body[0] in ("V", "U"):
        body = body[1:]
    if body.endswith("@@"):
        body = body[:-2]
    parts = [p for p in body.split("@") if p]
    return "::".join(reversed(parts))


def _vft_addr(vft):
    if vft is None:
        return None
    addr = _get(vft, "address")
    if addr is None:
        return None
    try:
        return int(addr)
    except (TypeError, ValueError):
        return None


def _get(obj, key):
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _items(obj):
    if isinstance(obj, dict):
        return obj.items()
    if hasattr(obj, "items"):
        return obj.items()
    return []


def _iter(obj):
    if obj is None:
        return []
    if isinstance(obj, (list, tuple)):
        return obj
    try:
        return list(obj)
    except TypeError:
        return []


def _as_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(v)
