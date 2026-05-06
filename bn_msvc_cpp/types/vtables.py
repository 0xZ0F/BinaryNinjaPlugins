import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from binaryninja import BinaryView, log

try:
    from binaryninja.demangle import demangle_ms as _demangle_ms
except Exception:
    _demangle_ms = None

from ..rtti import ClassGraph


@dataclass
class VtableSlot:
    offset: int
    target: int
    raw_mangle: str
    method_name: str
    is_thunk: bool
    func_type: object = None


@dataclass
class VtableScan:
    vft_addr: int
    class_name: str
    mi_for_base: Optional[str]
    slots: List[VtableSlot] = field(default_factory=list)


def scan_vtables(bv: BinaryView) -> List[VtableScan]:
    anchors = _collect_anchors(bv)
    log.log_info(f"[MSVC C++] vtable anchors: {len(anchors)}")
    if not anchors:
        return []

    sorted_addrs = sorted(anchors.keys())
    next_anchor = {a: (sorted_addrs[i + 1] if i + 1 < len(sorted_addrs) else None)
                   for i, a in enumerate(sorted_addrs)}

    results: List[VtableScan] = []
    for vft_addr, anchor_info in anchors.items():
        scan = _scan_one(bv, vft_addr, anchor_info, next_anchor.get(vft_addr))
        if scan is not None:
            results.append(scan)
    return results


def enrich_vtables(bv: BinaryView, scans: List[VtableScan]) -> int:
    """Build/update Class::VTable named structs from the scans. Returns count touched."""
    from binaryninja import QualifiedName, StructureBuilder, Type

    if not scans:
        return 0

    grouped: dict[Tuple[str, Optional[str]], List[VtableScan]] = {}
    for s in scans:
        key = (s.class_name, s.mi_for_base)
        grouped.setdefault(key, []).append(s)

    void_ptr = Type.pointer(bv.arch, Type.void())
    n_built = 0
    n_typed_slots = 0
    n_void_slots = 0

    for (class_name, mi_for_base), members in grouped.items():
        canonical = max(members, key=lambda s: len(s.slots))
        struct_name = _vtable_struct_name(class_name, mi_for_base)
        builder = StructureBuilder.create()
        builder.packed = True

        used_names: dict[str, int] = {}
        for slot in canonical.slots:
            base = _sanitize_member_name(slot.method_name) or f"slot_{slot.offset:x}"
            name = base
            if name in used_names:
                used_names[name] += 1
                name = f"{base}_{used_names[name]}"
            else:
                used_names[name] = 0
            slot_type = void_ptr
            if slot.func_type is not None:
                try:
                    slot_type = Type.pointer(bv.arch, slot.func_type)
                    n_typed_slots += 1
                except Exception:
                    n_void_slots += 1
            else:
                n_void_slots += 1
            builder.append(slot_type, name)

        try:
            qn = QualifiedName(struct_name)
            bv.define_user_type(qn, Type.structure_type(builder))
        except Exception as e:
            log.log_warn(f"[MSVC C++] failed to define {struct_name}: {e}")
            continue

        struct_type = Type.named_type_from_registered_type(bv, qn)
        for s in members:
            try:
                bv.define_user_data_var(s.vft_addr, struct_type)
            except Exception as e:
                log.log_debug(f"[MSVC C++] data_var {hex(s.vft_addr)} stamp failed: {e}")
        n_built += 1

    log.log_info(
        f"[MSVC C++] enriched: {n_built} struct types, "
        f"{n_typed_slots} typed slots, {n_void_slots} void* fallback slots"
    )
    return n_built


def _vtable_struct_name(class_name: str, mi_for_base: Optional[str]) -> str:
    if mi_for_base:
        return f"{class_name}::VTable_for_{_sanitize_segment(mi_for_base)}"
    return f"{class_name}::VTable"


def _sanitize_segment(s: str) -> str:
    out = []
    for c in s:
        if c.isalnum() or c in "_$":
            out.append(c)
        elif c in (":", "<", ">", ",", " ", "&", "*", "(", ")", "[", "]", "'", "`"):
            out.append("_")
        else:
            out.append("_")
    cleaned = "".join(out)
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned.strip("_") or "anon"


def _sanitize_member_name(s: str) -> str:
    if not s:
        return ""
    if s.startswith("`") and s.endswith("'"):
        s = s[1:-1]
    return _sanitize_segment(s)


def _collect_anchors(bv: BinaryView) -> dict:
    anchors: dict[int, dict] = {}

    for sym in bv.get_symbols():
        raw = getattr(sym, "raw_name", None) or ""
        short = getattr(sym, "short_name", None) or ""
        full = getattr(sym, "full_name", None) or ""

        is_mangled_vft = raw.startswith("??_7")
        is_named_vft = ("`vftable'" in short or "`vftable'" in full
                        or "::vftable" in short or "::vftable" in full)
        if not (is_mangled_vft or is_named_vft):
            continue

        addr = sym.address
        if addr in anchors:
            continue
        class_name, mi_for_base = _parse_vftable_name(bv, raw, short, full)
        if not class_name:
            continue
        anchors[addr] = {
            "raw_name": raw,
            "class_name": class_name,
            "mi_for_base": mi_for_base,
        }
    return anchors


def _parse_vftable_name(bv: BinaryView, raw: str, short: str, full: str) -> Tuple[str, Optional[str]]:
    primary, mi = _split_demangled_vftable(short or full)
    if primary and "`vftable'" not in primary and "::vftable" not in primary:
        return primary, mi

    if raw.startswith("??_7"):
        joined = _demangle_join(bv, raw)
        if joined:
            primary, mi = _split_demangled_vftable(joined)
            if primary:
                return primary, mi

    if short:
        primary, mi = _split_demangled_vftable(short)
        if primary:
            return primary, mi
    if full:
        primary, mi = _split_demangled_vftable(full)
        if primary:
            return primary, mi
    return raw, None


def _split_demangled_vftable(s: str) -> Tuple[str, Optional[str]]:
    if not s:
        return "", None
    for marker in ("::`vftable'", "::vftable"):
        if marker in s:
            head, tail = s.split(marker, 1)
            mi = None
            t = tail.strip()
            if t.startswith("{for `") and t.endswith("'}"):
                mi = t[len("{for `"):-len("'}")]
            return head, mi
    return "", None


_DEMANGLE_DEBUG_BUDGET = [3]


def _demangle_join(bv: BinaryView, raw: str) -> str:
    if not raw or _demangle_ms is None:
        return ""
    try:
        result = _demangle_ms(bv.arch, raw)
    except Exception as e:
        if _DEMANGLE_DEBUG_BUDGET[0] > 0:
            log.log_debug(f"[MSVC C++] demangle_ms threw on {raw!r}: {e}")
            _DEMANGLE_DEBUG_BUDGET[0] -= 1
        return ""

    if _DEMANGLE_DEBUG_BUDGET[0] > 0:
        log.log_debug(f"[MSVC C++] demangle_ms({raw[:60]!r}) -> {result!r}")
        _DEMANGLE_DEBUG_BUDGET[0] -= 1

    if result is None:
        return ""
    if isinstance(result, tuple) and len(result) == 2:
        _t, parts = result
        if isinstance(parts, list) and parts:
            return "::".join(str(p) for p in parts)
        if isinstance(parts, str):
            return parts
    if isinstance(result, list) and result:
        return "::".join(str(p) for p in result)
    if isinstance(result, str):
        return result
    return ""


def _scan_one(bv: BinaryView, vft_addr: int, info: dict, next_addr: Optional[int]) -> Optional[VtableScan]:
    text = bv.get_section_by_name(".text")
    text_lo = text.start if text else bv.start
    text_hi = text.end if text else bv.end

    slots: List[VtableSlot] = []
    cursor = vft_addr
    max_slots = 4096
    while True:
        if next_addr is not None and cursor >= next_addr:
            break
        if len(slots) >= max_slots:
            break
        data = bv.read(cursor, 8)
        if len(data) < 8:
            break
        target = struct.unpack("<Q", data)[0]
        if target == 0:
            break
        if not (text_lo <= target < text_hi):
            break
        raw_mangle, method_name, is_thunk, func_type = _slot_info(bv, target)
        slots.append(VtableSlot(
            offset=cursor - vft_addr,
            target=target,
            raw_mangle=raw_mangle,
            method_name=method_name,
            is_thunk=is_thunk,
            func_type=func_type,
        ))
        cursor += 8

    if not slots:
        return None
    return VtableScan(
        vft_addr=vft_addr,
        class_name=info["class_name"],
        mi_for_base=info["mi_for_base"],
        slots=slots,
    )


def _slot_info(bv: BinaryView, target: int) -> Tuple[str, str, bool, object]:
    sym = bv.get_symbol_at(target)
    raw = (getattr(sym, "raw_name", None) or "") if sym else ""
    short = (getattr(sym, "short_name", None) or "") if sym else ""
    full = (getattr(sym, "full_name", None) or "") if sym else ""

    is_thunk = ("[thunk]" in raw) or ("[thunk]" in short) or short.startswith("[thunk]:")
    method_name = _extract_method_name(bv, raw, short, full)

    func_type = None
    func = bv.get_function_at(target)
    if func is not None:
        for attr in ("type", "function_type"):
            try:
                t = getattr(func, attr, None)
                if t is not None:
                    func_type = t
                    break
            except Exception as e:
                if _DEMANGLE_DEBUG_BUDGET[0] > 0:
                    log.log_debug(f"[MSVC C++] func.{attr} threw on {hex(target)}: {e}")
                    _DEMANGLE_DEBUG_BUDGET[0] -= 1
        if func_type is None and _DEMANGLE_DEBUG_BUDGET[0] > 0:
            attrs = [a for a in dir(func) if "type" in a.lower()]
            log.log_info(f"[MSVC C++] func at {hex(target)} no usable type; attrs={attrs}")
            _DEMANGLE_DEBUG_BUDGET[0] -= 1
    return raw, method_name, is_thunk, func_type


def _extract_method_name(bv: BinaryView, raw: str, short: str, full: str) -> str:
    for s in (short, full):
        m = _last_method_segment(s)
        if m and not m.startswith("?") and not m.startswith("??"):
            return m
    if raw:
        joined = _demangle_join(bv, raw)
        m = _last_method_segment(joined)
        if m:
            return m
    return raw or short or full or "<anon>"


def _last_method_segment(s: str) -> str:
    if not s:
        return ""
    if s.startswith("[thunk]:"):
        s = s[len("[thunk]:"):]
    s = s.split("(", 1)[0]
    parts = s.split("::")
    if not parts:
        return s
    return parts[-1]
