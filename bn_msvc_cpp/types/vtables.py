"""VTable struct discovery + creation.

Walks RTTI vftable symbols (and orphan COL-derived addresses), computes slot
counts, and stamps `Class::VTable` structs onto the data variables. Also
mirrors descriptive slot names across sibling vtables that share an IUnknown
trio (`unify_purecall_slots`).

Verbatim port of the relevant logic from `vtable_autodefine.py`.
"""

import re

from binaryninja import BinaryView, demangle_ms, log_info
from binaryninja.enums import SectionSemantics, TypeClass
from binaryninja.types import StructureBuilder, Type

from ..util import strip_elaborated_type_keywords


# Matches: "CMsiEngine::`vftable'" and "CMsiEngine::`vftable'{for `IMsiEngine'}".
# The optional trailing "::~`vftable'" handles a BN demangler quirk that
# appears on `??_7` symbols for nested classes — BN renders them as
# "Outer::Inner::`vftable'::~`vftable'" (treating the symbol as destructor-
# like). Without this, the FTMEventDelegate inside a WaitForCompletion<>
# template falls through the regex and its address never enters
# `all_sorted_addrs`, so the previous vtable overshoots into it and produces
# a merged fat struct.
_VTABLE_RE = re.compile(
    r"^(.+?)::`vftable'(?:\{for `(.+?)'\})?(?:::~`vftable')?$"
)

_MAX_SLOTS = 512

# Maximum distance (in bytes) within which an orphan COL-derived vtable is
# attached to the nearest symbolized vtable's class. Sibling vtables of a
# single class are laid out contiguously in .rdata, so a relatively small
# window keeps the heuristic from cross-attaching vtables of unrelated classes
# while still tolerating very large vtables (~500 slots).
_ORPHAN_VTABLE_RADIUS = 0x1000

# Cache key for `rtti_col_vtable_addrs`'s output. The COL scan iterates
# `bv.data_vars` (potentially hundreds of thousands of entries on large
# binaries), so caching the result for the duration of a plugin command
# avoids paying the cost twice per "all classes" run. Invalidated by
# `invalidate_col_cache` at the start of each top-level command.
_COL_VTABLE_CACHE_KEY = "bn_msvc_cpp:col_vtable_addrs"


def invalidate_col_cache(bv: BinaryView) -> None:
    bv.session_data.pop(_COL_VTABLE_CACHE_KEY, None)


def find_vtable_symbols(bv: BinaryView) -> dict:
    """Return {class_name: [(addr, iface_name), ...]} sorted by address.

    Both `class_name` and `iface_name` are canonicalized through
    `strip_elaborated_type_keywords` here so every downstream consumer sees
    the same form.
    """
    result: dict[str, list] = {}
    for sym in bv.get_symbols():
        m = _VTABLE_RE.match(sym.name)
        if m is None:
            continue
        class_name = strip_elaborated_type_keywords(m.group(1))
        iface_name = strip_elaborated_type_keywords(m.group(2) or class_name)
        result.setdefault(class_name, []).append((sym.address, iface_name))
    for entries in result.values():
        entries.sort(key=lambda x: x[0])
    return result


def rtti_col_vtable_addrs(bv: BinaryView) -> set:
    """Return vtable start addresses inferred from RTTI Complete Object Locator
    data variables.

    In MSVC RTTI, every vtable is preceded by an 8-byte slot whose value is the
    address of the class's `_RTTICompleteObjectLocator` (image-relative on x64).
    The vtable body starts at that slot + 8. BN's RTTI analysis labels each
    COL data variable with a type whose name contains 'RTTICompleteObjectLocator',
    so we can enumerate them and walk back via data references to locate every
    vtable in the binary, including those for which BN never synthesized a
    `'vftable'` symbol.
    """
    cached = bv.session_data.get(_COL_VTABLE_CACHE_KEY)
    if cached is not None:
        return cached
    out: set = set()
    for col_addr, var in bv.data_vars.items():
        t = var.type
        tname = ""
        if t.type_class == TypeClass.NamedTypeReferenceClass:
            tname = str(t.name)
        elif t.type_class == TypeClass.StructureTypeClass:
            reg = getattr(t, "registered_name", None)
            tname = str(reg) if reg else ""
        if "RTTICompleteObjectLocator" not in tname:
            continue
        for ref in bv.get_data_refs(col_addr):
            out.add(ref + 8)
    bv.session_data[_COL_VTABLE_CACHE_KEY] = out
    return out


def attach_orphan_col_vtables(bv: BinaryView, vtable_map: dict) -> int:
    """Attach COL-derived vtable addresses with no `'vftable'` symbol to the
    nearest known class in vtable_map.

    Boundary detection alone (see `all_vtable_addrs`) is enough to stop the
    slot scanner from merging adjacent vtables, but produces no struct type
    for the unlabeled vtable. This walks each orphan COL-derived address and
    appends it to the nearest known class's entries (within
    `_ORPHAN_VTABLE_RADIUS`).

    Returns the number of orphan vtables attached.
    """
    col_addrs = rtti_col_vtable_addrs(bv)
    if not col_addrs:
        return 0
    known: dict[int, str] = {}
    for class_name, entries in vtable_map.items():
        for addr, _ in entries:
            known[addr] = class_name
    if not known:
        return 0
    sorted_known = sorted(known.keys())

    attached = 0
    for addr in sorted(col_addrs):
        if addr in known:
            continue
        nearest_class = None
        best_dist: int | None = None
        for k in sorted_known:
            d = abs(k - addr)
            if best_dist is None or d < best_dist:
                best_dist = d
                nearest_class = known[k]
            if k > addr and best_dist is not None and (k - addr) >= best_dist:
                break
        if nearest_class is None or best_dist is None or best_dist > _ORPHAN_VTABLE_RADIUS:
            continue
        vtable_map[nearest_class].append((addr, nearest_class))
        attached += 1

    for entries in vtable_map.values():
        entries.sort(key=lambda x: x[0])
    return attached


def all_vtable_addrs(vtable_map: dict, bv: BinaryView) -> list:
    """Return all vtable start addresses sorted ascending."""
    addrs = set()
    for entries in vtable_map.values():
        for addr, _ in entries:
            addrs.add(addr)
    addrs.update(rtti_col_vtable_addrs(bv))
    return sorted(addrs)


def is_code_pointer(bv: BinaryView, fp: int) -> bool:
    """Return True if fp is a vtable-eligible code pointer.

    Excludes external-section stubs (.extern / IAT thunks): they sit directly
    after vtables in .rdata and cause the slot scan to overshoot.
    """
    if fp == 0:
        return False
    seg = bv.get_segment_at(fp)
    if seg is None or not seg.executable:
        return False
    if any(s.semantics == SectionSemantics.ExternalSectionSemantics
           for s in bv.get_sections_at(fp)):
        return False
    return True


def scan_vtable_slots(bv: BinaryView, start: int, limit: int) -> int:
    """Count consecutive code pointers starting at start, stopping at limit."""
    count = 0
    addr = start
    while addr < limit:
        raw = bv.read(addr, 8)
        if not raw or len(raw) < 8:
            break
        fp = int.from_bytes(raw, "little")
        if not is_code_pointer(bv, fp):
            break
        count += 1
        addr += 8
    return count


def compute_slot_counts(bv: BinaryView, entries: list, all_sorted_addrs: list) -> list:
    """Return [(addr, iface_name, n_slots), ...] using the next vtable address as an upper bound."""
    result = []
    for addr, iface_name in entries:
        next_addr = None
        for a in all_sorted_addrs:
            if a > addr:
                next_addr = a
                break
        limit = next_addr if next_addr is not None else addr + 8 * _MAX_SLOTS
        n_slots = scan_vtable_slots(bv, addr, limit)
        result.append((addr, iface_name, n_slots))
    return result


def is_adjustor_thunk_slot(bv: BinaryView, vtable_addr: int, slot_idx: int = 0) -> bool:
    """Return True if vtable[slot_idx] points to an adjustor thunk.

    Adjustor thunks have BN-demangled symbol names starting with `[thunk]:`
    and containing `adjustor`. A vtable whose first slot is an adjustor thunk
    is the secondary vtable for a base subobject.
    """
    raw = bv.read(vtable_addr + slot_idx * 8, 8)
    if not raw or len(raw) < 8:
        return False
    fp = int.from_bytes(raw, "little")
    if fp == 0:
        return False
    sym = bv.get_symbol_at(fp)
    if sym is None:
        return False
    name = f"{sym.full_name or ''} {sym.short_name or ''}"
    return "adjustor" in name.lower()


def slot_func_namespace(bv: BinaryView, vtable_addr: int, slot_idx: int):
    """Return the qualified class namespace of the function at vtable[slot_idx], or None.

    Used to recover the real interface name for a secondary vtable: its
    IUnknown trio is implementation-class-qualified (via adjustor thunks),
    but slots 3+ are interface methods qualified by the interface itself.
    """
    raw = bv.read(vtable_addr + slot_idx * 8, 8)
    if not raw or len(raw) < 8:
        return None
    fp = int.from_bytes(raw, "little")
    if fp == 0:
        return None
    func = bv.get_function_at(fp)
    if func is None:
        return None
    fname = func.name
    if fname.startswith("?"):
        try:
            _, parts = demangle_ms(bv.arch, fname)
            if isinstance(parts, list):
                fname = "::".join(parts)
            elif isinstance(parts, str):
                fname = parts
        except Exception:
            pass
    if fname.startswith("[thunk]:"):
        fname = fname[len("[thunk]:"):]
    fname = re.sub(r"`adjustor\{\d+\}'$", "", fname).rstrip(":")
    if "::" not in fname:
        return None
    return strip_elaborated_type_keywords("::".join(fname.split("::")[:-1]))


def slot_field_name(bv: BinaryView, func, slot_index: int) -> str:
    """Return a clean field name derived from the function's demangled last name component.

    Falls back to slot_<index> if the name can't be reduced to a valid identifier.
    """
    raw = func.name

    if raw.startswith("?"):
        try:
            _, name_parts = demangle_ms(bv.arch, raw)
            if name_parts:
                if isinstance(name_parts, str):
                    name_parts = name_parts.split("::")
                raw = name_parts[-1] if name_parts else raw
        except Exception:
            pass

    if "::" in raw:
        raw = raw.split("::")[-1]

    base = re.sub(r"[^a-zA-Z0-9_]", "_", raw).strip("_")
    if not base or base[0].isdigit():
        base = f"slot_{slot_index}"
    return base


def is_generic_field_name(name: str) -> bool:
    """Return True if `name` is a placeholder we should overwrite with a
    descriptive sibling name during unification.

    Matches `_purecall` / `o__purecall` and `slot_N`. Real method names like
    `Invoke` are left alone.
    """
    if not name:
        return True
    if "purecall" in name.lower():
        return True
    if re.fullmatch(r"slot_\d+", name):
        return True
    return False


def vtable_struct_name(iface_name: str) -> str:
    """Return a namespaced struct name like 'IMsiEngine::VTable'."""
    return f"{strip_elaborated_type_keywords(iface_name)}::VTable"


def create_vtable_struct(
    bv: BinaryView, vtable_addr: int, struct_name: str, n_slots: int
) -> set:
    """Define a packed struct with n_slots typed function pointer fields and stamp it onto the vtable data variable.

    Returns the set of Function objects whose signatures were used as field types
    so the caller can queue them for re-analysis.
    """
    builder = StructureBuilder.create()
    builder.packed = True
    updated_funcs: set = set()
    used_names: dict[str, int] = {}

    for i in range(n_slots):
        offset = i * 8
        raw = bv.read(vtable_addr + offset, 8)
        fp_addr = int.from_bytes(raw, "little") if raw and len(raw) == 8 else 0
        func = bv.get_function_at(fp_addr) if fp_addr else None

        ft = func.type if func is not None else None
        if func is not None and ft is not None and ft.type_class == TypeClass.FunctionTypeClass:
            base = slot_field_name(bv, func, i)
            if base in used_names:
                used_names[base] += 1
                field_name = f"{base}_{used_names[base]}"
            else:
                used_names[base] = 0
                field_name = base
            if not ft.can_return:
                ft = Type.function(ft.return_value, list(ft.parameters), ft.calling_convention)
            field_type = Type.pointer(bv.arch, ft)
            updated_funcs.add(func)
        else:
            field_name = f"slot_{i}"
            field_type = Type.pointer(bv.arch, Type.void())

        builder.add_member_at_offset(field_name, field_type, offset)

    bv.define_user_type(struct_name, builder)

    # Stamp the data variable with a NamedTypeReference rather than the inline
    # StructureType so that BN's xref propagation and "Create All Members for
    # Structure" command (which key off NamedTypeReferenceType) keep working.
    if bv.get_type_by_name(struct_name) is not None:
        nt = Type.named_type_from_registered_type(bv, struct_name)
        bv.define_user_data_var(vtable_addr, nt)

    log_info(
        f"bn_msvc_cpp: defined {struct_name} ({n_slots} slots) @ {vtable_addr:#x}"
    )
    return updated_funcs


def unify_purecall_slots(bv: BinaryView, all_vtable_info: list) -> int:
    """Mirror descriptive slot names across vtables that share the same
    IUnknown trio (slot 0/1/2 function pointers).

    Two vtables with identical QI/AddRef/Release function pointers are sibling
    vtables for the same most-derived class. When one is the abstract base's
    primary vtable (filled with `_purecall` placeholders) and another is a
    concrete derived class's vtable (with real implementations), this pass
    copies the descriptive slot names from the concrete vtable to the abstract
    one.

    `all_vtable_info` is the aggregate of `(vtable_addr, iface_name,
    struct_name, n_slots)` tuples. Returns the number of structs whose field
    names were updated.
    """
    if not all_vtable_info:
        return 0

    # Group vtables by IUnknown trio + slot count. Slot count is added to the
    # key to defend against MSVC `/OPT:ICF` collapsing byte-identical
    # QI/AddRef/Release bodies across unrelated classes.
    groups: dict[tuple, list] = {}
    for vtable_addr, _iface_name, struct_name, n_slots in all_vtable_info:
        if n_slots < 3:
            continue
        trio = []
        ok = True
        for i in range(3):
            raw = bv.read(vtable_addr + i * 8, 8)
            if not raw or len(raw) < 8:
                ok = False
                break
            trio.append(int.from_bytes(raw, "little"))
        if not ok:
            continue
        groups.setdefault((tuple(trio), n_slots), []).append(
            (vtable_addr, struct_name, n_slots)
        )

    updated = 0
    for _key, members in groups.items():
        if len(members) < 2:
            continue
        max_slots = max(n for _, _, n in members)
        slot_best: dict[int, str] = {}
        for slot_idx in range(max_slots):
            for vtable_addr, _struct_name, n_slots in members:
                if slot_idx >= n_slots:
                    continue
                raw = bv.read(vtable_addr + slot_idx * 8, 8)
                if not raw or len(raw) < 8:
                    continue
                fp = int.from_bytes(raw, "little")
                func = bv.get_function_at(fp) if fp else None
                if func is None:
                    continue
                name = slot_field_name(bv, func, slot_idx)
                if is_generic_field_name(name):
                    continue
                slot_best[slot_idx] = name
                break
        if not slot_best:
            continue

        for _vtable_addr, struct_name, _n_slots in members:
            t = bv.get_type_by_name(struct_name)
            if t is None:
                continue
            if t.type_class == TypeClass.NamedTypeReferenceClass:
                t = bv.get_type_by_name(str(t.name))
                if t is None:
                    continue
            if t.type_class != TypeClass.StructureTypeClass:
                continue
            builder = StructureBuilder.create()
            builder.packed = getattr(t, "packed", True)
            changed = False
            for m in t.members:
                slot_idx = m.offset // 8
                desired = slot_best.get(slot_idx)
                if desired is not None and is_generic_field_name(m.name) and desired != m.name:
                    builder.add_member_at_offset(desired, m.type, m.offset)
                    changed = True
                else:
                    builder.add_member_at_offset(m.name, m.type, m.offset)
            if changed:
                bv.define_user_type(struct_name, builder)
                updated += 1
                log_info(
                    f"bn_msvc_cpp: unified placeholder slot names in {struct_name}"
                )
    return updated


def find_vtable_data_vars(bv: BinaryView) -> dict:
    """Return {vtable_addr: struct_name} for all data variables typed as `*::VTable` structs."""
    result = {}
    for addr, var in bv.data_vars.items():
        t = var.type
        name = None
        if t.type_class == TypeClass.NamedTypeReferenceClass:
            name = str(t.name)
        elif t.type_class == TypeClass.StructureTypeClass:
            reg = getattr(t, "registered_name", None)
            name = str(reg) if reg else None
        if name and "VTable" in name:
            result[addr] = name
    return result
