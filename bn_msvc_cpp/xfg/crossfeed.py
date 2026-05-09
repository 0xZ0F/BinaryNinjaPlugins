"""XFG alias disambiguation via vtable dispatch.

When an XFG hash maps to many functions (every IUnknown::Release override
shares one prototype-hash), inspecting the vtable slot loaded into RAX before
the `movabs r10` typically narrows to the single concrete target. This is
the dominant XFG resolution path on RTTI-rich binaries.

Verbatim port from `xfg_xrefs.py`.
"""

from binaryninja import BinaryView
from binaryninja.enums import TypeClass

from ..types.classes import find_class_offsets, offset_cache
from ..types.vtables import find_vtable_symbols
from ..util import demangled_function_name, class_name_from_func
from .dispatch import get_vtable_dispatch_info
from .settings import get_alias_threshold, get_metadata_mode
from .sites import find_xfg_call


VTABLE_DISAMBIG_KEY = "bn_msvc_cpp:xfg_vtable_disambig_ctx"


def get_vtable_disambig_ctx(bv: BinaryView):
    """Return a context for vtable-based XFG target disambiguation, or None.

    Cached on bv.session_data. Returns None (cached as False) when the binary
    has no RTTI vtable symbols, in which case `_narrow_targets` falls back to
    the threshold cap.
    """
    cached = bv.session_data.get(VTABLE_DISAMBIG_KEY)
    if cached is not None:
        return cached if cached is not False else None
    try:
        vtable_map = find_vtable_symbols(bv)
    except Exception:
        bv.session_data[VTABLE_DISAMBIG_KEY] = False
        return None
    if not vtable_map:
        bv.session_data[VTABLE_DISAMBIG_KEY] = False
        return None
    ctx = {"vtable_map": vtable_map}
    bv.session_data[VTABLE_DISAMBIG_KEY] = ctx
    return ctx


def _class_from_pointed_type(target, vtable_map: dict):
    """Return the vtable_map key for the type a pointer targets, else None."""
    if target is None:
        return None
    try:
        if target.type_class == TypeClass.NamedTypeReferenceClass:
            name = str(target.name)
            return name if name in vtable_map else None
        if target.type_class == TypeClass.StructureTypeClass:
            reg = getattr(target, "registered_name", None)
            if reg:
                name = str(reg)
                return name if name in vtable_map else None
    except Exception:
        return None
    return None


def _calling_class_from_call_first_arg(
    bv: BinaryView, call_addr: int, vtable_map: dict
):
    """Tier-2 fallback: derive the class from the type of the call's first argument.

    On x86_64 fastcall the first argument is the dispatched object — for a
    virtual call `obj->Method(args...)`, MLIL renders it as `Method(obj, args)`
    with `obj` as params[0]. This handles the common case where the calling
    function itself is *not* a method of an RTTI class (free functions, helpers,
    WRL template glue) but the dispatched object IS typed as a registered
    struct.
    """
    funcs = bv.get_functions_containing(call_addr)
    if not funcs:
        return None
    func = funcs[0]
    try:
        mlil_insn = func.get_medium_level_il_at(call_addr)
    except Exception:
        return None
    if mlil_insn is None:
        return None

    params = None
    try:
        params = list(mlil_insn.params)
    except Exception:
        return None
    if not params:
        return None

    first = params[0]
    et = None
    try:
        et = first.expr_type
    except Exception:
        et = None
    if et is None:
        try:
            et = first.var.type
        except Exception:
            et = None
    if et is None:
        return None
    try:
        if et.type_class != TypeClass.PointerTypeClass:
            return None
    except Exception:
        return None
    return _class_from_pointed_type(et.target, vtable_map)


def _get_calling_class(bv: BinaryView, addr: int, vtable_map: dict):
    """Return the vtable_map key matching the class of the function containing addr."""
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        return None
    name = demangled_function_name(bv.arch, funcs[0].name)
    return class_name_from_func(name, vtable_map)


def try_vtable_disambig(
    bv: BinaryView, movabs_addr: int, targets: list, ctx
):
    """Resolve XFG aliases to a concrete single target via vtable dispatch.

    Returns [fp_addr] on success, or None if the call can't be narrowed (no
    vtable context, non-vtable dispatch shape, no class match, fp not in
    alias set, etc.).
    """
    if ctx is None:
        return None
    vtable_map = ctx["vtable_map"]

    call_addr = find_xfg_call(bv, movabs_addr)
    if call_addr is None:
        return None

    try:
        slot_offset, vtable_class_offset = get_vtable_dispatch_info(bv, call_addr)
    except Exception:
        return None
    if slot_offset is None:
        return None

    # Tier 1: function name -> class via RTTI prefix match.
    try:
        calling_class = _get_calling_class(bv, call_addr, vtable_map)
    except Exception:
        calling_class = None

    # Tier 2: type of the call's first MLIL argument (the dispatched object).
    if not calling_class or calling_class not in vtable_map:
        calling_class = _calling_class_from_call_first_arg(bv, call_addr, vtable_map)
    if not calling_class or calling_class not in vtable_map:
        return None

    class_addrs = [a for a, _ in vtable_map[calling_class]]
    try:
        cache = offset_cache(bv)
        missing = [a for a in class_addrs if a not in cache]
        if missing:
            for a, off in find_class_offsets(bv, missing).items():
                cache[a] = off
    except Exception:
        return None

    matching_vtable = None
    if vtable_class_offset is not None:
        for a in class_addrs:
            if cache.get(a) == vtable_class_offset:
                matching_vtable = a
                break
    elif len(class_addrs) == 1:
        matching_vtable = class_addrs[0]
    if matching_vtable is None:
        return None

    raw = bv.read(matching_vtable + slot_offset, 8)
    if not raw or len(raw) < 8:
        return None
    fp_addr = int.from_bytes(raw, "little")
    if fp_addr == 0 or fp_addr not in targets:
        return None
    return [fp_addr]


def narrow_targets(
    bv: BinaryView, movabs_addr: int, targets: list, ctx
):
    """Reduce alias-rich XFG target lists via vtable dispatch or threshold cap.

    Returns:
      * list[int] - targets to write metadata (xrefs / indirect branches) for
      * None      - alias-rich and undisambiguable; caller should write the
                    'XFG ->' comment but skip metadata to avoid BNDB bloat
    """
    if len(targets) <= 1:
        return list(targets)
    narrowed = try_vtable_disambig(bv, movabs_addr, targets, ctx)
    if narrowed is not None:
        return narrowed
    if len(targets) <= get_alias_threshold():
        return list(targets)
    return None


def final_targets_to_write(
    bv: BinaryView, movabs_addr: int, targets: list, ctx, mode: str | None = None
) -> tuple:
    """Apply alias threshold + metadata mode and return what should be written.

    Returns (targets_to_write, status):
      * status "ok"               - len>0, len(targets) <= 1 OR not a disambig case
      * status "ok-disambig"      - narrowed from many aliases to a single concrete
      * status "skip-mode-none"   - mode=none, write nothing
      * status "skip-alias"       - alias-rich and undisambiguable
      * status "skip-not-disambig"- mode=disambig_only and we couldn't narrow to 1
    """
    if mode is None:
        mode = get_metadata_mode()
    if mode == "none":
        return [], "skip-mode-none"

    narrowed = narrow_targets(bv, movabs_addr, targets, ctx)
    if narrowed is None:
        return [], "skip-alias"

    is_disambig = len(targets) > 1 and len(narrowed) == 1
    if mode == "disambig_only" and len(narrowed) > 1:
        return [], "skip-not-disambig"

    return narrowed, "ok-disambig" if is_disambig else "ok"
