"""VTable auto-define + slot-typing user commands and their background workers.

The heart of the plugin: `_process_class` runs the full pipeline for one
class (vtable structs, class struct, interface struct, constructor + method
this-typing, caller var retyping), and `_do_process_all` iterates every
class plus runs the cross-class purecall-slot unification.

Verbatim port from `vtable_autodefine.py`.
"""

from binaryninja import BinaryView, Function, log_info, log_warn
from binaryninja.enums import FunctionUpdateType, TypeClass
from binaryninja.interaction import show_message_box
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.types import Type

from ..types.classes import (
    auto_populate_class_struct,
    find_class_offsets,
    offset_cache,
    update_class_struct,
    update_interface_struct,
)
from ..types.improve import do_type_all_vtables
from ..types.propagate import (
    retype_call_result_vars,
    update_constructor_this_types,
    update_vtable_method_this_types,
)
from ..types.vtables import (
    all_vtable_addrs,
    attach_orphan_col_vtables,
    compute_slot_counts,
    create_vtable_struct,
    find_vtable_symbols,
    invalidate_col_cache,
    is_adjustor_thunk_slot,
    slot_func_namespace,
    unify_purecall_slots,
    vtable_struct_name,
)
from ..util import (
    check_arch,
    class_name_from_func,
    demangled_function_name,
    strip_elaborated_type_keywords,
)


def _process_class(
    bv: BinaryView, class_name: str, entries: list, all_sorted_addrs: list
) -> tuple:
    """Run the full vtable pipeline for one class.

    Returns (n_structs_created, set_of_updated_funcs, summary_str, created_list).
    """
    cache = offset_cache(bv)
    for addr, _ in entries:
        cache.pop(addr, None)

    sized = compute_slot_counts(bv, entries, all_sorted_addrs)

    all_funcs: set = set()
    created: list = []

    # Capture pre-existing data var type names BEFORE we stamp new types.
    # BN's RTTI or PDB analysis may have created types with a canonical name
    # that differs from what we'd derive from the RTTI symbol text (e.g.,
    # different template-argument order in WRL helper classes). Using BN's
    # canonical name ensures class struct fields reference a resolvable type.
    pre_existing_names: dict[int, str] = {}
    for vtable_addr, _iface_name, _n_slots in sized:
        dv = bv.get_data_var_at(vtable_addr)
        if dv is not None:
            t = dv.type
            if t.type_class == TypeClass.PointerTypeClass:
                t = t.target
            if t.type_class == TypeClass.NamedTypeReferenceClass:
                name = strip_elaborated_type_keywords(str(t.name))
                if "VTable" in name:
                    pre_existing_names[vtable_addr] = name
            elif t.type_class == TypeClass.StructureTypeClass:
                reg = getattr(t, "registered_name", None)
                if reg:
                    name = strip_elaborated_type_keywords(str(reg))
                    if "VTable" in name:
                        pre_existing_names[vtable_addr] = name

    for vtable_addr, iface_name, n_slots in sized:
        if n_slots == 0:
            log_warn(
                f"bn_msvc_cpp: {class_name}/{iface_name} @ {vtable_addr:#x} - 0 slots, skipping"
            )
            continue
        # Secondary (adjustor-thunk) vtables: rename the inferred iface so the
        # struct ends up named after the actual base interface. pre_existing_names
        # wins because BN's PDB or a prior run may have already settled on a
        # canonical name.
        if (
            vtable_addr not in pre_existing_names
            and n_slots > 3
            and is_adjustor_thunk_slot(bv, vtable_addr)
        ):
            secondary_iface = slot_func_namespace(bv, vtable_addr, 3)
            if secondary_iface and secondary_iface != iface_name:
                log_info(
                    f"bn_msvc_cpp: secondary vtable @ {vtable_addr:#x} "
                    f"({class_name}) renamed iface {iface_name!r} -> {secondary_iface!r}"
                )
                iface_name = secondary_iface
        struct_name = pre_existing_names.get(vtable_addr) or vtable_struct_name(iface_name)
        funcs = create_vtable_struct(bv, vtable_addr, struct_name, n_slots)
        all_funcs.update(funcs)
        created.append((vtable_addr, iface_name, struct_name, n_slots))

    if not created:
        return 0, set(), f"{class_name}: no valid vtables found", []

    vtable_addrs_only = [addr for addr, _, _, _ in created]
    offset_map = find_class_offsets(bv, vtable_addrs_only)

    vtable_info = []
    for addr, iface_name, struct_name, _n_slots in created:
        class_offset = offset_map.get(addr)
        if class_offset is None:
            log_warn(
                f"bn_msvc_cpp: {class_name}/{iface_name} @ {addr:#x} - "
                "couldn't determine class offset; vtable struct defined but class struct not updated"
            )
            continue
        vtable_info.append((addr, iface_name, struct_name, class_offset))

    if vtable_info:
        update_class_struct(bv, class_name, vtable_info)
        for _addr, iface_name, struct_name, _class_off in vtable_info:
            update_interface_struct(bv, iface_name, struct_name)
        ctor_funcs = update_constructor_this_types(bv, class_name, vtable_info)
        all_funcs.update(ctor_funcs)
        # Walk every caller's HLIL and explicitly retype the variable that
        # captures the constructor's return value. Setting the prototype alone
        # is not enough: BN updates the variable's display annotation but
        # does NOT re-lift the caller's HLIL expression tree.
        ptr_to_class = (
            Type.pointer(bv.arch, Type.named_type_from_registered_type(bv, class_name))
            if bv.get_type_by_name(class_name) is not None
            else None
        )
        for ctor in ctor_funcs:
            for ref in bv.get_code_refs(ctor.start):
                caller = ref.function
                if caller is None:
                    continue
                all_funcs.add(caller)
                if ptr_to_class is not None:
                    retype_call_result_vars(caller, ctor.start, ptr_to_class)
        method_funcs = update_vtable_method_this_types(bv, class_name, vtable_info)
        all_funcs.update(method_funcs)

        # Ensure mark_caller_updates_required cascades to every factory/call site
        # that constructs this class, including WRL template base constructors
        # whose demangled name does NOT start with class_name + "::" and were
        # therefore skipped by update_constructor_this_types.
        for vtable_addr, _iface, _sname, class_offset in vtable_info:
            if class_offset != 0:
                continue
            for ref in bv.get_code_refs(vtable_addr):
                if ref.function is not None:
                    all_funcs.add(ref.function)

    slot_counts = ", ".join(f"{iface}={n}" for _, iface, _, n in created)
    return (
        len(created),
        all_funcs,
        f"{class_name}: {len(created)} vtable(s) [{slot_counts}]",
        created,
    )


# ---- Auto-Define for All Classes ----------------------------------------

def _do_process_all(bv: BinaryView, task: BackgroundTaskThread) -> None:
    task.progress = "VTables: scanning for RTTI vtable symbols..."
    vtable_map = find_vtable_symbols(bv)
    if not vtable_map:
        show_message_box(
            "Auto-Define Vtable Structs",
            "No RTTI vtable symbols found.\n\n"
            "Binary Ninja must have already run its RTTI analysis and produced\n"
            "symbols in the format: ClassName::`vftable'{for `IInterface'}",
        )
        return

    attached = attach_orphan_col_vtables(bv, vtable_map)
    if attached:
        log_info(
            f"bn_msvc_cpp: attached {attached} unsymbolized COL-derived "
            f"vtable(s) to nearest known class"
        )
    all_sorted = all_vtable_addrs(vtable_map, bv)

    bv.begin_undo_actions()
    all_funcs: set = set()
    all_created: list = []
    summaries = []
    total_structs = 0
    total_classes = len(vtable_map)

    for i, (class_name, entries) in enumerate(sorted(vtable_map.items()), 1):
        if task.cancelled:
            break
        task.progress = f"VTables: processing {i}/{total_classes} - {class_name}"
        n, funcs, msg, created = _process_class(bv, class_name, entries, all_sorted)
        total_structs += n
        all_funcs.update(funcs)
        all_created.extend(created)
        summaries.append(msg)
        log_info(f"bn_msvc_cpp: {msg}")

    # Cross-class post-pass: mirror descriptive slot names onto vtables that
    # have `_purecall` placeholders, when an IUnknown-trio-matching sibling
    # vtable provides a better name.
    task.progress = "VTables: unifying _purecall slot names..."
    unified = unify_purecall_slots(bv, all_created)
    if unified:
        log_info(
            f"bn_msvc_cpp: unified placeholder slot names in {unified} struct(s)"
        )

    task.progress = f"VTables: queueing re-analysis for {len(all_funcs)} function(s)..."
    for func in all_funcs:
        func.mark_caller_updates_required(FunctionUpdateType.UserFunctionUpdate)

    bv.commit_undo_actions()

    populated = 0
    if all_funcs and not task.cancelled:
        # Block until the retypes above have re-lifted HLIL, otherwise
        # create_structure_from_offset_access sees no observed accesses through
        # the new typed `this` pointer and returns an empty struct.
        task.progress = "VTables: waiting for analysis to settle..."
        bv.update_analysis_and_wait()
        log_info(
            f"bn_msvc_cpp: queued re-analysis for {len(all_funcs)} function(s)"
        )

        # Programmatic equivalent of the user pressing 'S' on every class.
        bv.begin_undo_actions()
        for i, class_name in enumerate(sorted(vtable_map.keys()), 1):
            if task.cancelled:
                break
            task.progress = f"VTables: auto-populating {i}/{total_classes} - {class_name}"
            if auto_populate_class_struct(bv, class_name):
                populated += 1
        bv.commit_undo_actions()
        if populated:
            bv.update_analysis_and_wait()

    show_message_box(
        "Auto-Define Vtable Structs",
        f"Processed {total_classes} class(es), {total_structs} vtable struct(s), "
        f"auto-populated {populated} class struct(s)"
        f"{' (cancelled)' if task.cancelled else ''}.\n\n"
        "Check HLIL for promoted vtable field accesses.",
    )


def cmd_process_all(bv: BinaryView) -> None:
    if not check_arch(bv, "Auto-Define Vtable Structs"):
        return
    invalidate_col_cache(bv)

    class _Task(BackgroundTaskThread):
        def __init__(self) -> None:
            super().__init__("VTables: auto-defining structs for all classes...", True)

        def run(self) -> None:
            try:
                _do_process_all(bv, self)
            finally:
                self.finish()

    _Task().start()


# ---- Auto-Define for This Class ----------------------------------------

def _do_process_for_address(bv: BinaryView, addr: int, task: BackgroundTaskThread) -> None:
    task.progress = "VTables: scanning for RTTI vtable symbols..."
    vtable_map = find_vtable_symbols(bv)
    attach_orphan_col_vtables(bv, vtable_map)
    all_sorted = all_vtable_addrs(vtable_map, bv)

    class_name = None
    funcs = bv.get_functions_containing(addr)
    if funcs:
        fname = demangled_function_name(bv.arch, funcs[0].name)
        class_name = class_name_from_func(fname, vtable_map)

    if not (class_name and class_name in vtable_map):
        names = ", ".join(sorted(vtable_map.keys())[:10])
        show_message_box(
            "Auto-Define Vtable Structs",
            f"Could not determine class from address {addr:#x}.\n\n"
            f"Classes with vtable symbols: {names}{'...' if len(vtable_map) > 10 else ''}\n\n"
            "Use VTables -> Auto-Define for All Classes from the Plugins menu.",
        )
        return

    task.progress = f"VTables: processing {class_name}"
    bv.begin_undo_actions()
    n, funcs_set, msg, created = _process_class(
        bv, class_name, vtable_map[class_name], all_sorted
    )
    # Per-class unification still helps when a single class has both an
    # abstract base vtable and a concrete derived vtable that share an
    # IUnknown trio (typical for WRL RuntimeClass + nested implementing
    # delegates).
    unified = unify_purecall_slots(bv, created)
    if unified:
        log_info(
            f"bn_msvc_cpp: unified placeholder slot names in {unified} struct(s)"
        )
    for func in funcs_set:
        func.mark_caller_updates_required(FunctionUpdateType.UserFunctionUpdate)
    bv.commit_undo_actions()

    populated = False
    if funcs_set and not task.cancelled:
        task.progress = "VTables: waiting for analysis to settle..."
        bv.update_analysis_and_wait()
        task.progress = f"VTables: auto-populating {class_name}"
        bv.begin_undo_actions()
        populated = auto_populate_class_struct(bv, class_name)
        bv.commit_undo_actions()
        if populated:
            bv.update_analysis()

    suffix = " (auto-populated class struct)" if populated else ""
    show_message_box("Auto-Define Vtable Structs", msg + suffix)


def cmd_process_for_address(bv: BinaryView, addr: int) -> None:
    if not check_arch(bv, "Auto-Define Vtable Structs"):
        return
    invalidate_col_cache(bv)

    class _Task(BackgroundTaskThread):
        def __init__(self) -> None:
            super().__init__("VTables: auto-defining structs for class...", True)

        def run(self) -> None:
            try:
                _do_process_for_address(bv, addr, self)
            finally:
                self.finish()

    _Task().start()


def cmd_process_for_function(bv: BinaryView, func: Function) -> None:
    cmd_process_for_address(bv, func.start)


# ---- Type All Fields from Functions ------------------------------------

def cmd_type_all_vtables(bv: BinaryView) -> None:
    """Re-type all VTable struct fields as function pointers and propagate
    signatures to call sites (port of `vtable_improve.py`).
    """
    if not check_arch(bv, "Type All Vtable Fields"):
        return

    class _Task(BackgroundTaskThread):
        def __init__(self) -> None:
            super().__init__("VTables: typing all fields from functions...", True)

        def run(self) -> None:
            try:
                do_type_all_vtables(bv, self)
            finally:
                self.finish()

    _Task().start()
