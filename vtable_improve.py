"""
vtable_improve.py - Binary Ninja plugin: improve virtual call display

Fixes decompiler output like `(*(r12->__offset(0x0).q + 0x230))(r12, 0)` by
re-typing vtable struct fields from void* to proper named function pointers.

After running, calls display as `obj->vtable->MethodName(...)` and BN
propagates the new signatures to call sites automatically.

Usage: Plugins -> VTables -> "Type All Fields from Functions"
Scans all data variables whose struct type name contains "VTable", re-types
every slot, then triggers propagation to callers. No navigation required.

Install: copy to %APPDATA%\\Binary Ninja\\plugins\\
"""

from binaryninja import BinaryView, PluginCommand, log_info
from binaryninja.enums import TypeClass, FunctionUpdateType
from binaryninja.types import Type, StructureBuilder, StructureMember
from binaryninja.interaction import show_message_box
from binaryninja.plugin import BackgroundTaskThread


def _check_arch(bv: BinaryView, title: str) -> bool:
    """Bail with a clean message if bv is not x86_64."""
    if bv.arch is None or bv.arch.name != "x86_64":
        show_message_box(title, "This plugin requires an x86_64 binary.")
        return False
    return True


def _resolve_named_struct(bv: BinaryView, var_type):
    """Return (name_str, StructureType) for a data variable's type, or (None, None)."""
    t = var_type
    if t.type_class == TypeClass.PointerTypeClass:
        t = t.target
    if t.type_class == TypeClass.NamedTypeReferenceClass:
        name = str(t.name)
        t = bv.get_type_by_name(name)
        return (name, t) if t is not None else (None, None)
    if t.type_class == TypeClass.StructureTypeClass:
        reg = getattr(t, "registered_name", None)
        return (str(reg) if reg else None, t)
    return None, None


def _type_vtable_at(
    bv: BinaryView, vtable_addr: int, struct_name: str, struct_type
) -> tuple:
    """Re-type every void* field in struct_name to a typed function pointer.

    Reads each slot's actual function address from vtable_addr, resolves the
    function, and replaces the field type with a pointer to that function's type.
    Returns (stats dict, set of Function objects that were retyped).
    """
    members = list(struct_type.members)
    updated_members = []
    updated_funcs = set()
    stats = {"typed": 0, "no_func": 0, "unreadable": 0}

    for member in members:
        slot_raw = bv.read(vtable_addr + member.offset, 8)
        if not slot_raw or len(slot_raw) < 8:
            stats["unreadable"] += 1
            updated_members.append(member)
            continue

        fp_addr = int.from_bytes(slot_raw, "little")
        if fp_addr == 0:
            stats["no_func"] += 1
            updated_members.append(member)
            continue

        func = bv.get_function_at(fp_addr)
        if func is None:
            stats["no_func"] += 1
            updated_members.append(member)
            continue

        # Skip slots whose target has no derived prototype - pointering a void
        # type produces void* and silently leaves the slot un-typed.
        ft = func.type
        if ft is None or ft.type_class != TypeClass.FunctionTypeClass:
            stats["no_func"] += 1
            updated_members.append(member)
            continue

        if not ft.can_return:
            # Virtual overrides can return normally — don't let one noreturn
            # implementation (purecall stubs, throw-only overrides, ud2 traps)
            # poison every call through this slot.
            ft = Type.function(ft.return_value, list(ft.parameters), ft.calling_convention)

        fp_type = Type.pointer(bv.arch, ft)
        updated_members.append(StructureMember(fp_type, member.name, member.offset))
        updated_funcs.add(func)
        stats["typed"] += 1

    if stats["typed"] > 0:
        builder = StructureBuilder.create()
        builder.packed = True
        for m in updated_members:
            builder.add_member_at_offset(m.name, m.type, m.offset)
        bv.define_user_type(struct_name, builder)

    return stats, updated_funcs


def _do_type_all_vtables(bv: BinaryView, task: BackgroundTaskThread) -> None:
    """Background worker for Type All Vtable Fields from Functions."""
    task.progress = "VTables: enumerating typed vtable data variables..."
    processed = []
    seen_structs: set[str] = set()
    all_updated_funcs: set = set()

    bv.begin_undo_actions()

    items = list(bv.data_vars.items())
    for i, (vtable_addr, var) in enumerate(items):
        if task.cancelled:
            break
        struct_name, struct_type = _resolve_named_struct(bv, var.type)
        if struct_name is None or struct_type is None:
            continue
        if "VTable" not in struct_name:
            continue
        if struct_name in seen_structs:
            continue
        seen_structs.add(struct_name)

        if not list(struct_type.members):
            continue

        task.progress = f"VTables: typing {struct_name} ({len(processed) + 1} processed)"
        stats, funcs = _type_vtable_at(bv, vtable_addr, struct_name, struct_type)
        processed.append((struct_name, vtable_addr, stats))
        all_updated_funcs.update(funcs)
        log_info(
            f"vtable_improve: {struct_name} @ {vtable_addr:#x} - "
            f"{stats['typed']} typed, {stats['no_func']} no-func, {stats['unreadable']} unreadable"
        )

    task.progress = f"VTables: queueing re-analysis for {len(all_updated_funcs)} function(s)..."
    for func in all_updated_funcs:
        func.mark_caller_updates_required(FunctionUpdateType.UserFunctionUpdate)

    bv.commit_undo_actions()

    if all_updated_funcs:
        bv.update_analysis()
        log_info(
            f"vtable_improve: queued re-analysis for {len(all_updated_funcs)} function(s)"
        )

    if not processed:
        if seen_structs:
            msg = (
                f"Found {len(seen_structs)} VTable struct(s) but none had typeable "
                "members (empty struct definitions)."
            )
        else:
            msg = (
                "No data variables with a type name containing 'VTable' were found.\n\n"
                "Vtable structs must be named with 'VTable' in the name\n"
                "(e.g. IMsiEngineVTable) and applied to vtable data variables."
            )
        show_message_box("Type All Vtable Fields", msg)
        return

    total_typed = sum(s["typed"] for _, _, s in processed)
    show_message_box(
        "Type All Vtable Fields",
        f"Updated {len(processed)} vtable struct(s), {total_typed} total fields re-typed"
        f"{' (cancelled)' if task.cancelled else ''}.\n\n"
        "Propagation queued - BN is re-analysing affected call sites.",
    )


def _cmd_type_all_vtables(bv: BinaryView) -> None:
    """Re-type all VTable struct fields as function pointers and propagate signatures to call sites."""
    if not _check_arch(bv, "Type All Vtable Fields"):
        return

    class _Task(BackgroundTaskThread):
        def __init__(self) -> None:
            super().__init__("VTables: typing all fields from functions...", True)

        def run(self) -> None:
            try:
                _do_type_all_vtables(bv, self)
            finally:
                self.finish()

    _Task().start()


PluginCommand.register(
    "VTables\\Type All Fields from Functions",
    "Re-type all VTable struct fields as function pointers and propagate signatures to call sites",
    _cmd_type_all_vtables,
)
