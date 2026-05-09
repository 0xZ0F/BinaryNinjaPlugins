"""Plugin command registration. All menus live under `MSVC C++\\...`."""

from binaryninja import PluginCommand

from ..config import MENU_ROOT, is_msvc_target
from . import full_analysis, nav, vtables, xfg


_REGISTERED = False


def _is_addr(bv, _addr) -> bool:
    return is_msvc_target(bv)


def _is_func(bv, _func) -> bool:
    return is_msvc_target(bv)


def register_all() -> None:
    global _REGISTERED
    if _REGISTERED:
        return
    _REGISTERED = True

    # ---- Run Full Analysis ----------------------------------------------
    PluginCommand.register(
        f"{MENU_ROOT}\\Run Full Analysis",
        "Auto-define vtable + class structs, re-type slot fields from function "
        "prototypes, and resolve all XFG indirect calls in one pass.",
        full_analysis.cmd_run_full_analysis,
        is_valid=is_msvc_target,
    )

    # ---- VTables --------------------------------------------------------
    PluginCommand.register(
        f"{MENU_ROOT}\\VTables\\Auto-Define for All Classes",
        "Create typed VTable structs from RTTI symbols and update class structs",
        vtables.cmd_process_all,
        is_valid=is_msvc_target,
    )
    PluginCommand.register_for_address(
        f"{MENU_ROOT}\\VTables\\Auto-Define for This Class",
        "Auto-define vtable structs for the class at this address",
        vtables.cmd_process_for_address,
        is_valid=_is_addr,
    )
    PluginCommand.register_for_function(
        f"{MENU_ROOT}\\VTables\\Auto-Define for This Class",
        "Auto-define vtable structs for the class this function belongs to",
        vtables.cmd_process_for_function,
        is_valid=_is_func,
    )
    PluginCommand.register(
        f"{MENU_ROOT}\\VTables\\Type All Fields from Functions",
        "Re-type all VTable struct fields as function pointers and propagate "
        "signatures to call sites",
        vtables.cmd_type_all_vtables,
        is_valid=is_msvc_target,
    )
    PluginCommand.register_for_address(
        f"{MENU_ROOT}\\VTables\\Navigate to Virtual Function",
        "Resolve the vtable dispatch at this address and navigate to the target function",
        nav.cmd_navigate_to_virtual,
        is_valid=_is_addr,
    )

    # ---- XFG: Cross-References -----------------------------------------
    PluginCommand.register_for_address(
        f"{MENU_ROOT}\\XFG\\Cross-References\\Find Here",
        "Add XFG xrefs for the function at this address to the cross-references panel",
        xfg.cmd_xref_for_address,
        is_valid=_is_addr,
    )
    PluginCommand.register_for_function(
        f"{MENU_ROOT}\\XFG\\Cross-References\\Find in This Function",
        "Add XFG xrefs for this function to the cross-references panel",
        xfg.cmd_xref_for_function,
        is_valid=_is_func,
    )
    PluginCommand.register(
        f"{MENU_ROOT}\\XFG\\Cross-References\\Add All",
        "Scan entire binary and add all resolvable XFG xrefs to the cross-references panel",
        xfg.cmd_xref_add_all,
        is_valid=is_msvc_target,
    )
    PluginCommand.register(
        f"{MENU_ROOT}\\XFG\\Cross-References\\Remove All",
        "Remove all XFG xrefs previously added by this plugin",
        xfg.cmd_xref_remove_all,
        is_valid=is_msvc_target,
    )

    # ---- XFG: Indirect Calls -------------------------------------------
    PluginCommand.register_for_address(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\Resolve Here",
        "Set indirect branch targets and 'XFG ->' comment on the XFG-guarded call at this address",
        xfg.cmd_resolve_here,
        is_valid=_is_addr,
    )
    PluginCommand.register_for_address(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\Remove Here",
        "Clear indirect branch targets and 'XFG ->' comment on the XFG-guarded call at this address",
        xfg.cmd_remove_here,
        is_valid=_is_addr,
    )
    PluginCommand.register_for_address(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\Go to Target Here",
        "Navigate to the target of the XFG-guarded call at this address (chooser on hash collision)",
        xfg.cmd_goto_xfg_target,
        is_valid=_is_addr,
    )
    PluginCommand.register_for_address(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\View Candidates Here",
        "List every function whose XFG hash matches the call at the cursor",
        xfg.cmd_view_candidates,
        is_valid=_is_addr,
    )
    PluginCommand.register_for_function(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\Resolve in This Function",
        "Set indirect branch targets and 'XFG ->' comments on every XFG call site in this function",
        xfg.cmd_resolve_in_func,
        is_valid=_is_func,
    )
    PluginCommand.register_for_function(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\Remove in This Function",
        "Clear indirect branch targets and 'XFG ->' comments on every XFG call site in this function",
        xfg.cmd_remove_in_func,
        is_valid=_is_func,
    )
    PluginCommand.register(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\Resolve All",
        "Scan entire binary and register indirect branch targets at XFG-guarded call sites",
        xfg.cmd_resolve_all,
        is_valid=is_msvc_target,
    )
    PluginCommand.register(
        f"{MENU_ROOT}\\XFG\\Indirect Calls\\Remove All",
        "Remove user-set indirect branch targets previously added at XFG call sites",
        xfg.cmd_remove_all,
        is_valid=is_msvc_target,
    )

    # ---- XFG: Reset cache ----------------------------------------------
    PluginCommand.register(
        f"{MENU_ROOT}\\XFG\\Reset Hash Map Cache",
        "Invalidate the cached XFG hash map (use after adding/removing functions mid-session)",
        xfg.cmd_reset_hash_map,
        is_valid=is_msvc_target,
    )
