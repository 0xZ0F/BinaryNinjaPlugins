from binaryninja import BackgroundTaskThread, PluginCommand, log

from ..config import MENU_ROOT, is_msvc_target
from ..rtti import walk_rtti
from ..types import build_class_types, discover_fields, enrich_vtables, propagate_this_types, scan_vtables
from ..xfg import apply_resolutions, build_hash_index, crossfeed_types, scan_xfg_sites

_REGISTERED = False


class _FullAnalysisTask(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__("MSVC C++: full analysis", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        try:
            self.progress = "MSVC C++: waiting for analysis"
            bv.update_analysis_and_wait()

            self.progress = "MSVC C++: reading RTTI metadata"
            rtti = walk_rtti(bv)
            log.log_info(f"[MSVC C++] RTTI metadata: {len(rtti)} classes")

            self.progress = "MSVC C++: scanning vftables"
            scans = scan_vtables(bv)
            log.log_info(f"[MSVC C++] vftable scans: {len(scans)}")

            by_class: dict[str, int] = {}
            total_slots = 0
            mi_count = 0
            for s in scans:
                by_class[s.class_name] = by_class.get(s.class_name, 0) + 1
                total_slots += len(s.slots)
                if s.mi_for_base is not None:
                    mi_count += 1
            log.log_info(
                f"[MSVC C++] vtable summary: {len(by_class)} unique classes, "
                f"{mi_count} MI-secondary, {total_slots} total slots"
            )

            for s in scans[:5]:
                mi = f" [for `{s.mi_for_base}']" if s.mi_for_base else ""
                slot_preview = ", ".join(slot.method_name for slot in s.slots[:5]) or "(empty)"
                log.log_info(
                    f"[MSVC C++]   {hex(s.vft_addr)} {s.class_name}{mi} "
                    f"slots={len(s.slots)} sample=[{slot_preview}]"
                )

            self.progress = "MSVC C++: enriching vtable structs"
            n_built = enrich_vtables(bv, scans)
            log.log_info(f"[MSVC C++] vtable structs built/updated: {n_built}")

            self.progress = "MSVC C++: building class structs"
            n_classes = build_class_types(bv, scans, rtti)
            log.log_info(f"[MSVC C++] class structs built/updated: {n_classes}")

            self.progress = "MSVC C++: propagating `this` types"
            n_propagated = propagate_this_types(bv, scans, rtti)
            log.log_info(f"[MSVC C++] this-typed functions: {n_propagated}")

            self.progress = "MSVC C++: discovering class fields"
            n_fields = discover_fields(bv, scans, rtti)
            log.log_info(f"[MSVC C++] class fields discovered: {n_fields}")

            self.progress = "MSVC C++: building XFG hash index"
            hash_index = build_hash_index(bv)

            self.progress = "MSVC C++: scanning XFG call sites"
            xfg_sites = scan_xfg_sites(bv, hash_index)
            log.log_info(f"[MSVC C++] XFG total sites: {len(xfg_sites)}")

            self.progress = "MSVC C++: cross-feeding vtable type info"
            crossfeed_types(bv, scans, xfg_sites, rtti)

            self.progress = "MSVC C++: applying XFG resolutions"
            n_xfg_applied = apply_resolutions(bv, xfg_sites)
            log.log_info(f"[MSVC C++] XFG total applied: {n_xfg_applied}")
        except Exception as e:
            log.log_error(f"[MSVC C++] full-analysis task failed: {e}")
            raise


def _run_full_analysis(bv) -> None:
    _FullAnalysisTask(bv).start()


def register_all() -> None:
    global _REGISTERED
    if _REGISTERED:
        return
    _REGISTERED = True

    PluginCommand.register(
        f"{MENU_ROOT}\\Run Full Analysis",
        "Walk RTTI metadata + vftable symbols; report class graph",
        _run_full_analysis,
        is_valid=is_msvc_target,
    )
