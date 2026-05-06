from binaryninja import BinaryView

PLUGIN_NAME = "MSVC C++"
MENU_ROOT = "MSVC C++"


def is_x86_64(bv: BinaryView) -> bool:
    return bool(bv and bv.arch and bv.arch.name == "x86_64")


def is_pe(bv: BinaryView) -> bool:
    return bool(bv and bv.view_type in ("PE", "COFF"))


def is_msvc_target(bv: BinaryView) -> bool:
    return is_x86_64(bv) and is_pe(bv)
