from binaryninja import log

_REGISTERED = False


def register_all() -> None:
    global _REGISTERED
    if _REGISTERED:
        return
    _REGISTERED = True
    log.log_debug("[MSVC C++] workflow activity registration deferred (skeleton)")
