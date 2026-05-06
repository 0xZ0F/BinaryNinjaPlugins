from binaryninja import log

from .config import is_x86_64, PLUGIN_NAME
from .commands import register_all as _register_commands
from .workflow import register_all as _register_workflows


def _entry():
    try:
        _register_workflows()
    except Exception as e:
        log.log_error(f"[{PLUGIN_NAME}] workflow registration failed: {e}")
    try:
        _register_commands()
    except Exception as e:
        log.log_error(f"[{PLUGIN_NAME}] command registration failed: {e}")


_entry()
