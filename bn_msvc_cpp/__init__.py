"""bn_msvc_cpp — Binary Ninja plugin for MSVC x86_64 C++ analysis.

Verbatim port of three legacy plugins (vtable_autodefine.py, vtable_improve.py,
xfg_xrefs.py) reorganized into a single library-style package.

Behavioral divergences from the legacy plugins:

* All commands live under the `MSVC C++` menu root (legacy `VTables` and `XFG`
  trees are now `MSVC C++ \\ VTables \\ ...` and `MSVC C++ \\ XFG \\ ...`).
* New `Run Full Analysis` command chains auto-define -> slot-typing -> XFG
  resolve in a single background task.
* New compact XFG comment format (see `xfg.comment.format_comment`).
* New `View Candidates Here` XFG command lists every hash-matching function
  in a plain-text report.
"""

from binaryninja import log_error

from .commands import register_all
from .config import PLUGIN_NAME


try:
    register_all()
except Exception as e:
    log_error(f"[{PLUGIN_NAME}] plugin command registration failed: {e}")
