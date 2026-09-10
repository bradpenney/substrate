"""Load jit-admin's pure functions under a name Python can import.

`jit-admin.py` has a hyphen, so it is not importable by name. This loads it by
path and hands back the MODULE OBJECT, so the golden generator calls the real
implementation and can patch its identity lookups in place. A shim that
reimplemented anything would pin nothing.
"""

import importlib.util
import pathlib


def load():
    spec = importlib.util.spec_from_file_location(
        "_jit_admin", pathlib.Path(__file__).resolve().parent / "jit-admin.py"
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
