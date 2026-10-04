"""
ZeroTrustZone (ZTZ) Core Package.
Offline-First Zero-Trust Cryptographic Pre-Flight Firewall.

Compatibility alias for `ztz`: every `zerotrustzone.<sub>` import resolves to the
very same module object as `ztz.<sub>` (same classes, same state, patches apply),
including submodules added to ztz later.
"""

import sys
import importlib
import importlib.abc
import importlib.util

_ALIAS = __name__
_TARGET = "ztz"


class _ZTZAliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        # __main__ stays a real file so `python -m zerotrustzone` works via runpy.
        if fullname.startswith(_ALIAS + ".") and fullname != _ALIAS + ".__main__":
            return importlib.util.spec_from_loader(fullname, self)
        return None

    def create_module(self, spec):
        return importlib.import_module(_TARGET + spec.name[len(_ALIAS):])

    def exec_module(self, module):
        pass  # already executed under its ztz.* name


if not any(isinstance(f, _ZTZAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _ZTZAliasFinder())


def __getattr__(name):
    # `zerotrustzone.core` etc. without an explicit submodule import.
    if not name.startswith("__"):
        try:
            return importlib.import_module(f"{_ALIAS}.{name}")
        except ModuleNotFoundError as e:
            if e.name != f"{_TARGET}.{name}":
                raise  # a genuine missing dependency inside ztz
    raise AttributeError(f"module {_ALIAS!r} has no attribute {name!r}")


from ztz.core import *
from ztz.cli import main

__all__ = ["main"]
