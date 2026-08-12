"""Auto-discovery of suite modules.

Importing this package imports every suite module so its ``@assertion``
decorators fire against the default registry. Modules whose name starts with
``_`` are infrastructure (e.g. :mod:`bauble.suites._base`) and are skipped.
Subpackages are imported by their ``__init__``, which is responsible for
importing their own submodules.
"""

from __future__ import annotations

import importlib
import pkgutil

__all__ = ["discover"]


def discover() -> None:
    """Import all suite modules in this package tree."""
    for module_info in pkgutil.iter_modules(__path__):
        name = module_info.name
        if name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{name}")


discover()
