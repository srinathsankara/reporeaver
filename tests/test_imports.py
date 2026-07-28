"""Smoke test: ensure all top-level modules import without error."""

import importlib
import pkgutil
import reporeaver


def test_all_modules_import():
    """Verify every submodule can be imported."""
    for _importer, modname, _ispkg in pkgutil.walk_packages(
        reporeaver.__path__, prefix="reporeaver."
    ):
        if "__pycache__" not in modname:
            importlib.import_module(modname)
