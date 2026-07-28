"""Tests for utils/known.py — verifies constants are importable and non-empty."""

from reporeaver.utils.known import (
    ARCHIVE_EXTS,
    CONFIG_EXTS,
    DOC_EXTS,
    IMAGE_EXTS,
    LOCKFILE_NAMES,
    SCRIPT_EXTS,
)


class TestKnown:
    def test_all_sets_non_empty(self):
        for name, s in [("IMAGE_EXTS", IMAGE_EXTS), ("DOC_EXTS", DOC_EXTS),
                         ("ARCHIVE_EXTS", ARCHIVE_EXTS), ("SCRIPT_EXTS", SCRIPT_EXTS),
                         ("CONFIG_EXTS", CONFIG_EXTS), ("LOCKFILE_NAMES", LOCKFILE_NAMES)]:
            assert len(s) > 0, f"{name} is empty"

    def test_archive_extensions_include_common(self):
        assert ".zip" in ARCHIVE_EXTS
        assert ".tar" in ARCHIVE_EXTS
        assert ".gz" in ARCHIVE_EXTS

    def test_script_extensions_include_py(self):
        assert ".py" in SCRIPT_EXTS
        assert ".js" in SCRIPT_EXTS
        assert ".sh" in SCRIPT_EXTS

    def test_config_extensions_include_yaml(self):
        assert ".yaml" in CONFIG_EXTS
        assert ".json" in CONFIG_EXTS
        assert ".toml" in CONFIG_EXTS

    def test_lockfile_names_include_package_lock(self):
        assert "package-lock.json" in LOCKFILE_NAMES
        assert "yarn.lock" in LOCKFILE_NAMES
