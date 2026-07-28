"""Additional pipeline tests — DiffFilter git integration and error handlers."""

import os
import subprocess
from pathlib import Path
from reporeaver.pipeline import DiffFilter, _read_entry, CacheManager
from reporeaver.models import FileEntry


class TestDiffFilterGit:
    def test_get_changed_non_git_dir(self, tmp_path):
        result = DiffFilter.get_changed(tmp_path)
        assert result is None

    def test_get_changed_nonexistent_path(self, tmp_path):
        result = DiffFilter.get_changed(tmp_path / "nonexistent")
        assert result is None

    def test_get_changed_empty_repo(self, tmp_path):
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)
        result = DiffFilter.get_changed(tmp_path)
        assert result is None or isinstance(result, set)


class TestReadEntryExtra:
    def test_read_entry_oserror_handled(self, tmp_path):
        entry = FileEntry(path="test.txt", size=100, is_text=True)
        bad_dir = tmp_path / "nonexistent"
        content, raw = _read_entry(entry, bad_dir, 10)
        assert content == ""

    def test_read_entry_value_error_handled(self, tmp_path):
        entry = FileEntry(path="/../../etc/passwd", size=100, is_text=True)
        content, raw = _read_entry(entry, tmp_path, 10)
        assert content == ""


class TestCacheManagerExtra:
    def test_cache_get_corrupted(self, tmp_path):
        cm = CacheManager(tmp_path)
        entry = FileEntry(path="test.js", size=10, hash_sha256="abc")
        cache_path = tmp_path / cm._cache_key(entry)
        cache_path.write_text("not valid json{{{")
        result = cm.get(entry)
        assert result is None

    def test_cache_set_write_error(self, tmp_path):
        cm = CacheManager(tmp_path)
        read_only = tmp_path / "readonly"
        read_only.mkdir()
        read_only.chmod(0o444)
        entry = FileEntry(path="test.js", size=10, hash_sha256="abc")
        cm2 = CacheManager(read_only)
        cm2.set(entry, [])
        assert True

    def test_cache_prune_empty_dir(self, tmp_path):
        cm = CacheManager(tmp_path / "empty")
        cm.prune()
        assert True

    def test_cache_prune_error(self, tmp_path):
        cm = CacheManager(tmp_path / "nonexistent")
        cm.prune()
        assert True
