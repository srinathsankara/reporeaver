"""Unit tests for pipeline components: CacheManager, DiffFilter, _read_entry."""

import json
from pathlib import Path
from reporeaver.pipeline import CacheManager, DiffFilter, _read_entry
from reporeaver.models import FileEntry, Severity, Confidence, Category, Finding


class TestReadEntry:
    def test_reads_text_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world", encoding="utf-8")
        entry = FileEntry(path="test.txt", size=11, is_text=True)
        content, raw = _read_entry(entry, tmp_path, 10)
        assert content == "hello world"
        assert raw == b"hello world"

    def test_skips_large_file(self, tmp_path):
        f = tmp_path / "big.txt"
        content_str = "x" * 200
        f.write_text(content_str, encoding="utf-8")
        entry = FileEntry(path="big.txt", size=200, is_text=True)
        content, raw = _read_entry(entry, tmp_path, 0.0001)
        assert content == ""

    def test_path_traversal_blocked(self, tmp_path):
        entry = FileEntry(path="../etc/passwd", size=100, is_text=True)
        content, raw = _read_entry(entry, tmp_path, 10)
        assert content == ""

    def test_nonexistent_file(self, tmp_path):
        entry = FileEntry(path="missing.txt", size=100, is_text=True)
        content, raw = _read_entry(entry, tmp_path, 10)
        assert content == ""


class TestCacheManager:
    def test_set_and_get(self, tmp_path):
        cm = CacheManager(tmp_path)
        entry = FileEntry(path="test.js", size=10, hash_sha256="abc")
        findings = [
            Finding("test.js", Severity.HIGH, Confidence.HIGH, Category.SVG_XXE,
                    "title", "desc")
        ]
        cm.set(entry, findings)
        cached = cm.get(entry)
        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["file"] == "test.js"

    def test_cache_miss(self, tmp_path):
        cm = CacheManager(tmp_path)
        entry = FileEntry(path="unknown.js", size=10)
        assert cm.get(entry) is None

    def test_cache_key_different_path(self, tmp_path):
        cm = CacheManager(tmp_path)
        e1 = FileEntry(path="a.js", size=10)
        e2 = FileEntry(path="b.js", size=10)
        cm.set(e1, [])
        assert cm.get(e2) is None

    def test_cache_key_different_hash(self, tmp_path):
        cm = CacheManager(tmp_path)
        e1 = FileEntry(path="f.js", size=10, hash_sha256="aaa")
        e2 = FileEntry(path="f.js", size=10, hash_sha256="bbb")
        cm.set(e1, [])
        assert cm.get(e2) is None

    def test_prune_oldest(self, tmp_path):
        cm = CacheManager(tmp_path)
        for i in range(5):
            e = FileEntry(path=f"f{i}.js", size=10)
            cm.set(e, [])
        cm.prune()
        remaining = list(tmp_path.iterdir())
        assert len([p for p in remaining if p.suffix != ".tmp"]) <= 5


class TestDiffFilter:
    def test_apply_none_returns_all(self):
        entries = [FileEntry(path="a", size=1), FileEntry(path="b", size=1)]
        assert DiffFilter.apply(entries, None) == entries

    def test_apply_filters(self):
        entries = [FileEntry(path="a", size=1), FileEntry(path="b", size=1)]
        result = DiffFilter.apply(entries, {"a"})
        assert len(result) == 1
        assert result[0].path == "a"

    def test_apply_empty_set(self):
        entries = [FileEntry(path="a", size=1)]
        assert DiffFilter.apply(entries, set()) == []
