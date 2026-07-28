"""Additional ingest tests — edge cases in _make_entry, DirectoryIngester, and archive error paths."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from reporeaver.ingest.single import (
    ArchiveIngester,
    DirectoryIngester,
    _build_entry,
    _extract_archive_path,
    _ingest_tar,
    _ingest_zip,
    _make_entry,
)


@pytest.mark.skipif(os.name == "nt", reason="symlink requires admin on Windows")
class TestMakeEntry:
    def test_symlink_returns_none(self, tmp_path):
        target = tmp_path / "real"
        target.write_text("content")
        link = tmp_path / "link"
        link.symlink_to(target)
        result = _make_entry(link)
        assert result is None

    def test_oserror_returns_none(self, tmp_path):
        missing = tmp_path / "nonexistent"
        result = _make_entry(missing)
        assert result is None

    def test_normal_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = _make_entry(f)
        assert result is not None
        assert result.path == str(f).replace("\\", "/")


class TestBuildEntry:
    def test_make_entry_skips_hash(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("content")
        entry = _make_entry(f)
        assert entry is not None
        assert entry.hash_sha256 is None

    def test_no_disk_path_no_hash(self):
        entry = _build_entry("test.txt", 100, "text/plain", ".txt")
        assert entry is not None
        assert entry.hash_sha256 is None


class TestDirectoryIngester:
    def test_oserror_handled(self, tmp_path):
        d = DirectoryIngester()
        with patch.object(Path, "is_file", return_value=True):
            with patch.object(Path, "stat", side_effect=OSError):
                with patch.object(Path, "relative_to", return_value="bad"):
                    result = d.ingest(str(tmp_path))
                    assert len(result.files) == 0

    def test_ignore_dirs_filtered(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "evil.js").write_text("bad")
        d = DirectoryIngester()
        result = d.ingest(str(tmp_path))
        assert len(result.files) == 0

    def test_ignore_exts_filtered(self, tmp_path):
        (tmp_path / "code.pyc").write_text("compiled")
        d = DirectoryIngester()
        result = d.ingest(str(tmp_path))
        assert len(result.files) == 0


class TestArchiveEdgeCases:
    def test_archive_unknown_suffix(self, tmp_path):
        f = tmp_path / "test.unknown"
        f.write_text("data")
        ingester = ArchiveIngester()
        result = ingester.ingest(str(f))
        assert result.source_type == "archive"

    def test_zip_extract_exception(self, tmp_path):
        bad_zip = tmp_path / "bad.zip"
        bad_zip.write_text("not a zip")
        result = _ingest_zip(bad_zip)
        assert len(result.files) == 0

    def test_tar_extract_exception(self, tmp_path):
        bad_tar = tmp_path / "bad.tar"
        bad_tar.write_text("not a tar")
        result = _ingest_tar(bad_tar)
        assert len(result.files) == 0

    def test_extract_archive_path_too_deep(self):
        result = _extract_archive_path(Path("/tmp/test.zip"), depth=4)
        assert result.source_type == "archive"

    def test_extract_archive_path_unknown(self, tmp_path):
        f = tmp_path / "test.xyz"
        f.write_text("data")
        result = _extract_archive_path(f)
        assert result.source_type == "archive"
