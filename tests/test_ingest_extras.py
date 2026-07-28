"""Additional ingest tests for archive edge cases."""

import io
import tarfile
import zipfile
from unittest.mock import patch

import pytest

from reporeaver.ingest import ArchiveIngester
from reporeaver.ingest.single import (
    MAX_FILE_COUNT,
    MAX_FILE_SIZE,
    TOTAL_MAX_SIZE,
    DirectoryIngester,
    _extract_archive_bytes,
    _ingest_tar,
    _ingest_zip,
    _is_bomb,
    _make_entry,
    _should_skip_name,
)


class TestShouldSkipName:
    def test_path_traversal(self):
        assert _should_skip_name("../etc/passwd")

    def test_absolute_path(self):
        assert _should_skip_name("/etc/passwd")

    def test_windows_ads(self):
        assert _should_skip_name("file:secret")

    def test_ignore_dirs(self):
        assert _should_skip_name("node_modules/evil.js")

    def test_ignore_exts(self):
        assert _should_skip_name("file.pyc")

    def test_clean_name(self):
        assert not _should_skip_name("src/main.js")


class TestIsBomb:
    def test_too_many_files(self):
        assert _is_bomb(list(range(MAX_FILE_COUNT)), 0, "test")

    def test_too_much_data(self):
        assert _is_bomb([], TOTAL_MAX_SIZE + 1, "test")

    def test_not_bomb(self):
        assert not _is_bomb([], 100, "test")


class TestIngestZip:
    def test_ingest_simple_zip(self, tmp_path):
        zpath = tmp_path / "test.zip"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("a.js", "var x = 1;")
            z.writestr("b.txt", "hello")
            z.writestr("node_modules/evil.js", "bad")
        result = _ingest_zip(zpath)
        assert result.total_files == 2
        paths = {f.path for f in result.files}
        assert "a.js" in paths
        assert "b.txt" in paths

    def test_ingest_empty_zip(self, tmp_path):
        zpath = tmp_path / "empty.zip"
        with zipfile.ZipFile(str(zpath), "w") as _:
            pass
        result = _ingest_zip(zpath)
        assert result.total_files == 0

    def test_ingest_zip_max_size_skip(self, tmp_path):
        zpath = tmp_path / "big.zip"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("big.bin", b"x" * (MAX_FILE_SIZE + 1))
            z.writestr("small.txt", "ok")
        result = _ingest_zip(zpath)
        assert result.total_files == 1
        assert result.files[0].path == "small.txt"

    def test_nested_zip(self, tmp_path):
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as z:
            z.writestr("inner.txt", "nested")
        inner_data = inner_buf.getvalue()

        zpath = tmp_path / "outer.zip"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("outer.txt", "outside")
            z.writestr("inner.zip", inner_data)
        result = _ingest_zip(zpath)
        paths = {f.path for f in result.files}
        assert "outer.txt" in paths
        assert any("inner.txt" in f.path for f in result.files)

    def test_zip_bomb_file_count(self, tmp_path):
        zpath = tmp_path / "bomb.zip"
        with zipfile.ZipFile(str(zpath), "w") as z:
            for i in range(MAX_FILE_COUNT + 5):
                z.writestr(f"f{i}.txt", "x")
        result = _ingest_zip(zpath)
        assert result.total_files <= MAX_FILE_COUNT

    def test_zip_nested_memory_error(self, tmp_path):
        zpath = tmp_path / "memfail.zip"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("inner.zip", b"not-a-real-zip")
        with patch("zipfile.ZipFile.open", side_effect=MemoryError("decompression bomb")):
            import pytest
            with pytest.raises(MemoryError):
                _ingest_zip(zpath)


class TestIngestTar:
    def test_ingest_simple_tar(self, tmp_path):
        tpath = tmp_path / "test.tar"
        with tarfile.open(str(tpath), "w") as t:
            t.addfile(tarfile.TarInfo("a.js"), io.BytesIO(b"var x = 1;"))
            t.addfile(tarfile.TarInfo("b.txt"), io.BytesIO(b"hello"))
        result = _ingest_tar(tpath)
        assert result.total_files == 2
        paths = {f.path for f in result.files}
        assert "a.js" in paths
        assert "b.txt" in paths

    def test_tar_nested_memory_error(self, tmp_path):
        tpath = tmp_path / "memfail.tar"
        with tarfile.open(str(tpath), "w") as t:
            info = tarfile.TarInfo("inner.tar")
            info.size = 10
            t.addfile(info, io.BytesIO(b"not-a-real-tar"))
        with patch("tarfile.TarFile.extractfile", side_effect=MemoryError("decompression bomb")):
            with pytest.raises(MemoryError):
                _ingest_tar(tpath)


class TestExtractArchiveBytes:
    def test_extract_nested_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("nested.txt", "deep")
        data = buf.getvalue()
        result = _extract_archive_bytes(data, "outer.zip", 1)
        assert result.total_files >= 1

    def test_extract_nested_tar(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            t.addfile(tarfile.TarInfo("nested.txt"), io.BytesIO(b"deep"))
        data = buf.getvalue()
        result = _extract_archive_bytes(data, "outer.tar", 1)
        assert result.total_files >= 1

    def test_extract_too_deep(self):
        result = _extract_archive_bytes(b"data", "outer.zip", 5)
        assert result.source_type == "nested_too_deep"

    def test_extract_random_bytes(self):
        result = _extract_archive_bytes(b"not an archive", "random.bin", 1)
        assert result.source_type == "nested_unknown"

    def test_extract_zip_with_ignore_dir(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("node_modules/evil.js", "bad")
        data = buf.getvalue()
        result = _extract_archive_bytes(data, "outer.zip", 1)
        assert result.total_files == 0


class TestArchiveIngester:
    def test_rar_not_implemented(self, tmp_path):
        f = tmp_path / "test.rar"
        f.write_text("fake rar")
        ingester = ArchiveIngester()
        result = ingester.ingest(str(f))
        assert result.source_type == "archive"

    def test_7z_not_implemented(self, tmp_path):
        f = tmp_path / "test.7z"
        f.write_text("fake 7z")
        ingester = ArchiveIngester()
        result = ingester.ingest(str(f))
        assert result.source_type == "archive"


class TestDirectoryIngester:
    def test_path_traversal_error_handled(self, tmp_path):
        ingester = DirectoryIngester()
        with patch.object(type(tmp_path), "rglob", return_value=[tmp_path / ".." / "escaped.txt"]):
            with patch("pathlib.Path.is_file", return_value=True):
                result = ingester.ingest(str(tmp_path))
                assert result.total_files == 0


class TestMakeEntry:
    def test_symlink_skipped(self, tmp_path):
        link = tmp_path / "link.txt"
        real = tmp_path / "real.txt"
        real.write_text("content")
        try:
            link.symlink_to(real)
        except OSError:
            pytest.skip("symlink not supported on this platform")
        entry = _make_entry(link)
        assert entry is None
