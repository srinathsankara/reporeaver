"""Fuzz tests for ingest pipeline — malformed/corrupted archives."""

import io
import os
import zipfile
import tarfile
from pathlib import Path

from reporeaver.ingest.base import IngestResult
from reporeaver.ingest.single import _make_entry, _build_entry, _ingest_zip, _ingest_tar, _extract_archive_bytes, _is_bomb


def _make_zip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("test.txt", data)
    return buf.getvalue()


class TestFuzzMakeEntry:
    """Malformed paths to _make_entry."""

    def test_random_binary_file(self, tmp_path: Path):
        f = tmp_path / "random.bin"
        f.write_bytes(os.urandom(100))
        entry = _make_entry(f)
        assert entry is not None
        assert not entry.is_text

    def test_unicode_filename(self, tmp_path: Path):
        f = tmp_path / "unicode\u200b.txt"
        f.write_text("hello")
        entry = _make_entry(f)
        assert entry is not None

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        entry = _make_entry(f)
        assert entry is not None

    def test_nonexistent_file(self, tmp_path: Path):
        entry = _make_entry(tmp_path / "nonexistent.txt")
        assert entry is None


class TestFuzzIngestZip:
    """Malformed zip files passed to _ingest_zip."""

    def test_random_bytes_not_archive(self, tmp_path: Path):
        f = tmp_path / "random.zip"
        f.write_bytes(os.urandom(200))
        result = _ingest_zip(f)
        assert result is None or len(result.files) == 0

    def test_corrupted_zip_truncated_eocd(self, tmp_path: Path):
        """Truncating the end-of-central-directory should fail."""
        f = tmp_path / "corrupt.zip"
        f.write_bytes(b"PK\x03\x04truncated")
        result = _ingest_zip(f)
        assert result is None or len(result.files) == 0

    def test_truncated_zip(self, tmp_path: Path):
        buf = _make_zip(b"hello world")
        f = tmp_path / "truncated.zip"
        f.write_bytes(buf[:20])
        result = _ingest_zip(f)
        assert result is None or len(result.files) == 0

    def test_empty_zip_file(self, tmp_path: Path):
        f = tmp_path / "empty.zip"
        f.write_bytes(b"")
        result = _ingest_zip(f)
        assert result is None or len(result.files) == 0


class TestFuzzIngestTar:
    """Malformed tar files passed to _ingest_tar."""

    def test_corrupted_tar_header(self, tmp_path: Path):
        """Corrupting the tar magic should cause failure."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="evil.sh")
            info.size = 50
            tar.addfile(info, io.BytesIO(os.urandom(50)))
        data = bytearray(buf.getvalue())
        # Corrupt the tar magic bytes
        for i in range(257, 262):
            if i < len(data):
                data[i] ^= 0xFF
        f = tmp_path / "corrupt.tar"
        f.write_bytes(bytes(data))
        result = _ingest_tar(f)
        assert result is None or len(result.files) == 0

    def test_random_bytes_is_not_tar(self, tmp_path: Path):
        f = tmp_path / "random.tar"
        f.write_bytes(os.urandom(200))
        result = _ingest_tar(f)
        assert result is None or len(result.files) == 0

    def test_truncated_tar(self, tmp_path: Path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="test.txt")
            info.size = 5
            tar.addfile(info, io.BytesIO(b"hello"))
        f = tmp_path / "truncated.tar"
        f.write_bytes(buf.getvalue()[:50])
        result = _ingest_tar(f)
        assert result is None or len(result.files) == 0

    def test_empty_tar_file(self, tmp_path: Path):
        f = tmp_path / "empty.tar"
        f.write_bytes(b"")
        result = _ingest_tar(f)
        assert result is None or len(result.files) == 0


class TestFuzzExtractArchiveBytes:
    """Malformed data passed to _extract_archive_bytes."""

    def test_random_bytes(self):
        result = _extract_archive_bytes(os.urandom(200), "test.zip", 0)
        assert result is None or len(result.files) == 0

    def test_corrupted_bytes(self):
        result = _extract_archive_bytes(b"PK\x03\x04truncated", "test.zip", 0)
        assert result is None or len(result.files) == 0

    def test_too_deep(self):
        buf = _make_zip(b"hello")
        result = _extract_archive_bytes(buf, "test.zip", 11)
        assert result is None or len(result.files) == 0


class TestFuzzBuildEntry:
    """Edge cases for _build_entry."""

    def test_empty_content(self):
        entry = _build_entry("/tmp/empty.txt", 0, "text/plain", ".txt", io.BytesIO(b""))
        assert entry is not None

    def test_large_content(self):
        entry = _build_entry("/tmp/large.txt", 1000, "text/plain", ".txt", io.BytesIO(b"x" * 1000))
        assert entry is not None

    def test_binary_content(self):
        entry = _build_entry("/tmp/data.bin", 100, "application/octet-stream", ".bin", io.BytesIO(os.urandom(100)))
        assert entry is not None
        assert not entry.is_text


class TestFuzzZipBomb:
    """Ensure zip bombs are caught by ingest."""

    def test_is_bomb_too_many_files(self):
        files = [f"/file{i}.txt" for i in range(10_001)]
        assert _is_bomb(files, 1000, "test.zip")

    def test_is_bomb_not_too_many(self):
        assert not _is_bomb(["a.txt"], 1000, "test.zip")

    def test_is_bomb_too_much_data(self):
        assert _is_bomb(["a.txt"], 501 * 1024 * 1024, "test.zip")

    def test_large_compressed_ratio(self, tmp_path: Path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("bomb.txt", "a" * 100_000_000)
        f = tmp_path / "bomb2.zip"
        f.write_bytes(buf.getvalue())
        result = _ingest_zip(f)
        assert result is None or len(result.files) == 0
