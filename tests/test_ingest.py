"""Tests for ingest layer."""

import tempfile
from pathlib import Path

from reporeaver.ingest.single import SingleFileIngester, DirectoryIngester, ArchiveIngester
from reporeaver.models import FileEntry


class TestSingleFileIngester:
    def test_ingest_text_file(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("hello")
            fname = f.name
        try:
            ingester = SingleFileIngester()
            result = ingester.ingest(fname)
            assert result.total_files == 1
            assert result.files[0].path.endswith(".txt")
        finally:
            import os
            os.unlink(fname)


class TestDirectoryIngester:
    def test_ingest_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test.js").write_text("var x = 1;")
            Path(tmp, "test.svg").write_text("<svg></svg>")
            Path(tmp, "readme.md").write_text("# Hello")
            ingester = DirectoryIngester()
            result = ingester.ingest(tmp)
            assert result.total_files == 3
            paths = [f.path for f in result.files]
            assert any("test.js" in p for p in paths)
            assert any("test.svg" in p for p in paths)
            assert any("readme.md" in p for p in paths)

    def test_ingest_ignores_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "good.js").write_text("ok")
            Path(tmp, "node_modules").mkdir()
            Path(tmp, "node_modules", "bad.js").write_text("evil")
            ingester = DirectoryIngester()
            result = ingester.ingest(tmp)
            paths = [f.path for f in result.files]
            assert any("good.js" in p for p in paths)
            assert not any("node_modules" in p for p in paths)


class TestArchiveIngester:
    def test_ingest_zip(self):
        import zipfile
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            fname = f.name
        try:
            with zipfile.ZipFile(fname, "w") as z:
                z.writestr("test.js", "var x = 1;")
                z.writestr("test.svg", "<svg></svg>")
                z.writestr("node_modules/evil.js", "malicious")
            ingester = ArchiveIngester()
            result = ingester.ingest(fname)
            assert result.total_files == 2
            paths = [f.path for f in result.files]
            assert "test.js" in paths
            assert "test.svg" in paths
            assert "node_modules/evil.js" not in paths
        finally:
            import os
            os.unlink(fname)
