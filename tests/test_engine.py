"""Integration tests for the scanning engine."""

from pathlib import Path
from reporeaver.engine import scan_target, _load_analyzers, _select_ingester
from reporeaver.models import ScanResult, Severity

FIXTURES = Path(__file__).parent / "fixtures"


class TestEngine:
    def test_scan_target_malicious_dir(self):
        exit_code = scan_target(
            target=str(FIXTURES),
            verbose=False,
            json_output=False,
            max_size_mb=5,
        )
        assert exit_code == 1  # Should fail due to critical findings

    def test_scan_target_svg_file(self):
        svg = FIXTURES / "malicious.svg"
        exit_code = scan_target(target=str(svg), max_size_mb=5)
        assert exit_code == 1

    def test_scan_target_benign_dir(self):
        # Create a temp clean directory
        import tempfile
        import os
        tmp = tempfile.mkdtemp(prefix="reporeaver_test_")
        try:
            (Path(tmp) / "clean.txt").write_text("hello world")
            exit_code = scan_target(target=tmp, max_size_mb=5)
            assert exit_code == 0
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_select_ingester_directory(self):
        ingester = _select_ingester(FIXTURES)
        from reporeaver.ingest.single import DirectoryIngester
        assert isinstance(ingester, DirectoryIngester)

    def test_select_ingester_file(self):
        svg = FIXTURES / "benign.svg"
        ingester = _select_ingester(svg)
        from reporeaver.ingest.single import SingleFileIngester
        assert isinstance(ingester, SingleFileIngester)

    def test_load_all_analyzers(self):
        analyzers = _load_analyzers(set())
        assert len(analyzers) >= 9
        names = [a.name for a in analyzers]
        assert "svg_vector" in names
        assert "unicode" in names
        assert "behavioral" in names

    def test_load_analyzers_skip(self):
        analyzers = _load_analyzers({"entropy", "behavioral"})
        names = [a.name for a in analyzers]
        assert "entropy" not in names
        assert "behavioral" not in names
        assert "svg_vector" in names
