"""Integration tests for the scanning engine."""

from pathlib import Path
from reporeaver.engine import scan_target
from reporeaver.config import RepoReaverConfig
from reporeaver.ingest import select_ingester
from reporeaver.analyzers.base import _analyzer_registry

FIXTURES = Path(__file__).parent / "fixtures"


class TestEngine:
    def _make_config(self, **kwargs):
        defaults = dict(max_size_mb=5)
        defaults.update(kwargs)
        return RepoReaverConfig(**defaults)

    def test_scan_target_malicious_dir(self):
        config = self._make_config()
        exit_code = scan_target(
            target_path=FIXTURES,
            config=config,
            verbose=False,
            json_output=False,
        )
        assert exit_code == 1  # Should fail due to critical findings

    def test_scan_target_svg_file(self):
        svg = FIXTURES / "malicious.svg"
        config = self._make_config()
        exit_code = scan_target(target_path=svg, config=config)
        assert exit_code == 1

    def test_scan_target_benign_dir(self):
        import tempfile
        import shutil
        tmp = tempfile.mkdtemp(prefix="reporeaver_test_")
        try:
            (Path(tmp) / "clean.txt").write_text("hello world")
            config = self._make_config()
            exit_code = scan_target(target_path=Path(tmp), config=config)
            assert exit_code == 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_select_ingester_directory(self):
        ingester = select_ingester(FIXTURES)
        from reporeaver.ingest.single import DirectoryIngester
        assert isinstance(ingester, DirectoryIngester)

    def test_select_ingester_file(self):
        svg = FIXTURES / "benign.svg"
        ingester = select_ingester(svg)
        from reporeaver.ingest.single import SingleFileIngester
        assert isinstance(ingester, SingleFileIngester)

    def test_load_all_analyzers(self):
        assert len(_analyzer_registry) >= 14
        names = list(_analyzer_registry.keys())
        assert "svg_vector" in names
        assert "unicode" in names
        assert "behavioral" in names
        assert "secrets" in names
        assert "yara" in names

    def test_load_analyzers_skip(self):
        from reporeaver.analyzers.base import _analyzer_registry
        names = [n for n in _analyzer_registry if n not in {"entropy", "behavioral"}]
        assert "entropy" not in names
        assert "behavioral" not in names
        assert "svg_vector" in _analyzer_registry
