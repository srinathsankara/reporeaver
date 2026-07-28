"""Additional engine tests — output paths and error branches."""

import json
from unittest.mock import patch

from reporeaver.config import RepoReaverConfig
from reporeaver.engine import scan_target


def _make_config(**kw):
    defaults = dict(max_size_mb=5)
    defaults.update(kw)
    return RepoReaverConfig(**defaults)


class TestEngineOutput:
    def test_json_output(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "clean.txt").write_text("hello")
        out = tmp_path / "report.json"
        _ = scan_target(
            target_path=target,
            config=_make_config(),
            output_file=str(out),
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert "risk_score" in data

    def test_sarif_output(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "clean.txt").write_text("hello")
        out = tmp_path / "out.sarif"
        _ = scan_target(
            target_path=target,
            config=_make_config(),
            sarif_output=str(out),
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert data.get("$schema", "").startswith("https://")

    def test_html_output(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "clean.txt").write_text("hello")
        out = tmp_path / "report.html"
        _ = scan_target(
            target_path=target,
            config=_make_config(),
            html_output=str(out),
        )
        assert out.exists()
        assert b"<html" in out.read_bytes().lower() or b"<!doctype" in out.read_bytes().lower()

    def test_history_save_failure_logged(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "clean.txt").write_text("hello")
        with patch("reporeaver.engine.save_scan_history", side_effect=Exception("db error")):
            code = scan_target(
                target_path=target,
                config=_make_config(),
                save_history=True,
            )
            assert code in (0, 1)

    def test_scan_without_history(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "clean.txt").write_text("hello")
        code = scan_target(
            target_path=target,
            config=_make_config(),
            save_history=False,
        )
        assert code == 0
