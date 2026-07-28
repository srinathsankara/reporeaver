"""Additional YARA analyzer tests — condition skip, regex error, base64 payload path."""

import re
from unittest.mock import MagicMock, patch

from reporeaver.analyzers.yara_analyzer import YaraAnalyzer
from reporeaver.models import FileEntry


def _entry(path="test.txt", is_text=True, size=100):
    return FileEntry(path=path, size=size, is_text=is_text, detected_mime="text/plain")


class TestYaraAnalyzerExtra:
    a = YaraAnalyzer()

    def test_base64_payload_short_lines_skipped(self):
        content = "\n".join("short" for _ in range(50))
        res = self.a.analyze(_entry(), content)
        assert len(res.findings) == 0

    def test_base64_payload_matches(self):
        content = "A" * 150 + "=="
        res = self.a.analyze(_entry(), content)
        matches = [f for f in res.findings if "base64" in f.title.lower()]
        assert len(matches) >= 1

    def test_should_analyze_size_limit(self):
        large = _entry("big.txt", is_text=True, size=2_000_000)
        assert not self.a.should_analyze(large)

    def test_should_analyze_binary_skipped(self):
        binary = _entry("bin.dat", is_text=False)
        assert not self.a.should_analyze(binary)

    def test_regex_error_handled(self):
        with patch("reporeaver.analyzers.yara_analyzer.re.finditer", side_effect=re.error("bad pattern")):
            res = self.a.analyze(_entry(), "test content")
            assert isinstance(res.findings, list)

    def test_clean_content_no_match(self):
        res = self.a.analyze(_entry(), "clean content")
        assert len(res.findings) == 0

    def test_yara_compile_no_yara_lib(self):
        with patch.dict("sys.modules", {"yara": None}):
            a = YaraAnalyzer()
            assert a._yara_compiled is None

    def test_yara_rule_files_load(self, tmp_path):
        yara_dir = tmp_path / "yara_rules"
        yara_dir.mkdir()
        rule_file = yara_dir / "test.yar"
        rule_file.write_text("rule test { condition: true }")
        mock_yara = MagicMock()
        with patch.dict("sys.modules", {"yara": mock_yara}):
            with patch("reporeaver.analyzers.yara_analyzer.YARA_RULE_DIRS", [str(yara_dir)]):
                a = YaraAnalyzer()
                assert a._yara_compiled is not None

    def test_yara_match_exception(self):
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = Exception("match error")
        a = YaraAnalyzer()
        a._yara_compiled = mock_compiled
        res = a.analyze(_entry(), "test content")
        assert len(res.findings) == 0

    def test_yara_match_success(self):
        mock_match = MagicMock()
        mock_match.rule = "test_rule"
        mock_compiled = MagicMock()
        mock_compiled.match.return_value = [mock_match]
        a = YaraAnalyzer()
        a._yara_compiled = mock_compiled
        res = a.analyze(_entry(), "test content")
        assert len(res.findings) == 1
        assert "test_rule" in res.findings[0].title
