"""Tests for the base analyzer module."""

from unittest.mock import MagicMock, patch

from reporeaver.analyzers.base import (
    AnalyzerResult,
    BaseAnalyzer,
    _analyzer_registry,
    all_analyzers,
    discover_analyzers,
    register_analyzer,
)
from reporeaver.models import FileEntry, Finding


class _ConcreteAnalyzer(BaseAnalyzer):
    name = "concrete_test"
    def should_analyze(self, entry):
        return True
    def analyze(self, entry, content):
        return AnalyzerResult([])


class TestAnalyzerResult:
    def test_bool_true_when_findings(self):
        result = AnalyzerResult([MagicMock(spec=Finding)])
        assert bool(result) is True

    def test_bool_false_when_no_findings(self):
        result = AnalyzerResult([])
        assert bool(result) is False


class TestBaseAnalyzer:
    def test_analyze_binary_returns_empty(self):
        entry = MagicMock(spec=FileEntry)
        analyzer = _ConcreteAnalyzer()
        result = analyzer.analyze_binary(entry, b"data")
        assert len(result.findings) == 0

    def test_analyze_binary_is_analyzer_result(self):
        entry = MagicMock(spec=FileEntry)
        analyzer = _ConcreteAnalyzer()
        result = analyzer.analyze_binary(entry, b"data")
        assert isinstance(result, AnalyzerResult)


class TestRegistry:
    def setup_method(self):
        self._orig = dict(_analyzer_registry)

    def teardown_method(self):
        _analyzer_registry.clear()
        _analyzer_registry.update(self._orig)

    def test_register_analyzer(self):
        @register_analyzer
        class _(BaseAnalyzer):
            name = "temp_test_reg"
            def should_analyze(self, entry):
                return True
            def analyze(self, entry, content):
                return AnalyzerResult([])
        assert "temp_test_reg" in _analyzer_registry

    def test_all_analyzers_returns_copy(self):
        result = all_analyzers()
        assert isinstance(result, dict)

    def test_discover_analyzers_entry_points_fallback(self):
        with patch("importlib.metadata.entry_points") as mock_ep:
            mock_ep.return_value.get.return_value = []
            result = discover_analyzers()
            assert isinstance(result, dict)

    def test_discover_analyzers_skips_external(self):
        mock_entry = MagicMock()
        mock_entry.module = "external_pkg.plugin"
        with patch("importlib.metadata.entry_points") as mock_ep:
            mock_ep.return_value.get.return_value = [mock_entry]
            result = discover_analyzers()
            assert isinstance(result, dict)

    def test_discover_analyzers_load_error(self):
        mock_entry = MagicMock()
        mock_entry.module = "reporeaver.analyzers.fake"
        mock_entry.name = "fake"
        mock_entry.load.side_effect = ImportError("broken")
        with patch("importlib.metadata.entry_points") as mock_ep:
            mock_ep.return_value.get.return_value = [mock_entry]
            result = discover_analyzers()
            assert isinstance(result, dict)

    def test_discover_analyzers_exception(self):
        with patch("importlib.metadata.entry_points", side_effect=Exception("no metadata")):
            result = discover_analyzers()
            assert isinstance(result, dict)
