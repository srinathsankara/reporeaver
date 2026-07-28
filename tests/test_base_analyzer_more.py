"""Additional base analyzer tests — entry_point load success path."""

from unittest.mock import MagicMock, patch

from reporeaver.analyzers.base import discover_analyzers


class TestDiscoverAnalyzers:
    def test_entry_point_loads_successfully(self):
        mock_cls = MagicMock()
        mock_cls.name = "loaded_plugin"
        mock_entry = MagicMock()
        mock_entry.module = "reporeaver.analyzers.custom"
        mock_entry.name = "custom_plugin"
        mock_entry.load.return_value = mock_cls
        with patch("importlib.metadata.entry_points") as mock_ep:
            mock_ep.return_value.get.return_value = [mock_entry]
            result = discover_analyzers()
            assert "custom_plugin" in result
            assert result["custom_plugin"] is mock_cls

    def test_entry_point_fallback_to_registry_when_no_plugins(self):
        with patch("importlib.metadata.entry_points") as mock_ep:
            mock_ep.return_value.get.return_value = []
            result = discover_analyzers()
            assert isinstance(result, dict)

    def test_entry_point_exception_falls_back(self):
        with patch("importlib.metadata.entry_points", side_effect=Exception("broken")):
            result = discover_analyzers()
            assert isinstance(result, dict)
