"""Additional report tests — encoding fallback."""

import builtins
from unittest.mock import patch
from reporeaver.output.report import _safe_print


class TestSafePrint:
    def test_normal_print(self, capsys):
        _safe_print("hello", "world")
        captured = capsys.readouterr()
        assert captured.out.strip() == "hello world"

    def test_unicode_encode_error_fallback(self):
        call_count = [0]
        orig_print = builtins.print

        def mock_print(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise UnicodeEncodeError("codec", "", 0, 1, "bad")
            orig_print(*args, **kwargs)

        with patch.object(builtins, "print", mock_print):
            _safe_print("\u2713 checkmark")
        assert call_count[0] >= 2

    def test_print_with_non_ascii(self, capsys):
        _safe_print("hello \u2713 world")
        captured = capsys.readouterr()
        assert "hello" in captured.out
