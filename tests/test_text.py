"""Tests for text utilities."""

from reporeaver.utils.text import is_meaningful_text


class TestIsMeaningfulText:
    def test_short_text_not_meaningful(self):
        assert not is_meaningful_text("ab", min_len=5)

    def test_printable_ascii_is_meaningful(self):
        assert is_meaningful_text("hello world this is a test string")

    def test_low_printable_ratio_not_meaningful(self):
        text = "\x00\x01\x02" * 50
        assert not is_meaningful_text(text)

    def test_default_min_len_accepts_short(self):
        assert is_meaningful_text("hello")

    def test_no_spaces_long_alpha_not_meaningful(self):
        text = "a" * 60
        assert not is_meaningful_text(text)

    def test_with_spaces_long_alpha_is_meaningful(self):
        text = "aaaaaaa bbbbbbb ccccccc dddddddd eeeeeeee"
        assert is_meaningful_text(text)
