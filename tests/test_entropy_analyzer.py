"""Targeted tests for EntropyAnalyzer edge cases."""

import base64

from reporeaver.analyzers.entropy_analyzer import EntropyAnalyzer, _has_meaningful_content, _try_decode
from reporeaver.models import FileEntry


def _entry(path="test.txt", is_text=True, size=1000):
    return FileEntry(path=path, size=size, is_text=is_text, detected_mime="text/plain")


class TestEntropyAnalyzer:
    a = EntropyAnalyzer()

    def test_long_line_truncated(self):
        res = self.a.analyze(_entry(), "AB" * 2500)
        assert isinstance(res.findings, list)

    def test_short_line_skipped(self):
        res = self.a.analyze(_entry(), "short")
        assert len(res.findings) == 0

    def test_high_entropy_not_b64_or_hex_skipped(self):
        text = "@@@@!!!!####$$$$" * 5
        res = self.a.analyze(_entry(), text)
        assert len(res.findings) == 0

    def test_b64_meaningful_detected(self):
        import random
        import string
        random.seed(12345)
        chars = string.ascii_letters + string.digits + string.punctuation + " "
        long_text = "".join(random.choices(chars, k=5000))
        encoded = base64.b64encode(long_text.encode()).decode()
        res = self.a.analyze(_entry(), encoded)
        high = [f for f in res.findings if f.severity.name == "HIGH"]
        assert len(high) >= 1

    def test_should_analyze_respects_size_limit(self):
        assert not self.a.should_analyze(_entry("big.bin", is_text=True, size=3_000_000))

    def test_should_analyze_binary_skipped(self):
        assert not self.a.should_analyze(_entry("bin.dat", is_text=False))


class TestTryDecode:
    def test_base64_decode_failure(self):
        assert _try_decode("!!!not-valid-b64!!!") is None

    def test_hex_decode_failure(self):
        assert _try_decode("ZZZZZZZZZZ") is None

    def test_base64_decode_success(self):
        encoded = base64.b64encode(b"hello world").decode()
        result = _try_decode(encoded)
        assert result is not None and "hello" in result

    def test_hex_decode_success(self):
        result = _try_decode("68656c6c6f")
        assert result is not None and "hello" in result

    def test_base64_no_ascii_letters(self):
        result = _try_decode("AAAAAAAAAAAA")
        assert result is None


class TestHasMeaningfulContent:
    def test_too_short(self):
        assert _has_meaningful_content("short") is False

    def test_low_printable_ratio(self):
        text = "\x00\x01\x02\x03\x04\x05\x06\x07\x08" * 5
        assert _has_meaningful_content(text) is False

    def test_meaningful_text(self):
        assert _has_meaningful_content("hello world this is code") is True
