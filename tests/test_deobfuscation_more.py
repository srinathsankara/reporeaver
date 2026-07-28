"""Additional deobfuscation tests — trojan source detection and edge cases."""

from reporeaver.deobfuscation.unicode import (
    detect_trojan_source, strip_zero_width, strip_bidi, normalize_homoglyphs, count_zero_width,
)
from reporeaver.deobfuscation.js import find_obfuscated_strings, extract_urls_from_script
from reporeaver.deobfuscation.encoding import try_decode, decode_js_string


class TestTrojanSource:
    def test_detect_bidi_override(self):
        results = detect_trojan_source("\u202eHello")
        assert len(results) == 1
        assert "Bidi" in results[0][1]

    def test_detect_multiple_bidi(self):
        text = "\u202eline1\n\u202eline2\nnormal"
        results = detect_trojan_source(text)
        assert len(results) >= 2

    def test_no_bidi_clean_text(self):
        results = detect_trojan_source("clean text without overrides")
        assert len(results) == 0

    def test_empty_text(self):
        results = detect_trojan_source("")
        assert len(results) == 0

    def test_detect_popdir_override(self):
        results = detect_trojan_source("\u202c")
        assert len(results) == 1


class TestUnicodeExtra:
    def test_strip_multiple_zero_width(self):
        original = "a\u200b\u200cb\u200d"
        cleaned = strip_zero_width(original)
        assert cleaned == "ab"

    def test_strip_bidi_all_types(self):
        text = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        cleaned = strip_bidi(text)
        assert cleaned == ""

    def test_normalize_multiple_homoglyphs(self):
        text = "\u0430\u0435\u043e\u0441"
        normalized = normalize_homoglyphs(text)
        assert normalized == "aeoc"

    def test_count_no_zero_width(self):
        assert count_zero_width("normal text") == 0

    def test_count_multiple(self):
        text = "\u200b\u200b\u200b"
        assert count_zero_width(text) == 3


class TestEncodingMore:
    def test_try_decode_gzip(self):
        import gzip, base64
        payload = b"decoded gzip content"
        compressed = base64.b64encode(gzip.compress(payload)).decode()
        result = try_decode(compressed)
        assert result is not None and "decoded gzip content" in result

    def test_try_decode_url_encoded(self):
        result = try_decode("hello%20world%21")
        assert result is not None and "hello world!" in result

    def test_try_decode_url_no_change(self):
        assert try_decode("hello world") is None

    def test_try_decode_max_depth_zero(self):
        assert try_decode("dGVzdA==", max_depth=0) is None

    def test_try_decode_hex_too_short(self):
        assert try_decode("6865") is None

    def test_try_decode_b64_too_short(self):
        assert try_decode("YWJj") is None

    def test_decode_js_string_no_change(self):
        assert decode_js_string("plain text") is None

    def test_decode_js_string_decode_failure(self):
        assert decode_js_string("\\xZZ") is None
