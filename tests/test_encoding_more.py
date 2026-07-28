"""Additional encoding deobfuscation tests — _is_meaningful edge cases, decode_js_string."""
import pytest
from reporeaver.deobfuscation.encoding import (
    try_decode, decode_js_string, _is_meaningful,
)


class TestIsMeaningful:
    def test_too_short(self):
        assert not _is_meaningful("ab")

    def test_low_printable_ratio(self):
        assert not _is_meaningful("a\x00b\x00c\x00d\x00e\x00f\x00g")

    def test_meaningful_text(self):
        assert _is_meaningful("hello world")

    def test_long_no_space_all_alpha_skipped(self):
        assert not _is_meaningful("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")

    def test_long_no_space_with_punctuation(self):
        assert _is_meaningful("console.log(hello);alert(world);")

    def test_compact_code_accepted(self):
        assert _is_meaningful("var x=1;var y=2;var z=3;var a=4;var b=5;var c=6;")


class TestDecodeJsString:
    def test_basic_unicode_escape(self):
        result = decode_js_string("\\u0048\\u0065\\u006c\\u006c\\u006f")
        assert result == "Hello"

    def test_no_escape_returns_none(self):
        result = decode_js_string("hello")
        assert result is None

    def test_mixed_string(self):
        result = decode_js_string("hell\\u006f")
        assert result == "hello"

    def test_invalid_escape_returns_none(self):
        result = decode_js_string("\\uZZZZ")
        assert result is None


class TestTryDecodeEdgeCases:
    def test_max_depth_zero(self):
        result = try_decode("aGVsbG8=", max_depth=0)
        assert result is None

    def test_hex_decode(self):
        result = try_decode("48656c6c6f")
        assert result == "Hello"

    def test_hex_decode_too_short(self):
        result = try_decode("ab")
        assert result is None

    def test_b64_decode(self):
        result = try_decode("aGVsbG8gd29ybGQ=")  # "hello world"
        assert result == "hello world"

    def test_gzip_decode(self):
        import gzip
        data = gzip.compress(b"hello world")
        import base64
        b64 = base64.b64encode(data).decode()
        result = try_decode(b64)
        assert result == "hello world"

    def test_url_decode(self):
        result = try_decode("hello%20world")
        assert result == "hello world"

    def test_double_encoding(self):
        import base64
        encoded = base64.b64encode(b"hello world").decode()
        double = base64.b64encode(encoded.encode()).decode()
        result = try_decode(double)
        assert result == "hello world"

    def test_decode_js_string_from_try_decode(self):
        text = "\\u0048\\u0065\\u006c\\u006c\\u006f"
        result = try_decode(text)
        # try_decode doesn't handle unicode_escape directly, but decode_js_string does
        assert result is None

    def test_invalid_b64_returns_none(self):
        result = try_decode("!!!")
        assert result is None

    def test_invalid_hex_returns_none(self):
        result = try_decode("ZZZZZZ")
        assert result is None
