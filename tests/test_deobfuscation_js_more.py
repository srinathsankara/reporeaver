"""Additional JS deobfuscation tests — hex decode, fromCharCode with hex, edge cases."""
import pytest
from reporeaver.deobfuscation.js import (
    find_obfuscated_strings, HEX_STRING, UNICODE_STRING,
    EVAL_B64, FROM_CHARCODE, ENCODED_ARRAY,
)


class TestFindHexStrings:
    def test_hex_decode_correct(self):
        text = r"var x = '\x48\x65\x6c\x6c\x6f';"
        results = find_obfuscated_strings(text)
        decoded = [r[0] for r in results if r[2] == "hex_escape"]
        assert "Hello" in decoded

    def test_hex_with_non_printable_skipped(self):
        text = r"var x = '\x00\x01\x02';"
        results = find_obfuscated_strings(text)
        hex_results = [r for r in results if r[2] == "hex_escape"]
        assert len(hex_results) == 0

    def test_hex_decode_multiple(self):
        text = r"'\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64'"
        results = find_obfuscated_strings(text)
        decoded = [r[0] for r in results if r[2] == "hex_escape"]
        assert any("Hello World" in d for d in decoded)

    def test_empty_hex_does_not_crash(self):
        text = r"'\x00'"
        # Should not raise, just return nothing printable
        results = find_obfuscated_strings(text)
        assert isinstance(results, list)


class TestFindUnicodeStrings:
    def test_unicode_decode(self):
        text = r"var x = '\u0048\u0065\u006c\u006c\u006f';"
        results = find_obfuscated_strings(text)
        decoded = [r[0] for r in results if r[2] == "unicode_escape"]
        assert "Hello" in decoded


class TestFindEvalB64:
    def test_eval_atob(self):
        text = 'eval(atob("dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZw=="))'
        results = find_obfuscated_strings(text)
        decoded = [r[0] for r in results if r[2] == "eval_base64"]
        assert "this is a base64" in decoded[0]

    def test_eval_atob_too_short_skipped(self):
        text = 'eval(atob("YQ=="))'  # 4 chars, min 20
        results = find_obfuscated_strings(text)
        decoded = [r for r in results if r[2] == "eval_base64"]
        assert len(decoded) == 0


class TestFindFromCharCode:
    def test_from_char_code(self):
        text = "String.fromCharCode(72,101,108,108,111)"
        results = find_obfuscated_strings(text)
        decoded = [r[0] for r in results if r[2] == "from_char_code"]
        assert "Hello" in decoded

    def test_from_char_code_with_hex(self):
        text = "String.fromCharCode(0x48,0x65,0x6c,0x6c,0x6f)"
        results = find_obfuscated_strings(text)
        decoded = [r[0] for r in results if r[2] == "from_char_code"]
        assert "Hello" in decoded

    def test_from_char_code_out_of_range_skipped(self):
        text = "String.fromCharCode(1114112)"  # > 0x10FFFF
        results = find_obfuscated_strings(text)
        decoded = [r for r in results if r[2] == "from_char_code"]
        assert len(decoded) == 0

    def test_from_char_code_invalid_arg_skipped(self):
        text = "String.fromCharCode(abc)"
        results = find_obfuscated_strings(text)
        decoded = [r for r in results if r[2] == "from_char_code"]
        assert len(decoded) == 0


class TestNoFalsePositives:
    def test_clean_text(self):
        text = "console.log('hello world');"
        results = find_obfuscated_strings(text)
        assert len(results) == 0

    def test_mixed_obfuscation(self):
        text = (
            r"var a = '\x48\x65\x6c\x6c\x6f';"
            r'var b = eval(atob("d29ybGQ="));'
            r"var c = String.fromCharCode(33);"
        )
        results = find_obfuscated_strings(text)
        assert len(results) >= 1
