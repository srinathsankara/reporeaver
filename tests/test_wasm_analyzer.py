"""Edge-case tests for wasm_analyzer — all branches."""
import pytest

from reporeaver.analyzers.wasm_analyzer import (
    SECTION_EXPORT,
    SECTION_FUNC,
    SECTION_IMPORT,
    WASM_MAGIC,
    WASM_VERSION,
    WasmAnalyzer,
    _parse_exports,
    _parse_imports,
    _read_leb128,
    _read_name,
)
from reporeaver.models import FileEntry, Severity

# --- Helpers ---

def _leb(v: int) -> bytes:
    b = bytearray()
    while True:
        byte = v & 0x7F
        v >>= 7
        if v:
            byte |= 0x80
        b.append(byte)
        if not v:
            break
    return bytes(b)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _leb(len(payload)) + payload


WASM_HEADER = WASM_MAGIC + WASM_VERSION


@pytest.fixture
def entry():
    return FileEntry(
        path="test.wasm", size=100, hash_sha256="aa",
        is_text=False, detected_mime="application/wasm",
    )


class TestShouldAnalyze:
    def test_wasm_extension(self):
        e = FileEntry(path="mod.wasm", size=10, hash_sha256="a", is_text=False)
        assert WasmAnalyzer().should_analyze(e)

    def test_non_wasm_extension(self):
        e = FileEntry(path="mod.txt", size=10, hash_sha256="a", is_text=False)
        assert not WasmAnalyzer().should_analyze(e)

    def test_mime_type(self):
        e = FileEntry(path="mod.bin", size=10, hash_sha256="a", is_text=False,
                      detected_mime="application/wasm")
        assert WasmAnalyzer().should_analyze(e)


class TestWasmHeaderEdgeCases:
    def test_empty_data(self):
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=0, hash_sha256="", is_text=False)
        res = a.analyze_binary(e, b"")
        assert len(res.findings) == 0

    def test_no_magic(self):
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=4, hash_sha256="", is_text=False)
        res = a.analyze_binary(e, b"nope")
        assert len(res.findings) == 0

    def test_magic_only_no_sections(self):
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=8, hash_sha256="", is_text=False)
        res = a.analyze_binary(e, WASM_HEADER)
        assert len(res.findings) == 0

    def test_truncated_header(self):
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=4, hash_sha256="", is_text=False)
        res = a.analyze_binary(e, b"\x00asm")
        assert len(res.findings) == 0


class TestReadLeb128:
    def test_simple(self):
        val, pos = _read_leb128(b"\x05", 0)
        assert val == 5
        assert pos == 1

    def test_multi_byte(self):
        val, pos = _read_leb128(b"\x80\x01", 0)
        assert val == 128
        assert pos == 2

    def test_large(self):
        val, pos = _read_leb128(b"\xff\xff\xff\xff\x0f", 0)
        assert val == 0xFFFFFFFF
        assert pos == 5

    def test_shift_overflow(self):
        val, pos = _read_leb128(b"\x80" * 6, 0)
        assert val is None
        assert pos == 0

    def test_truncated_no_terminator(self):
        val, pos = _read_leb128(b"\x80", 0)
        assert val is None
        assert pos == 0

    def test_empty(self):
        val, pos = _read_leb128(b"", 0)
        assert val is None
        assert pos == 0


class TestReadName:
    def test_normal(self):
        name, pos = _read_name(_leb(3) + b"abc", 0)
        assert name == "abc"
        assert pos == 4

    def test_nlen_none(self):
        name, pos = _read_name(b"\x80", 0)
        assert name == ""

    def test_truncated_body(self):
        name, pos = _read_name(_leb(10) + b"short", 0)
        assert name == ""

    def test_utf8(self):
        raw = _leb(3) + "hé".encode("utf-8")
        name, pos = _read_name(raw, 0)
        assert name == "hé"

    def test_replacement_chars(self):
        raw = _leb(4) + b"\xff\xfe\xfd\xfc"
        name, pos = _read_name(raw, 0)
        assert "\ufffd" in name


class TestParseImports:
    def test_no_import_section(self):
        data = WASM_HEADER + _section(SECTION_FUNC, _leb(0))
        imports = _parse_imports(data)
        assert imports == []

    def test_empty_import_section(self):
        data = WASM_HEADER + _section(SECTION_IMPORT, _leb(0))
        imports = _parse_imports(data)
        assert imports == []

    def test_one_import(self):
        module = _leb(3) + b"env"
        name = _leb(5) + b"print"
        payload = _leb(1) + module + name + bytes([0, 0, 0])  # count=1 + import_kind(1) + type_idx(2)
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        imports = _parse_imports(data)
        assert ("env", "print") in imports

    def test_count_exceeds_limit(self):
        payload = _leb(50001)
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        imports = _parse_imports(data)
        assert imports == []

    def test_count_is_none(self):
        payload = b"\x80\x80\x80\x80\x80\x80"  # overflow
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        imports = _parse_imports(data)
        assert imports == []

    def test_section_size_none(self):
        payload = b"\x80\x80\x80\x80\x80\x80"  # non-terminating LEB128
        section = bytes([SECTION_IMPORT]) + payload
        data = WASM_HEADER + section
        imports = _parse_imports(data)
        assert imports == []

    def test_multiple_imports(self):
        module = _leb(3) + b"env"
        name1 = _leb(5) + b"print"
        name2 = _leb(4) + b"exec"
        payload = _leb(2) + module + name1 + bytes([0, 0, 0]) + module + name2 + bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        imports = _parse_imports(data)
        assert ("env", "print") in imports
        assert ("env", "exec") in imports


class TestParseExports:
    def test_no_export_section(self):
        data = WASM_HEADER + _section(SECTION_FUNC, _leb(0))
        exports = _parse_exports(data)
        assert exports == []

    def test_empty_export_section(self):
        data = WASM_HEADER + _section(SECTION_EXPORT, _leb(0))
        exports = _parse_exports(data)
        assert exports == []

    def test_one_export(self):
        name = _leb(4) + b"main"
        payload = _leb(1) + name + bytes([0, 0])  # export_kind(1) + index(1)
        data = WASM_HEADER + _section(SECTION_EXPORT, payload)
        exports = _parse_exports(data)
        assert "main" in exports

    def test_count_exceeds_limit(self):
        payload = _leb(50001)
        data = WASM_HEADER + _section(SECTION_EXPORT, payload)
        exports = _parse_exports(data)
        assert exports == []

    def test_section_size_none(self):
        payload = b"\x80\x80\x80\x80\x80\x80"
        section = bytes([SECTION_EXPORT]) + payload
        data = WASM_HEADER + section
        exports = _parse_exports(data)
        assert exports == []

    def test_truncated_export_name(self):
        payload = _leb(1) + _leb(100) + b"short"
        data = WASM_HEADER + _section(SECTION_EXPORT, payload)
        exports = _parse_exports(data)
        assert exports == []


class TestAnalyzeBinaryFindings:
    def test_suspicious_env_import(self):
        payload = _leb(1)
        payload += _leb(3) + b"env"
        payload += _leb(21) + b"emscripten_run_script"
        payload += bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        assert any(f.title for f in res.findings if "emscripten_run_script" in f.title)
        assert any(f.severity == Severity.CRITICAL for f in res.findings)

    def test_dangerous_func_finding(self):
        payload = _leb(1)
        payload += _leb(3) + b"env"
        payload += _leb(5) + b"popen"
        payload += bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        titles = [f.title for f in res.findings]
        assert any("popen" in t for t in titles)

    def test_wasi_import_finding(self):
        payload = _leb(1)
        payload += _leb(22) + b"wasi_snapshot_preview1"
        payload += _leb(8) + b"fd_write"
        payload += bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        assert any("fd_write" in f.title for f in res.findings)

    def test_network_import_finding(self):
        payload = _leb(1)
        payload += _leb(3) + b"env"
        payload += _leb(6) + b"socket"
        payload += bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        assert any("socket" in f.title for f in res.findings)

    def test_both_exec_and_network_capability_summary(self):
        payload = _leb(2)
        payload += _leb(3) + b"env" + _leb(5) + b"popen" + bytes([0, 0, 0])
        payload += _leb(3) + b"env" + _leb(6) + b"socket" + bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        titles = [f.title for f in res.findings]
        assert any("code execution" in t for t in titles)
        assert any("network capabilities" in t for t in titles)

    def test_benign_import_no_findings(self):
        payload = _leb(1)
        payload += _leb(3) + b"env"
        payload += _leb(6) + b"memory"
        payload += bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        assert len(res.findings) == 0

    def test_unknown_module_no_findings(self):
        payload = _leb(1)
        payload += _leb(6) + b"custom"
        payload += _leb(5) + b"hello"
        payload += bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        assert len(res.findings) == 0

    def test_wasi_unstable_import(self):
        payload = _leb(1)
        payload += _leb(13) + b"wasi_unstable"
        payload += _leb(7) + b"fd_read"
        payload += bytes([0, 0, 0])
        data = WASM_HEADER + _section(SECTION_IMPORT, payload)
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=len(data), hash_sha256="a", is_text=False)
        res = a.analyze_binary(e, data)
        assert any("fd_read" in f.title for f in res.findings)


class TestAnalyzeTextFallback:
    def test_text_analyze_returns_empty(self):
        a = WasmAnalyzer()
        e = FileEntry(path="x.wasm", size=10, hash_sha256="a", is_text=False)
        res = a.analyze(e, "content")
        assert len(res.findings) == 0
