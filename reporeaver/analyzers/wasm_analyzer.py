"""WASM analyzer — inspects WebAssembly binaries for suspicious imports and behavior."""

import struct
from typing import Dict, List, Optional, Set

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

# WASM magic: \0asm (0x00 0x61 0x73 0x6D)
WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"

# Known section IDs
SECTION_FUNC = 3
SECTION_IMPORT = 2
SECTION_EXPORT = 7

# Suspicious import module names
SUSPICIOUS_IMPORTS: Dict[str, Set[str]] = {
    "wasi_snapshot_preview1": {"fd_write", "fd_read", "proc_exit", "environ_get",
                                "environ_sizes_get", "args_get", "args_sizes_get"},
    "env": {"emscripten_run_script", "emscripten_async_run_script", "system",
            "popen", "execve", "fork", "sbrk"},
    "wasi_unstable": {"fd_write", "fd_read", "proc_exit"},
}

HIGH_RISK_IMPORTS = {
    "emscripten_run_script", "emscripten_async_run_script",
    "system", "popen", "execve", "dlopen", "dlsym",
}

NETWORK_IMPORTS = {"connect", "send", "recv", "socket", "bind", "listen", "accept"}


@register_analyzer
class WasmAnalyzer(BaseAnalyzer):
    name = "wasm_analyzer"
    description = "WebAssembly binary analysis: suspicious imports, capabilities, risk assessment"
    priority = 48

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        return name.endswith(".wasm") or entry.detected_mime == "application/wasm"

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        return AnalyzerResult([])

    def analyze_binary(self, entry: FileEntry, data: bytes) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path

        if not data.startswith(WASM_MAGIC):
            return AnalyzerResult(findings)

        # Basic module info
        version = data[4:8]
        if version == WASM_VERSION:
            pass  # valid v1

        imports = _parse_imports(data)
        exports = _parse_exports(data)

        # Check for suspicious imports
        import_names = {f"{m}.{n}" for m, n in imports}
        has_network = False
        has_exec = False

        for module, name in imports:
            mod_suspicious = SUSPICIOUS_IMPORTS.get(module, set())
            if name in mod_suspicious or name in HIGH_RISK_IMPORTS:
                has_exec = True
                findings.append(Finding(
                    path, Severity.CRITICAL, Confidence.HIGH, Category.SUSPICIOUS_JS_API,
                    title=f"WASM imports dangerous function: {module}.{name}",
                    description=f"WebAssembly binary imports '{module}.{name}' — "
                                f"can execute native/system calls from WASM sandbox.",
                    attack_path="WASM loaded -> dangerous import called -> sandbox escape / code execution",
                    remediation="Review WASM module source. Remove unsafe imports if possible.",
                    raw_value=f"{module}.{name}",
                ))
            if name in NETWORK_IMPORTS:
                has_network = True
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.BEHAVIORAL_NETWORK,
                    title=f"WASM imports networking function: {module}.{name}",
                    description=f"WASM binary imports '{module}.{name}' — can make network calls.",
                    attack_path="WASM loaded -> network call to C2 -> data exfiltration",
                    remediation="Audit WASM module for unauthorized network activity.",
                    raw_value=f"{module}.{name}",
                ))

        if has_exec:
            findings.append(Finding(
                path, Severity.CRITICAL, Confidence.HIGH, Category.BEHAVIORAL_EXEC,
                title="WASM module has code execution capabilities",
                description="WebAssembly binary imports functions that enable arbitrary code execution.",
                attack_path="WASM loaded -> code execution -> system compromise",
                remediation="Treat this WASM module as untrusted. Sandbox its execution.",
            ))

        if has_network:
            findings.append(Finding(
                path, Severity.HIGH, Confidence.MEDIUM, Category.BEHAVIORAL_NETWORK,
                title="WASM module has network capabilities",
                description="WebAssembly binary imports network functions — may phone home or download payloads.",
                attack_path="WASM loaded -> network connection -> C2 communication",
                remediation="Review WASM network destinations. Block if unexpected.",
            ))

        return AnalyzerResult(findings)


def _parse_imports(data: bytes) -> List[tuple]:
    """Parse WASM import section (section ID 2) to extract (module, name) pairs."""
    imports: List[tuple] = []
    pos = 8  # skip magic + version

    while pos < len(data):
        if pos + 1 > len(data):
            break
        section_id = data[pos]
        pos += 1
        if pos + 5 > len(data):
            break
        section_size = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4

        if section_id == SECTION_IMPORT:
            if pos + 4 > len(data):
                break
            count = struct.unpack("<I", data[pos:pos+4])[0]
            pos += 4
            for _ in range(count):
                module, pos = _read_name(data, pos)
                name, pos = _read_name(data, pos)
                if module and name:
                    imports.append((module, name))
                # Skip the import kind byte and type index
                if pos < len(data):
                    pos += 3  # kind(1) + type_idx(2)
        else:
            pos += section_size  # skip non-import sections

    return imports


def _parse_exports(data: bytes) -> List[str]:
    """Parse WASM export section (section ID 7) to extract export names."""
    exports: List[str] = []
    pos = 8

    while pos < len(data):
        if pos + 1 > len(data):
            break
        section_id = data[pos]
        pos += 1
        if pos + 5 > len(data):
            break
        section_size = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4

        if section_id == SECTION_EXPORT:
            if pos + 4 > len(data):
                break
            count = struct.unpack("<I", data[pos:pos+4])[0]
            pos += 4
            for _ in range(count):
                name, pos = _read_name(data, pos)
                if name:
                    exports.append(name)
                if pos < len(data):
                    pos += 2  # export kind(1) + index(1)
        else:
            pos += section_size

    return exports


def _read_name(data: bytes, pos: int) -> tuple:
    """Read a WASM-encoded name (length-prefixed UTF-8 string)."""
    if pos + 4 > len(data):
        return ("", pos)
    nlen = struct.unpack("<I", data[pos:pos+4])[0]
    pos += 4
    if pos + nlen > len(data):
        return ("", pos)
    name = data[pos:pos+nlen].decode("utf-8", errors="replace")
    pos += nlen
    return (name, pos)
