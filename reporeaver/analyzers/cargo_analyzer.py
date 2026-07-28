"""Cargo/Rust analyzer — checks build.rs, Cargo.toml for build-time code execution risks."""

import configparser
import io
import logging
import re
from typing import List

log = logging.getLogger("reporeaver.cargo")

from ..models import Category, Confidence, FileEntry, Finding, Severity
from ..utils.text import trunc, line_of
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer


@register_analyzer
class CargoAnalyzer(BaseAnalyzer):
    name = "cargo"
    description = "Rust/Cargo build script analysis: build.rs, Cargo.toml dependency risks"
    priority = 28

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        return name in ("cargo.toml", "build.rs")

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        name = entry.path.rsplit("/", 1)[-1].lower()
        if name == "cargo.toml":
            return _check_cargo_toml(content, entry.path)
        return _check_build_rs(content, entry.path)


def _check_cargo_toml(content: str, path: str) -> AnalyzerResult:
    findings: List[Finding] = []

    try:
        cfg = configparser.ConfigParser()
        cfg.read_string(content)
    except Exception as exc:
        log.debug("configparser failed on TOML (expected), falling back to regex: %s", exc)

    # Check for git dependencies (unpinned)
    for match in re.finditer(r'(?:git|repository)\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE):
        url = match.group(1)
        findings.append(Finding(
            path, Severity.MEDIUM, Confidence.LOW, Category.SUSPICIOUS_DEPENDENCY,
            title=f"Cargo dependency from git: {trunc(url, 80)}",
            description=f"Cargo.toml references git repository '{url}' — unpinned dependency.",
            attack_path="cargo build -> fetches from git -> mutable reference -> supply-chain risk",
            remediation="Pin to a specific commit SHA or use crates.io version.",
            line_number=line_of(content, match.start()), raw_value=url,
        ))

    # Check for build scripts
    if re.search(r'build\s*=\s*["\']build\.rs["\']', content):
        findings.append(Finding(
            path, Severity.INFO, Confidence.HIGH, Category.LIFECYCLE_HOOK,
            title="Cargo.toml has build script (build.rs)",
            description="Cargo will compile and run build.rs during build. It has full system access.",
            attack_path="cargo build -> build.rs compiles + runs -> arbitrary code during build",
            remediation="Review build.rs for suspicious operations.",
        ))

    # Check for procedural macros (code gen at compile time)
    for match in re.finditer(r'(?:proc-macro|proc_macro)\s*=\s*true', content):
        findings.append(Finding(
            path, Severity.INFO, Confidence.LOW, Category.INFO,
            title="Cargo.toml defines a proc-macro crate",
            description="Procedural macros execute arbitrary code at compile time.",
            attack_path="cargo build -> proc-macro code executes -> compile-time compromise",
            remediation="Audit the proc-macro crate thoroughly.",
            line_number=line_of(content, match.start()),
        ))

    return AnalyzerResult(findings)


def _check_build_rs(content: str, path: str) -> AnalyzerResult:
    findings: List[Finding] = []

    suspicious_build_patterns = [
        (r'(?:std::process::Command|Command::new|std::process::Stdio)', Severity.HIGH,
         "External command execution in build.rs"),
        (r'(?:cc::Build|cmake|autotools|pkg_config)', Severity.MEDIUM,
         "C/C++ code compilation in build script"),
        (r'(?:fs::write|fs::copy|fs::rename|std::fs::File::create)', Severity.MEDIUM,
         "File system write in build script"),
        (r'(?:download|url|http|https|reqwest|curl_easy)', Severity.HIGH,
         "Network request in build script — possible C2/downloader"),
        (r'(?:env::var|env::set_var)', Severity.LOW,
         "Environment variable access in build script"),
        (r'(?:include_bytes!|include_str!)', Severity.LOW,
         "Compile-time file inclusion — may embed payloads"),
        (r'(?:unreachable|unsafe\s*\{)', Severity.MEDIUM,
         "Unsafe code in build script — increased risk"),
        (r'(?:std::os|libc)', Severity.MEDIUM,
         "OS-level system calls in build script"),
    ]

    for pat, severity, desc in suspicious_build_patterns:
        for match in re.finditer(pat, content):
            findings.append(Finding(
                path, severity, Confidence.MEDIUM, Category.SUSPICIOUS_COMMAND,
                title=desc,
                description=f"build.rs uses '{trunc(match.group(0), 80)}' — this runs during cargo build.",
                attack_path="cargo build -> build.rs executes -> system access",
                remediation="Review build.rs. Remove unnecessary operations.",
                line_number=line_of(content, match.start()),
                snippet=trunc(content[max(0, match.start()-20):match.end()+40], 150),
            ))

    return AnalyzerResult(findings)



