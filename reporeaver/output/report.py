"""Human-readable report output."""

import json
import sys
from typing import List

from ..models import Finding, ScanResult, Severity, SEVERITY_ORDER
from ..utils.text import trunc


def _safe_print(*args, **kwargs):
    """Print with encoding fallback for Windows consoles."""
    text = " ".join(str(a) for a in args)
    try:
        print(text, **kwargs)
    except (UnicodeEncodeError, UnicodeError):
        enc = sys.stdout.encoding if sys.stdout.encoding and sys.stdout.encoding != "cp65001" else "utf-8"
        try:
            safe = text.encode(enc, errors="replace").decode(enc, errors="replace")
            print(safe, **kwargs)
        except (UnicodeError, LookupError):
            safe = text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
            print(safe, **kwargs)


def print_report(result: ScanResult, verbose: bool = False, json_output: bool = False):
    if json_output:
        print(json.dumps(result.to_dict(), indent=2))
        return

    rs = result.risk_score
    if not result.findings:
        _safe_print(f"\n  {'='*60}")
        _safe_print(f"  REPOREAVER SCAN COMPLETE - NO ISSUES DETECTED")
        _safe_print(f"  {result.target}")
        _safe_print(f"  Files scanned: {result.files_scanned}")
        _safe_print(f"  Risk score: {rs.score if rs else 0}/10")
        _safe_print(f"  {'='*60}\n")
        return

    _safe_print(f"\n  {'='*60}")
    _safe_print(f"  REPOREAVER - SECURITY GATE REPORT")
    _safe_print(f"  Target: {result.target}")
    _safe_print(f"  Time: {result.scan_time}")
    _safe_print(f"  {'='*60}")

    if rs:
        _safe_print(f"\n  RISK SCORE: {rs.score:.1f} / 10.0  ({rs.max_severity.value})")
        _safe_print(f"  {rs.critical} critical, {rs.high} high, {rs.medium} medium, {rs.low} low")
        _safe_print(f"  Total findings: {rs.total}")

    by_severity = _group_by_severity(result.findings)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        group = by_severity.get(sev, [])
        if not group:
            continue
        if sev == Severity.MEDIUM and not verbose:
            continue

        _safe_print(f"\n  {'-'*60}")
        _safe_print(f"  {sev.value.upper()} FINDINGS ({len(group)})")
        _safe_print(f"  {'-'*60}")

        for f in group:
            _print_finding(f)
            _safe_print("")

    _safe_print(f"  {'='*60}")
    _safe_print(f"  Scan complete. Risk score: {rs.score if rs else 0}/10")
    _safe_print(f"  {'='*60}\n")


def _group_by_severity(findings: List[Finding]) -> dict:
    groups = {}
    for f in findings:
        groups.setdefault(f.severity, []).append(f)
    for sev in groups:
        groups[sev].sort(key=lambda x: (x.file_path or "", x.line_number or 0))
    return groups


def _print_finding(f: Finding):
    loc = f"  File: {f.file_path}"
    if f.line_number:
        loc += f", line {f.line_number}"

    _safe_print(f"  [!] {f.title}")
    _safe_print(loc)
    _safe_print(f"  Confidence: {f.confidence.value}")

    if f.description:
        _safe_print(f"  Detail: {f.description}")
    if f.attack_path:
        _safe_print(f"  Attack chain: {f.attack_path}")
    if f.remediation:
        _safe_print(f"  Fix: {f.remediation}")
    if f.decoded:
        _safe_print(f"  Decoded content: {trunc(f.decoded, 300)}")
    if f.snippet:
        _safe_print(f"  Context: {trunc(f.snippet, 300)}")


