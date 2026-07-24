"""Main scanner orchestrator — coordinates all scanner modules."""

import concurrent.futures
import os
import sys
from pathlib import Path
from typing import List, Optional

from .scanners.svg_scanner import scan_svg_file
from .scanners.script_scanner import scan_file as scan_script_file
from .scanners.entropy_scanner import (
    EntropyFinding,
    collect_targets,
    scan_entropy_in_file,
)
from .scanners.url_scanner import scan_urls_in_text
from .scanners.dep_graph import analyze_postinstall_chains, find_obscure_deps
from .scanners.report import aggregate_findings, print_report, save_json_report


EXCLUDE_DIRS = {
    "node_modules", ".git", "__pycache__", ".next", "dist",
    "build", "target", "vendor", ".venv", "venv", "env",
    ".vscode", ".idea", "coverage", ".gitlab", ".github",
}

MAX_WORKERS = 8


def scan_repository(
    repo_path: str,
    verbose: bool = False,
    json_output: bool = False,
    output_file: Optional[str] = None,
    max_size_mb: float = 1.0,
    skip_entropy: bool = False,
) -> int:
    """Run all scanners against a repository directory.

    Returns exit code (0 = clean, 1 = findings).
    """
    root = Path(repo_path).resolve()
    if not root.is_dir():
        print(f"Error: '{repo_path}' is not a directory", file=sys.stderr)
        return 1

    print(f"Scanning repository: {root}")
    print(f"{'-'*60}")

    all_findings = []

    svg_findings = _scan_svg_files(root)
    all_findings.extend(svg_findings)
    print(f"  SVG files scanned: {len(svg_findings)} issues found")

    script_files = _collect_script_files(root)
    for sf in script_files:
        sfindings = scan_script_file(sf)
        all_findings.extend(sfindings)
    script_count = len(script_files)
    print(f"  Script/config files scanned: {script_count} files, "
          f"{sum(1 for f in all_findings if f not in svg_findings)} issues")

    dep_findings = analyze_postinstall_chains(root)
    dep_findings += find_obscure_deps(root)
    all_findings.extend(dep_findings)
    print(f"  Dependency analysis: {len(dep_findings)} issues found")

    if not skip_entropy:
        entropy_findings = _scan_entropy(root, max_size_mb)
        all_findings.extend(entropy_findings)
        print(f"  Entropy analysis: {len(entropy_findings)} issues found")

    url_findings = _scan_urls(root, max_size_mb)
    all_findings.extend(url_findings)
    print(f"  URL analysis: {len(url_findings)} issues found")

    all_findings = aggregate_findings(all_findings)

    if output_file:
        save_json_report(all_findings, output_file)
    else:
        print_report(all_findings, verbose=verbose, json_output=json_output)

    critical_count = sum(1 for f in all_findings if f.severity == "critical")
    return 1 if critical_count > 0 else 0


def _scan_svg_files(root: Path) -> List:
    findings = []
    svg_files = list(root.rglob("*.svg"))
    for svg_path in svg_files:
        if any(excl in svg_path.parts for excl in EXCLUDE_DIRS):
            continue
        findings.extend(scan_svg_file(svg_path))
    return findings


def _collect_script_files(root: Path) -> List[Path]:
    targets = []
    for name in ("package.json", "Makefile", "Dockerfile", "dockerfile"):
        for p in root.rglob(name):
            if any(excl in p.parts for excl in EXCLUDE_DIRS):
                continue
            targets.append(p)
    return targets


def _scan_entropy(root: Path, max_size_mb: float) -> List[EntropyFinding]:
    findings = []
    targets = collect_targets(root, max_size_mb)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_path = {
            executor.submit(scan_entropy_in_file, p): p for p in targets
        }
        for future in concurrent.futures.as_completed(future_to_path):
            try:
                findings.extend(future.result())
            except Exception:
                pass

    return findings


def _scan_urls(root: Path, max_size_mb: float) -> List:
    findings = []
    from .scanners.entropy_scanner import collect_targets

    targets = collect_targets(root, max_size_mb)
    for p in targets:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        findings.extend(scan_urls_in_text(text, str(p)))

    return findings
