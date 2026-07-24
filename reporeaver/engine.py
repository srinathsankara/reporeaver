"""Scanning engine — orchestrates ingest, analysis, scoring, and output."""

import concurrent.futures
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Type

from .analyzers import BaseAnalyzer, all_analyzers
from .analyzers.svg_analyzer import SVGVectorAnalyzer
from .analyzers.unicode_analyzer import UnicodeAnalyzer
from .analyzers.script_analyzer import ScriptAnalyzer
from .analyzers.dep_analyzer import DepAnalyzer
from .analyzers.workflow_analyzer import WorkflowAnalyzer
from .analyzers.entropy_analyzer import EntropyAnalyzer
from .analyzers.url_analyzer import URLNetworkAnalyzer
from .analyzers.mime_analyzer import MimeDeceptionAnalyzer
from .analyzers.behavioral_analyzer import BehavioralAnalyzer
from .ingest.single import SingleFileIngester, DirectoryIngester, ArchiveIngester
from .models import FileEntry, Finding, RiskScore, ScanResult, Severity
from .output.report import print_report
from .output.sarif import render_sarif
from .output.html_dashboard import render_html
from .policy import Policy, load_policy


def _register_builtins():
    for cls in [
        SVGVectorAnalyzer, UnicodeAnalyzer, ScriptAnalyzer,
        DepAnalyzer, WorkflowAnalyzer, EntropyAnalyzer,
        URLNetworkAnalyzer, MimeDeceptionAnalyzer, BehavioralAnalyzer,
    ]:
        from .analyzers.base import _analyzer_registry
        name = getattr(cls, "name", cls.__name__)
        _analyzer_registry[name] = cls


_register_builtins()


def scan_target(
    target: str,
    verbose: bool = False,
    json_output: bool = False,
    sarif_output: Optional[str] = None,
    html_output: Optional[str] = None,
    output_file: Optional[str] = None,
    policy_path: Optional[str] = None,
    max_size_mb: float = 2.0,
    skip_analyzers: Optional[List[str]] = None,
    max_workers: int = 4,
    save_history: bool = True,
) -> int:
    """Run full scan pipeline against a target path.

    Returns exit code (0 = pass, 1 = fail/critical).
    """
    start = time.time()
    target_path = Path(target)

    if not target_path.exists():
        print(f"Error: '{target}' does not exist", file=sys.stderr)
        return 1

    print(f"\n  RepoReaver v0.2.0 — Security Gate Scan")
    print(f"  Target: {target}")
    print(f"{'-'*60}")

    ingester = _select_ingester(target_path)
    ingest_result = ingester.ingest(str(target_path.absolute()))
    print(f"  Files discovered: {ingest_result.total_files} ({_fmt_size(ingest_result.total_size)})")

    skip_set = set(skip_analyzers or [])
    analyzers = _load_analyzers(skip_set)
    print(f"  Analyzers loaded: {len(analyzers)}")

    all_findings: List[Finding] = []
    files_analyzed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for entry in ingest_result.files:
            try:
                content = _read_content(entry, target_path, max_size_mb)
            except Exception:
                continue

            for analyzer in analyzers:
                if not analyzer.should_analyze(entry):
                    continue
                fut = pool.submit(analyzer.analyze, entry, content)
                futures[fut] = (analyzer, entry)

        for fut in concurrent.futures.as_completed(futures):
            analyzer, entry = futures[fut]
            files_analyzed += 1
            try:
                result = fut.result()
                all_findings.extend(result.findings)
            except Exception as e:
                all_findings.append(Finding(
                    file_path=entry.path,
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    category=Category.PARSE_ERROR,
                    title=f"Analyzer '{analyzer.name}' failed",
                    description=str(e),
                ))

    policy = load_policy(policy_path) if policy_path else Policy()
    policy_findings = policy.evaluate(all_findings)
    all_findings.extend(policy_findings)

    risk = RiskScore.compute(all_findings)

    result = ScanResult(
        target=target,
        files_scanned=ingest_result.total_files,
        findings=all_findings,
        risk_score=risk,
    )

    elapsed = time.time() - start

    if html_output:
        render_html(result, html_output)
        print(f"  HTML dashboard: {html_output}")

    if sarif_output:
        sarif_doc = render_sarif(result)
        import json
        with open(sarif_output, "w") as f:
            json.dump(sarif_doc, f, indent=2)
        print(f"  SARIF output: {sarif_output}")

    if output_file:
        import json
        with open(output_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"  JSON report: {output_file}")

    print_report(result, verbose=verbose, json_output=json_output)
    print(f"  Scan completed in {elapsed:.1f}s")
    print(f"{'-'*60}\n")

    if save_history:
        try:
            from .history import save_scan
            save_scan(
                target=target,
                scan_time=result.scan_time,
                duration_ms=int(elapsed * 1000),
                files_count=ingest_result.total_files,
                risk_score=risk.score,
                max_sev=risk.max_severity.value,
                critical=risk.critical,
                high=risk.high,
                medium=risk.medium,
                low=risk.low,
                findings=result.to_dict().get("findings", []),
                sarif_path=sarif_output,
                html_path=html_output,
            )
        except Exception:
            pass  # history is a nice-to-have, don't fail the scan

    return 1 if risk.score >= 7.0 else 0


def _select_ingester(path: Path):
    if path.is_file():
        if path.suffix.lower() in (".zip", ".tar", ".tar.gz", ".tgz", ".gz"):
            return ArchiveIngester()
        return SingleFileIngester()
    return DirectoryIngester()


def _load_analyzers(skip_set: set) -> List[BaseAnalyzer]:
    from .analyzers.base import _analyzer_registry
    loaded = []
    for name, cls in sorted(_analyzer_registry.items(), key=lambda x: getattr(x[1], "priority", 50)):
        if name in skip_set:
            continue
        loaded.append(cls())
    return loaded


def _read_content(entry: FileEntry, root: Path, max_size_mb: float) -> str:
    full = root / entry.path
    if not full.exists() or full.stat().st_size > max_size_mb * 1024 * 1024:
        return ""
    return full.read_text(encoding="utf-8", errors="replace")


def _fmt_size(b: int) -> str:
    for unit in ("B", "KB", "MB"):
        if b < 1024:
            return f"{b:.0f}{unit}"
        b /= 1024
    return f"{b:.1f}GB"
