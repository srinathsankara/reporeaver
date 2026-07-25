"""Scanning engine — orchestrates ingest, analysis, scoring, and output."""

import concurrent.futures
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

log = logging.getLogger("reporeaver.engine")

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
from .analyzers.secrets_analyzer import SecretsAnalyzer
from .analyzers.cargo_analyzer import CargoAnalyzer
from .analyzers.python_analyzer import PythonAnalyzer
from .analyzers.dockerfile_analyzer import DockerfileAnalyzer
from .analyzers.wasm_analyzer import WasmAnalyzer
from .analyzers.yara_analyzer import YaraAnalyzer
from .ingest.single import SingleFileIngester, DirectoryIngester, ArchiveIngester
from .models import Category, Confidence, FileEntry, Finding, RiskScore, ScanResult, Severity
from .output.report import print_report
from .output.sarif import render_sarif
from .output.html_dashboard import render_html
from .policy import Policy, load_policy

CACHE_DIR = Path.home() / ".reporeaver" / "cache"


def _register_builtins():
    for cls in [
        SVGVectorAnalyzer, UnicodeAnalyzer, ScriptAnalyzer,
        DepAnalyzer, WorkflowAnalyzer, EntropyAnalyzer,
        URLNetworkAnalyzer, MimeDeceptionAnalyzer, BehavioralAnalyzer,
        SecretsAnalyzer, CargoAnalyzer, PythonAnalyzer,
        DockerfileAnalyzer, WasmAnalyzer, YaraAnalyzer,
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
    diff_mode: bool = False,
    no_cache: bool = False,
) -> int:
    """Run full scan pipeline against a target path.

    Supports:
      - diff-mode: only scan files changed vs origin/main
      - caching: skip files whose SHA-256 hasn't changed since last scan
      - progress bar: prints a running tally as files are analyzed
    """
    from .logging import get_logger
    get_logger()  # init file logging

    start = time.time()
    target_path = Path(target)

    if not target_path.exists():
        print(f"Error: '{target}' does not exist", file=sys.stderr)
        return 1

    print(f"\n  RepoReaver v0.2.0 — Security Gate Scan")
    print(f"  Target: {target}")
    if diff_mode:
        print(f"  Mode: diff (only changed files)")
    print(f"{'-'*60}")

    # Select ingester and discover files
    ingester = _select_ingester(target_path)
    ingest_result = ingester.ingest(str(target_path.absolute()))
    print(f"  Files discovered: {ingest_result.total_files} ({_fmt_size(ingest_result.total_size)})")

    # If diff mode, filter to only changed files vs origin/main
    if diff_mode:
        changed_files = _git_changed_files(target_path)
        if changed_files is not None:
            before = ingest_result.total_files
            ingest_result.files = [f for f in ingest_result.files
                                    if f.path in changed_files]
            print(f"  Diff filter: {before} -> {ingest_result.total_files} files")
        else:
            print(f"  (not a git repo or no diff available — scanning all files)")

    cache_enabled = not no_cache and ingest_result.total_files > 10
    if cache_enabled:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _prune_cache()

    # Load analyzers
    skip_set = set(skip_analyzers or [])
    analyzers = _load_analyzers(skip_set)
    text_analyzers = [a for a in analyzers if not hasattr(a, "analyze_binary") or
                      type(a).analyze_binary is BaseAnalyzer.analyze_binary]
    binary_analyzers = [a for a in analyzers if hasattr(a, "analyze_binary") and
                        type(a).analyze_binary is not BaseAnalyzer.analyze_binary]

    print(f"  Analyzers loaded: {len(analyzers)} ({len(text_analyzers)} text, {len(binary_analyzers)} binary)")
    print(f"  Cache: {'enabled' if cache_enabled else 'disabled'}")

    all_findings: List[Finding] = []
    skipped_cache = 0
    files_analyzed = 0
    total_jobs = ingest_result.total_files

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}

        for entry in ingest_result.files:
            # Check cache first
            if cache_enabled and entry.hash_sha256:
                cached = _load_cache(entry.hash_sha256)
                if cached is not None:
                    all_findings.extend(cached)
                    skipped_cache += 1
                    continue

            # Read content
            content = ""
            raw_bytes = b""
            try:
                if entry.is_text or entry.size < max_size_mb * 1024 * 1024 * 2:
                    full = target_path / entry.path
                    if full.exists() and full.stat().st_size <= max_size_mb * 1024 * 1024:
                        content = full.read_text(encoding="utf-8", errors="replace")
                        raw_bytes = content.encode("utf-8", errors="replace")
            except Exception as exc:
                log.debug("File read error %s: %s", entry.path, exc)

            # Submit per-file analysis jobs (one per file, all applicable analyzers run inline)
            fut = pool.submit(_analyze_file, entry, content, raw_bytes, text_analyzers, binary_analyzers)
            futures[fut] = entry

        # Process results
        for fut in concurrent.futures.as_completed(futures):
            entry = futures[fut]
            files_analyzed += 1
            try:
                entry_findings, entry_hash = fut.result()
                all_findings.extend(entry_findings)
                if cache_enabled and entry_hash:
                    _save_cache(entry_hash, entry_findings)
            except Exception as e:
                all_findings.append(Finding(
                    file_path=entry.path,
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    category=Category.PARSE_ERROR,
                    title=f"Analysis failed for {entry.path}",
                    description=str(e),
                ))

            # Show progress every 50 files
            if files_analyzed % 50 == 0 or files_analyzed == total_jobs:
                print(f"  Progress: {files_analyzed}/{total_jobs} files "
                      f"({len(all_findings)} findings so far)...")

    if skipped_cache:
        print(f"  Cache hits: {skipped_cache} files skipped (unchanged since last scan)")

    # Policy evaluation
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

    # Output phase
    if html_output:
        render_html(result, html_output)
        print(f"  HTML dashboard: {html_output}")

    if sarif_output:
        sarif_doc = render_sarif(result)
        with open(sarif_output, "w") as f:
            json.dump(sarif_doc, f, indent=2)
        print(f"  SARIF output: {sarif_output}")

    if output_file:
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
        except Exception as exc:
            log.warning("Failed to save scan history: %s", exc)

    return 1 if risk.score >= 7.0 else 0


def _analyze_file(entry: FileEntry, content: str, raw: bytes,
                  text_analyzers: list, binary_analyzers: list) -> Tuple:
    """Run all applicable analyzers against one file. Used as a pool worker."""
    all_findings: List[Finding] = []

    if content:
        for a in text_analyzers:
            if not a.should_analyze(entry):
                continue
            try:
                res = a.analyze(entry, content)
                all_findings.extend(res.findings)
            except Exception as exc:
                log.debug("Analyzer %s failed on %s: %s", a.name, entry.path, exc)

    if raw and binary_analyzers:
        for a in binary_analyzers:
            try:
                res = a.analyze_binary(entry, raw)
                all_findings.extend(res.findings)
            except Exception as exc:
                log.debug("Binary analyzer %s failed on %s: %s", a.name, entry.path, exc)

    return (all_findings, entry.hash_sha256)


def _git_changed_files(repo_path: Path) -> Optional[set]:
    """Get list of files changed vs origin/main. Returns None if not a git repo."""
    try:
        # Check if it's a git repo
        subprocess.run(["git", "rev-parse", "--git-dir"],
                       cwd=repo_path, capture_output=True, timeout=5, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    try:
        # Try to get diff against a known base
        result = subprocess.run(
            ["git", "diff", "--name-only", "origin/main...HEAD", "--"],
            cwd=repo_path, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return set(line.strip() for line in result.stdout.splitlines() if line.strip())

        # Fallback: diff against HEAD
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD", "--"],
            cwd=repo_path, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return set(line.strip() for line in result.stdout.splitlines() if line.strip())
    except Exception as exc:
        log.debug("Git diff origin/main...HEAD failed: %s", exc)

    # If origin/main doesn't exist (new branch), return unstaged changes
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD", "--"],
            cwd=repo_path, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return set(line.strip() for line in result.stdout.splitlines() if line.strip())
    except Exception as exc:
        log.debug("Git diff HEAD failed: %s", exc)

    return None


def _select_ingester(path: Path):
    if path.is_file():
        if path.suffix.lower() in (".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".rar", ".7z"):
            return ArchiveIngester()
        return SingleFileIngester()
    return DirectoryIngester()


def _load_analyzers(skip_set: set) -> List[BaseAnalyzer]:
    from .analyzers.base import _analyzer_registry
    loaded = []
    for name, cls in sorted(_analyzer_registry.items(),
                            key=lambda x: getattr(x[1], "priority", 50)):
        if name in skip_set:
            continue
        loaded.append(cls())
    return loaded


def _load_cache(hash_key: str) -> Optional[List[Finding]]:
    """Load cached findings for a file hash. Returns None if no cache hit."""
    cache_file = CACHE_DIR / f"{hash_key}.json"
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        return [Finding(**f) for f in data]
    except Exception as exc:
        log.debug("Cache load failed for %s: %s", hash_key[:16], exc)
        return None


def _save_cache(hash_key: str, findings: List[Finding]):
    """Cache findings for a file hash."""
    cache_file = CACHE_DIR / f"{hash_key}.json"
    try:
        cache_file.write_text(
            json.dumps([f.to_dict() for f in findings], default=str),
            encoding="utf-8",
        )
    except Exception as exc:
        log.debug("Cache save failed for %s: %s", hash_key[:16], exc)


def _prune_cache(max_entries: int = 10000):
    """Remove old cache entries if cache exceeds max_entries."""
    try:
        entries = sorted(CACHE_DIR.iterdir(), key=lambda p: p.stat().st_mtime)
        while len(entries) > max_entries:
            entries[0].unlink()
            entries = entries[1:]
    except Exception as exc:
        log.debug("Cache prune error: %s", exc)


def _fmt_size(b: int) -> str:
    for unit in ("B", "KB", "MB"):
        if b < 1024:
            return f"{b:.0f}{unit}"
        b /= 1024
    return f"{b:.1f}GB"
