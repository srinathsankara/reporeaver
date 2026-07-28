"""Scan pipeline — orchestrates ingestion, analysis, caching, policy, output."""

import hashlib
import json
import logging
import os
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .analyzers.base import BaseAnalyzer, discover_analyzers
from .config import RepoReaverConfig
from .ingest import select_ingester
from .models import FileEntry, Finding, ScanResult, RiskScore
from .policy import evaluate_policy

log = logging.getLogger("reporeaver.pipeline")

MAX_CACHE_ENTRIES = 1000
PROGRESS_INTERVAL = 50
EXIT_THRESHOLD = 7.0


def _read_entry(entry: FileEntry, target_dir: Path, max_size_mb: int) -> Tuple[str, bytes]:
    """Read a file from disk, returning (content, raw_bytes) or ("", b"")."""
    content = ""
    raw_bytes = b""
    try:
        full = (target_dir / entry.path).resolve()
        full.relative_to(target_dir.resolve())
        if full.exists():
            st = full.stat()
            if st.st_size <= max_size_mb * 1024 * 1024:
                with open(str(full), "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                raw_bytes = content.encode("utf-8", errors="replace")
            else:
                log.debug("Skipping large file (%d bytes): %s", st.st_size, entry.path)
    except (ValueError, OSError) as exc:
        log.warning("File read error %s: %s", entry.path, exc)
    return content, raw_bytes


def _analyze_file(entry: FileEntry, content: str, raw: bytes,
                  text_analyzers: list, binary_analyzers: list) -> Tuple[List[Finding], int]:
    """Run all applicable analyzers against one file. Returns (findings, error_count)."""
    findings: List[Finding] = []
    errors = 0

    if content:
        for a in text_analyzers:
            if not a.should_analyze(entry):
                continue
            try:
                res = a.analyze(entry, content)
                findings.extend(res.findings)
            except Exception as exc:
                log.warning("Analyzer %s failed on %s: %s", a.name, entry.path, exc, exc_info=True)
                errors += 1

    if raw and binary_analyzers:
        for a in binary_analyzers:
            try:
                res = a.analyze_binary(entry, raw)
                findings.extend(res.findings)
            except Exception as exc:
                log.warning("Binary analyzer %s failed on %s: %s", a.name, entry.path, exc, exc_info=True)
                errors += 1

    return findings, errors


class CacheManager:
    """Manages result caching to skip re-analysis of unchanged files."""

    def __init__(self, cache_dir: Path):
        self._cache_dir = cache_dir

    def _cache_key(self, entry: FileEntry) -> str:
        return hashlib.sha256(
            f"{entry.path}:{entry.size}:{entry.hash_sha256 or ''}".encode()
        ).hexdigest()

    def get(self, entry: FileEntry) -> Optional[List[Dict]]:
        cache_path = self._cache_dir / self._cache_key(entry)
        if cache_path.exists():
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return None

    def set(self, entry: FileEntry, findings: List[Finding]):
        cache_path = self._cache_dir / self._cache_key(entry)
        tmp = cache_path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump([f.to_dict() for f in findings], f)
            tmp.rename(cache_path)
        except OSError as exc:
            log.debug("Cache write failed for %s: %s", entry.path, exc)

    def prune(self):
        if not self._cache_dir.exists():
            return
        try:
            entries = sorted(self._cache_dir.iterdir(), key=lambda p: p.stat().st_mtime)
            for p in entries[:-MAX_CACHE_ENTRIES]:
                p.unlink()
        except OSError as exc:
            log.debug("Cache prune failed: %s", exc)


class DiffFilter:
    """Filters FileEntries to only those changed since last scan."""

    @staticmethod
    def get_changed(repo_path: Path) -> Optional[set]:
        if not repo_path.exists():
            return None
        env = os.environ.copy()
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
        try:
            subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=repo_path, capture_output=True, timeout=5, check=True, env=env,
            )
        except (subprocess.CalledProcessError, OSError):
            return None
        for cmd in [
            ["git", "diff", "--name-only", "origin/main...HEAD", "--"],
            ["git", "diff", "--name-only", "HEAD", "--"],
            ["git", "diff", "--name-only", "HEAD~1", "--"],
        ]:
            try:
                r = subprocess.run(
                    cmd, cwd=repo_path, capture_output=True, text=True, timeout=10, env=env,
                )
                if r.returncode == 0 and r.stdout.strip():
                    return set(r.stdout.splitlines())
            except OSError:
                continue
        return None

    @staticmethod
    def apply(entries: List[FileEntry], changed: set) -> List[FileEntry]:
        if changed is None:
            return entries
        return [e for e in entries if e.path in changed]


class ScanPipeline:
    """Orchestrates a full scan: ingest -> analyze -> policy -> output."""

    def __init__(self, target_path: Path, config: RepoReaverConfig):
        self._target = target_path
        self._config = config
        self._cache = CacheManager(config.cache_dir) if config.cache_dir else None

    def run(self) -> Tuple[ScanResult, float]:
        start = time.time()
        log.info("Scanning %s", self._target)

        # 1. Ingestion
        ingester = select_ingester(self._target)
        ingest_result = ingester.ingest(str(self._target))

        # 2. Diff filter
        changed = DiffFilter.get_changed(self._target) if self._config.diff_only else None
        files = DiffFilter.apply(ingest_result.files, changed)

        # 3. Load analyzers
        text_analyzers, binary_analyzers = self._load_analyzers()
        total = len(files)

        # 4. Analyze
        all_findings: List[Finding] = []
        skipped_cache = 0
        analyzer_errors = 0
        workers = self._config.workers or cpu_count() or 1

        # Pre-read files, then analyze in parallel via process pool
        pending = []
        for i, entry in enumerate(files, 1):
            if i % PROGRESS_INTERVAL == 0 or i == total:
                pct = i / total * 100 if total else 100
                print(f"  Analyzing [{i}/{total}] ({pct:.0f}%)", end="\r" if i < total else "\n")

            if self._cache:
                cached = self._cache.get(entry)
                if cached is not None:
                    all_findings.extend(Finding.from_dict(d) for d in cached)
                    skipped_cache += 1
                    continue

            content, raw_bytes = _read_entry(entry, self._target, self._config.max_size_mb)
            pending.append((entry, content, raw_bytes))

        if pending:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                fut_map = {
                    pool.submit(_analyze_file, entry, content, raw, text_analyzers, binary_analyzers): entry
                    for entry, content, raw in pending
                }
                for fut in as_completed(fut_map):
                    entry = fut_map[fut]
                    try:
                        result = fut.result(timeout=120)
                        if result:
                            findings, error_count = result
                            all_findings.extend(findings)
                            analyzer_errors += error_count
                            if self._cache:
                                self._cache.set(entry, findings)
                    except Exception as exc:
                        log.error("Analyzer failed for %s: %s", entry.path, exc, exc_info=True)
                        analyzer_errors += 1

        # 5. Compute risk
        risk = RiskScore.compute(all_findings)

        # 6. Policy evaluation
        blocked = evaluate_policy(self._config.policy, all_findings)

        # 7. Build result
        result = ScanResult(
            target=str(self._target),
            files_scanned=total,
            findings=all_findings,
            risk_score=risk,
            blocked=blocked,
            analyzer_errors=analyzer_errors,
            skipped_cache=skipped_cache,
        )

        elapsed = time.time() - start
        return result, elapsed

    def _load_analyzers(self) -> Tuple[List[BaseAnalyzer], List[BaseAnalyzer]]:
        skip_names = set(self._config.skip_analyzers or [])
        text = []
        binary = []
        for cls in discover_analyzers().values():
            inst = cls()
            name = getattr(inst, "name", cls.__name__)
            if name in skip_names:
                continue
            if self._config.quick_mode and getattr(inst, "slow", False):
                continue
            if inst.analyze_text:
                text.append(inst)
            else:
                binary.append(inst)
        text.sort(key=lambda a: a.priority)
        binary.sort(key=lambda a: a.priority)
        return text, binary
