# SPDX-License-Identifier: MIT
"""Configuration dataclass for RepoReaver scans."""

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

log = logging.getLogger("reporeaver.config")

CONFIG_FILE_NAMES = ["reporeaver.yaml", ".reporeaver.yaml", "config.yaml"]


@dataclass
class RepoReaverConfig:
    """Consolidated configuration for a single scan."""
    cache_dir: Optional[Path] = None
    diff_only: bool = False
    workers: int = 4
    max_size_mb: float = 2.0
    policy: Optional[str] = None
    skip_analyzers: Optional[List[str]] = None
    quick_mode: bool = False
    no_cache: bool = False
    feeds_dir: Optional[Path] = None
    history_dir: Optional[Path] = None

    @classmethod
    def from_env(cls) -> "RepoReaverConfig":
        """Create config from REPOREAVER_* environment variables (CLI overrides)."""
        kwargs = {}
        cache = os.environ.get("REPOREAVER_CACHE_DIR")
        if cache:
            kwargs["cache_dir"] = Path(cache)
        if os.environ.get("REPOREAVER_DIFF_ONLY"):
            kwargs["diff_only"] = True
        workers = os.environ.get("REPOREAVER_WORKERS")
        if workers:
            try:
                kwargs["workers"] = int(workers)
            except ValueError:
                pass
        max_size = os.environ.get("REPOREAVER_MAX_SIZE_MB")
        if max_size:
            try:
                kwargs["max_size_mb"] = float(max_size)
            except ValueError:
                pass
        if os.environ.get("REPOREAVER_POLICY"):
            kwargs["policy"] = os.environ["REPOREAVER_POLICY"]
        if os.environ.get("REPOREAVER_QUICK"):
            kwargs["quick_mode"] = True
        if os.environ.get("REPOREAVER_NO_CACHE"):
            kwargs["no_cache"] = True
        feeds = os.environ.get("REPOREAVER_FEEDS_DIR")
        if feeds:
            kwargs["feeds_dir"] = Path(feeds)
        history = os.environ.get("REPOREAVER_HISTORY_DIR")
        if history:
            kwargs["history_dir"] = Path(history)
        return cls(**kwargs)


def find_config(target_dir: Optional[Path] = None) -> Optional[Path]:
    """Auto-discover config file in target dir, cwd, or user config dir."""
    search_dirs = []
    if target_dir:
        search_dirs.append(target_dir)
    search_dirs.append(Path.cwd())
    search_dirs.append(Path.home() / ".config" / "reporeaver")
    for d in search_dirs:
        for name in CONFIG_FILE_NAMES:
            p = d / name
            if p.exists():
                log.debug("Found config: %s", p)
                return p
    return None


def load_config(yaml_path: Path) -> dict:
    """Load a YAML config file and return as a dict. Returns {} on error."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            log.warning("Config file %s is not a dict, ignoring", yaml_path)
            return {}
        return data
    except (FileNotFoundError, yaml.YAMLError, ValueError) as exc:
        log.debug("Failed to load config %s: %s", yaml_path, exc)
        return {}
