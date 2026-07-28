"""Configuration dataclass for RepoReaver scans."""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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
        import yaml
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            log.warning("Config file %s is not a dict, ignoring", yaml_path)
            return {}
        return data
    except Exception as exc:
        log.debug("Failed to load config %s: %s", yaml_path, exc)
        return {}
