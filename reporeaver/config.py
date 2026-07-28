"""Configuration dataclass for RepoReaver scans."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class RepoReaverConfig:
    """Consolidated configuration for a single scan."""
    cache_dir: Optional[Path] = None
    diff_only: bool = False
    workers: int = 4
    max_size_mb: float = 2.0
    policy: Optional[str] = None
    skip_analyzers: Optional[List[str]] = None
    no_cache: bool = False
