"""Tests for scan configuration."""

from reporeaver.config import RepoReaverConfig
from pathlib import Path


def test_default_config():
    cfg = RepoReaverConfig()
    assert cfg.workers == 4
    assert cfg.max_size_mb == 2.0
    assert cfg.diff_only is False


def test_config_with_cache_dir():
    cfg = RepoReaverConfig(cache_dir=Path("/tmp/cache"))
    assert cfg.cache_dir == Path("/tmp/cache")


def test_config_no_history():
    cfg = RepoReaverConfig(no_cache=True)
    assert cfg.no_cache is True
