"""Tests for scan configuration."""

import tempfile
from pathlib import Path

from reporeaver.config import RepoReaverConfig, find_config, load_config


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


def test_config_all_fields():
    cfg = RepoReaverConfig(
        cache_dir=Path("/cache"),
        diff_only=True,
        workers=8,
        max_size_mb=10.0,
        policy="my.yaml",
        skip_analyzers=["yara"],
        quick_mode=True,
        no_cache=True,
    )
    assert cfg.diff_only is True
    assert cfg.workers == 8
    assert cfg.max_size_mb == 10.0
    assert cfg.policy == "my.yaml"
    assert cfg.skip_analyzers == ["yara"]
    assert cfg.quick_mode is True


class TestFindConfig:
    def test_no_config_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            result = find_config(Path(td))
            assert result is None

    def test_finds_reporeaver_yaml_in_target(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "reporeaver.yaml"
            p.write_text("workers: 2", encoding="utf-8")
            result = find_config(Path(td))
            assert result == p

    def test_finds_dot_reporeaver_yaml_in_target(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".reporeaver.yaml"
            p.write_text("workers: 2", encoding="utf-8")
            result = find_config(Path(td))
            assert result == p

    def test_finds_config_yaml_in_user_dir(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            user_dir = Path(td) / ".config" / "reporeaver"
            user_dir.mkdir(parents=True, exist_ok=True)
            user_cfg = user_dir / "config.yaml"
            user_cfg.write_text("workers: 2", encoding="utf-8")
            monkeypatch.setattr(Path, "home", lambda: Path(td))
            work_dir = tempfile.mkdtemp(dir=td)
            result = find_config(Path(work_dir))
            assert result == user_cfg


class TestLoadConfig:
    def test_loads_valid_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "reporeaver.yaml"
            p.write_text("workers: 6\nquick_mode: true", encoding="utf-8")
            data = load_config(p)
            assert data == {"workers": 6, "quick_mode": True}

    def test_non_dict_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "reporeaver.yaml"
            p.write_text("[1, 2, 3]", encoding="utf-8")
            data = load_config(p)
            assert data == {}

    def test_missing_file(self):
        data = load_config(Path("nonexistent.yaml"))
        assert data == {}

    def test_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.yaml"
            p.write_text(": : invalid", encoding="utf-8")
            data = load_config(p)
            assert data == {}


class TestFromEnv:
    def test_from_env_empty(self):
        cfg = RepoReaverConfig.from_env()
        assert cfg.workers == 4
        assert cfg.diff_only is False

    def test_from_env_workers(self, monkeypatch):
        monkeypatch.setenv("REPOREAVER_WORKERS", "8")
        cfg = RepoReaverConfig.from_env()
        assert cfg.workers == 8

    def test_from_env_invalid_workers_ignored(self, monkeypatch):
        monkeypatch.setenv("REPOREAVER_WORKERS", "not-a-number")
        cfg = RepoReaverConfig.from_env()
        assert cfg.workers == 4

    def test_from_env_quick_and_no_cache(self, monkeypatch):
        monkeypatch.setenv("REPOREAVER_QUICK", "1")
        monkeypatch.setenv("REPOREAVER_NO_CACHE", "1")
        cfg = RepoReaverConfig.from_env()
        assert cfg.quick_mode is True
        assert cfg.no_cache is True

    def test_from_env_dirs(self, monkeypatch):
        monkeypatch.setenv("REPOREAVER_FEEDS_DIR", "/tmp/feeds")
        monkeypatch.setenv("REPOREAVER_HISTORY_DIR", "/tmp/hist")
        monkeypatch.setenv("REPOREAVER_CACHE_DIR", "/tmp/cache")
        cfg = RepoReaverConfig.from_env()
        assert cfg.feeds_dir == Path("/tmp/feeds")
        assert cfg.history_dir == Path("/tmp/hist")
        assert cfg.cache_dir == Path("/tmp/cache")
