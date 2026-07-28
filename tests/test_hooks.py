"""Tests for pre-commit hook installer."""

import pytest
from pathlib import Path
from reporeaver.hooks import install_precommit


class TestInstallPrecommit:
    def test_installs_hook(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        install_precommit(str(tmp_path))
        hook = tmp_path / ".git" / "hooks" / "pre-commit"
        assert hook.exists()
        text = hook.read_text()
        assert "RepoReaver" in text
        assert "$REPOREAVER scan" in text

    def test_not_git_repo(self, tmp_path):
        with pytest.raises(SystemExit):
            install_precommit(str(tmp_path))

    def test_overwrite_prompt_yes(self, tmp_path, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda: "y")
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        (tmp_path / ".git" / "hooks" / "pre-commit").write_text("old")
        install_precommit(str(tmp_path))
        assert "RepoReaver" in (tmp_path / ".git" / "hooks" / "pre-commit").read_text()

    def test_overwrite_prompt_no(self, tmp_path, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda: "n")
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        (tmp_path / ".git" / "hooks" / "pre-commit").write_text("original")
        install_precommit(str(tmp_path))
        assert (tmp_path / ".git" / "hooks" / "pre-commit").read_text() == "original"
