"""Tests for sandbox utilities."""

import subprocess
from unittest.mock import patch

from reporeaver.utils.sandbox import clone_to_temp, safe_tempdir


class TestSandbox:
    def test_safe_tempdir_returns_string(self):
        tmp = safe_tempdir()
        assert isinstance(tmp, str)
        assert len(tmp) > 0

    @patch("reporeaver.utils.sandbox.subprocess.run")
    def test_clone_success(self, mock_run):
        tmp = clone_to_temp("https://github.com/user/repo.git")
        assert tmp is not None
        assert isinstance(tmp, str)

    @patch("reporeaver.utils.sandbox.subprocess.run",
           side_effect=subprocess.CalledProcessError(1, "git"))
    def test_clone_failure(self, mock_run):
        tmp = clone_to_temp("https://github.com/user/repo.git")
        assert tmp is None

    @patch("reporeaver.utils.sandbox.subprocess.run",
           side_effect=FileNotFoundError("git not found"))
    def test_clone_no_git(self, mock_run):
        tmp = clone_to_temp("https://github.com/user/repo.git")
        assert tmp is None

    @patch("reporeaver.utils.sandbox.subprocess.run")
    def test_clone_uses_dash_dash(self, mock_run):
        clone_to_temp("https://github.com/user/repo.git")
        call_args = mock_run.call_args[0][0]
        assert "--" in call_args
        dash_idx = call_args.index("--")
        assert call_args[dash_idx + 1] == "https://github.com/user/repo.git"
