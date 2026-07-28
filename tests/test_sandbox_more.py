"""Additional sandbox tests — temp dir cleanup on failure."""

import subprocess
from unittest.mock import patch

from reporeaver.utils.sandbox import clone_to_temp


class TestSandboxCleanup:
    @patch("reporeaver.utils.sandbox.subprocess.run",
           side_effect=subprocess.CalledProcessError(1, "git"))
    @patch("reporeaver.utils.sandbox.shutil.rmtree")
    def test_clone_failure_cleans_up(self, mock_rmtree, mock_run):
        tmp = clone_to_temp("https://github.com/user/repo.git")
        assert tmp is None
        mock_rmtree.assert_called_once()

    @patch("reporeaver.utils.sandbox.subprocess.run",
           side_effect=FileNotFoundError("git not found"))
    @patch("reporeaver.utils.sandbox.shutil.rmtree")
    def test_clone_no_git_cleans_up(self, mock_rmtree, mock_run):
        tmp = clone_to_temp("https://github.com/user/repo.git")
        assert tmp is None
        mock_rmtree.assert_called_once()

    @patch("reporeaver.utils.sandbox.subprocess.run")
    @patch("reporeaver.utils.sandbox.shutil.rmtree")
    def test_clone_success_no_cleanup(self, mock_rmtree, mock_run):
        tmp = clone_to_temp("https://github.com/user/repo.git")
        assert tmp is not None
        mock_rmtree.assert_not_called()
