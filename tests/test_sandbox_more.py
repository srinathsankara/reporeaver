"""Additional sandbox tests — temp dir cleanup on failure and URL validation."""

import subprocess
from unittest.mock import patch

from reporeaver.utils.sandbox import _is_unsafe_url, clone_to_temp


class TestIsUnsafeUrl:
    def test_https_is_safe(self):
        assert not _is_unsafe_url("https://github.com/user/repo.git")

    def test_http_is_safe(self):
        assert not _is_unsafe_url("http://example.com/repo")

    def test_file_url_is_unsafe(self):
        assert _is_unsafe_url("file:///etc/passwd")

    def test_local_path_is_unsafe(self):
        assert _is_unsafe_url("/home/user/repo")
        assert _is_unsafe_url("./local/repo")

    def test_unknown_scheme_is_unsafe(self):
        assert _is_unsafe_url("ssh://git@host/repo")
        assert _is_unsafe_url("ftp://files.example.com/repo")


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
