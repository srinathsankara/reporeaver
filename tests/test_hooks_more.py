"""Additional hooks tests — error branches."""

from unittest.mock import patch
import pytest
from reporeaver.hooks import install_precommit


class TestInstallPrecommitExtra:
    def test_overwrite_interrupt(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        (tmp_path / ".git" / "hooks" / "pre-commit").write_text("old")
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with pytest.raises(SystemExit):
                install_precommit(str(tmp_path))

    def test_overwrite_eoferror(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        (tmp_path / ".git" / "hooks" / "pre-commit").write_text("old")
        with patch("builtins.input", side_effect=EOFError):
            with pytest.raises(SystemExit):
                install_precommit(str(tmp_path))

    def test_write_error_on_hook(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        with patch("pathlib.Path.write_text", side_effect=PermissionError("denied")):
            with pytest.raises(SystemExit):
                install_precommit(str(tmp_path))
