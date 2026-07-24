"""Sandbox utilities — safe environment for scanning."""

import os
import tempfile
from pathlib import Path
from typing import Optional


def safe_tempdir() -> str:
    """Create a temporary directory for safe scanning."""
    return tempfile.mkdtemp(prefix="reporeaver_")


def clone_to_temp(repo_url: str, branch: Optional[str] = None) -> Optional[str]:
    """Clone a git repo to a temp directory for scanning.

    Never runs on untrusted code — only git operations.
    """
    import subprocess
    tmp = safe_tempdir()
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([repo_url, tmp])
    try:
        subprocess.run(cmd, capture_output=True, timeout=60, check=True)
        return tmp
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Warning: git clone failed: {e}", file=__import__("sys").stderr)
        return None
