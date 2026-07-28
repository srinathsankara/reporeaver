# SPDX-License-Identifier: MIT
"""Sandbox utilities — safe environment for scanning."""

import shutil
import subprocess
import sys
import tempfile
from typing import Optional


def safe_tempdir() -> str:
    return tempfile.mkdtemp(prefix="reporeaver_")


def _is_unsafe_url(url: str) -> bool:
    """Block file:// URLs and local paths to prevent SSRF/path-traversal."""
    lower = url.strip().lower()
    if lower.startswith("file://"):
        return True
    if ":" in lower and not lower.startswith("http://") and not lower.startswith("https://"):
        return True
    if lower.startswith("/") or lower.startswith("./"):
        return True
    return False


def clone_to_temp(repo_url: str, branch: Optional[str] = None) -> Optional[str]:
    if _is_unsafe_url(repo_url):
        print(f"Warning: refusing to clone unsafe URL: {repo_url}", file=sys.stderr)
        return None
    tmp = safe_tempdir()
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend(["--", repo_url, tmp])
    try:
        subprocess.run(cmd, capture_output=True, timeout=60, check=True)
        return tmp
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Warning: git clone failed: {e}", file=sys.stderr)
        shutil.rmtree(tmp, ignore_errors=True)
        return None
