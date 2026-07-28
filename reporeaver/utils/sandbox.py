# SPDX-License-Identifier: MIT
"""Sandbox utilities — safe environment for scanning."""

import shutil
import subprocess
import sys
import tempfile
from typing import Optional


def safe_tempdir() -> str:
    return tempfile.mkdtemp(prefix="reporeaver_")


def clone_to_temp(repo_url: str, branch: Optional[str] = None) -> Optional[str]:
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
