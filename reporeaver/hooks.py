"""Pre-commit hook installer — runs reporeaver on staged files before every commit."""

import os
import stat
import sys
from pathlib import Path

HOOK_TEMPLATE = """#!/bin/sh
# RepoReaver pre-commit hook — checks staged files for security issues.
# Installed by `reporeaver init-precommit`. Remove or edit this file to uninstall.

REPOREAVER="$(which reporeaver 2>/dev/null || echo '')"
if [ -z "$REPOREAVER" ]; then
    echo "reporeaver: command not found. Skipping pre-commit check."
    echo "Install with: pip install reporeaver"
    exit 0
fi

# Collect staged files that still exist
STAGED_FILES=""
for f in $(git diff --cached --name-only --diff-filter=ACM); do
    if [ -f "$f" ]; then
        STAGED_FILES="$STAGED_FILES $f"
    fi
done

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

echo ""
echo "  RepoReaver — scanning staged changes..."
echo ""

# Write staged files to a temp file for the scanner
TMPFILE=$(mktemp /tmp/reporeaver-staged-XXXXXX)
echo "$STAGED_FILES" | tr ' ' '\\n' > "$TMPFILE"

$REPOREAVER scan . \\
    --diff-only \\
    --verbose \\
    --max-size 5 \\
    --no-cache \\
    --skip worklist \\
    --no-history

EXIT_CODE=$?
rm -f "$TMPFILE"

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "  RepoReaver: security checks FAILED."
    echo "  Review the findings above. To bypass (not recommended):"
    echo "    git commit --no-verify"
    echo ""
fi

exit $EXIT_CODE
"""


def install_precommit(target_dir: str = "."):
    """Install the pre-commit hook into .git/hooks/pre-commit."""
    root = Path(target_dir).resolve()
    hooks_dir = root / ".git" / "hooks"
    hook_path = hooks_dir / "pre-commit"

    if not hooks_dir.is_dir():
        print(f"Error: {hooks_dir} does not exist. Is '{root}' a git repository?",
              file=sys.stderr)
        sys.exit(1)

    if hook_path.exists():
        print(f"Pre-commit hook already exists at {hook_path}")
        print("Overwrite? (y/n): ", end="")
        try:
            response = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)
        if response != "y":
            print("Aborted.")
            return

    try:
        hook_path.write_text(HOOK_TEMPLATE)
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"Installed reporeaver pre-commit hook at {hook_path}")
        print("It will run on staged files before every commit.")
        print("To skip: git commit --no-verify")
    except Exception as e:
        print(f"Error installing hook: {e}", file=sys.stderr)
        sys.exit(1)
