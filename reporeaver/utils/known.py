# SPDX-License-Identifier: MIT
"""Single source of truth for file extension sets and well-known paths.

Every analyzer and ingester should import from here, not define its own list.
"""

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp"}
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".rar", ".7z"}
SCRIPT_EXTS = {".js", ".jsx", ".ts", ".tsx", ".py", ".sh", ".bash", ".ps1", ".bat", ".vbs", ".cmd"}
CONFIG_EXTS = {".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg"}
LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "gemfile.lock", "poetry.lock", "composer.lock",
}
