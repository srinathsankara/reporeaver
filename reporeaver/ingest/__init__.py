# SPDX-License-Identifier: MIT
from pathlib import Path

from ..utils.known import ARCHIVE_EXTS
from .base import BaseIngester, IngestResult
from .single import ArchiveIngester, DirectoryIngester, SingleFileIngester


def select_ingester(path: Path) -> BaseIngester:
    if path.is_file():
        if path.suffix.lower() in ARCHIVE_EXTS:
            return ArchiveIngester()
        return SingleFileIngester()
    return DirectoryIngester()


__all__ = [
    "BaseIngester", "IngestResult",
    "SingleFileIngester", "DirectoryIngester", "ArchiveIngester",
    "select_ingester",
]
