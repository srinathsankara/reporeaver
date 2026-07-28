from pathlib import Path
from typing import Union

from .base import BaseIngester, IngestResult
from .single import SingleFileIngester, DirectoryIngester, ArchiveIngester


def select_ingester(path: Path) -> BaseIngester:
    if path.is_file():
        if path.suffix.lower() in (".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".rar", ".7z"):
            return ArchiveIngester()
        return SingleFileIngester()
    return DirectoryIngester()


__all__ = [
    "BaseIngester", "IngestResult",
    "SingleFileIngester", "DirectoryIngester", "ArchiveIngester",
    "select_ingester",
]
