"""Base ingester interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models import FileEntry


@dataclass
class IngestResult:
    files: List[FileEntry] = field(default_factory=list)
    source_type: str = ""
    source_path: str = ""
    metadata: Dict = field(default_factory=dict)

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def total_size(self) -> int:
        return sum(f.size for f in self.files)


class BaseIngester(ABC):
    @abstractmethod
    def ingest(self, source: str) -> IngestResult:
        ...
