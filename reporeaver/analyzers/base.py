"""Base analyzer plugin interface."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type

from ..models import FileEntry, Finding


class AnalyzerResult:
    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def __bool__(self) -> bool:
        return len(self.findings) > 0


class BaseAnalyzer(ABC):
    name: str = "base"
    description: str = ""
    priority: int = 50

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    @abstractmethod
    def should_analyze(self, entry: FileEntry) -> bool:
        ...

    @abstractmethod
    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        ...

    def analyze_binary(self, entry: FileEntry, data: bytes) -> AnalyzerResult:
        return AnalyzerResult([])


_analyzer_registry: Dict[str, Type[BaseAnalyzer]] = {}


def register_analyzer(cls: Type[BaseAnalyzer]):
    _analyzer_registry[getattr(cls, "name", cls.__name__)] = cls
    return cls


def all_analyzers() -> Dict[str, Type[BaseAnalyzer]]:
    return dict(_analyzer_registry)
