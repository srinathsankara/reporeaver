"""Base analyzer plugin interface."""

import importlib.metadata
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
    analyze_text: bool = True

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

ENTRY_POINT_GROUP = "reporeaver.analyzers"


def register_analyzer(cls: Type[BaseAnalyzer]):
    _analyzer_registry[getattr(cls, "name", cls.__name__)] = cls
    return cls


def all_analyzers() -> Dict[str, Type[BaseAnalyzer]]:
    return dict(_analyzer_registry)


def discover_analyzers() -> Dict[str, Type[BaseAnalyzer]]:
    """Discover analyzers via entry_points, falling back to decorator registry."""
    found: Dict[str, Type[BaseAnalyzer]] = {}
    try:
        for ep in importlib.metadata.entry_points().get(ENTRY_POINT_GROUP, []):
            if not ep.module.startswith("reporeaver."):
                continue
            try:
                cls = ep.load()
                found[ep.name] = cls
            except Exception:
                continue
    except Exception:
        pass
    if not found:
        found.update(_analyzer_registry)
    return found
