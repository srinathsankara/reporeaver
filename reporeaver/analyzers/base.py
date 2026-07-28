# SPDX-License-Identifier: MIT
"""Base analyzer plugin interface."""

import importlib.metadata
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Type

log = logging.getLogger("reporeaver.analyzers")

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
    slow: bool = False

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
            except (ImportError, AttributeError, TypeError) as exc:
                log.debug("Failed to load analyzer %s: %s", ep.name, exc)
    except Exception as exc:
        log.debug("Failed to query entry points: %s", exc)
    if not found:
        found.update(_analyzer_registry)
    return found
