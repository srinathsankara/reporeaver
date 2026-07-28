# SPDX-License-Identifier: MIT
"""Analyzer plugin system."""

from .base import AnalyzerResult, BaseAnalyzer, _analyzer_registry, all_analyzers, discover_analyzers, register_analyzer
from .behavioral_analyzer import BehavioralAnalyzer
from .cargo_analyzer import CargoAnalyzer
from .dep_analyzer import DepAnalyzer
from .dockerfile_analyzer import DockerfileAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from .mime_analyzer import MimeDeceptionAnalyzer
from .python_analyzer import PythonAnalyzer
from .script_analyzer import ScriptAnalyzer
from .secrets_analyzer import SecretsAnalyzer

# Import all built-in analyzers so their @register_analyzer decorators fire.
from .svg_analyzer import SVGVectorAnalyzer
from .unicode_analyzer import UnicodeAnalyzer
from .url_analyzer import URLNetworkAnalyzer
from .wasm_analyzer import WasmAnalyzer
from .workflow_analyzer import WorkflowAnalyzer
from .yara_analyzer import YaraAnalyzer

__all__ = [
    "BaseAnalyzer", "AnalyzerResult", "register_analyzer", "all_analyzers",
    "discover_analyzers", "_analyzer_registry",
    "SVGVectorAnalyzer", "UnicodeAnalyzer", "ScriptAnalyzer",
    "DepAnalyzer", "WorkflowAnalyzer", "EntropyAnalyzer",
    "URLNetworkAnalyzer", "MimeDeceptionAnalyzer", "BehavioralAnalyzer",
    "SecretsAnalyzer", "CargoAnalyzer", "PythonAnalyzer",
    "DockerfileAnalyzer", "WasmAnalyzer", "YaraAnalyzer",
]
