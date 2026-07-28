"""Analyzer plugin system."""

from .base import (BaseAnalyzer, AnalyzerResult, register_analyzer,
                   all_analyzers, discover_analyzers, _analyzer_registry)

# Import all built-in analyzers so their @register_analyzer decorators fire.
from .svg_analyzer import SVGVectorAnalyzer
from .unicode_analyzer import UnicodeAnalyzer
from .script_analyzer import ScriptAnalyzer
from .dep_analyzer import DepAnalyzer
from .workflow_analyzer import WorkflowAnalyzer
from .entropy_analyzer import EntropyAnalyzer
from .url_analyzer import URLNetworkAnalyzer
from .mime_analyzer import MimeDeceptionAnalyzer
from .behavioral_analyzer import BehavioralAnalyzer
from .secrets_analyzer import SecretsAnalyzer
from .cargo_analyzer import CargoAnalyzer
from .python_analyzer import PythonAnalyzer
from .dockerfile_analyzer import DockerfileAnalyzer
from .wasm_analyzer import WasmAnalyzer
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
