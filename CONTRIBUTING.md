# Contributing to RepoReaver

## Development Setup

```bash
git clone https://github.com/srinathsankara/reporeaver
cd reporeaver
pip install -e ".[dev,dashboard]"
```

## Running Tests

```bash
pytest                       # all tests
pytest -x --tb=short         # stop at first failure
pytest --cov=reporeaver      # with coverage
```

## Lint & Type Check

```bash
ruff check .                 # lint (E, F, I, W rules, 120-char lines)
mypy reporeaver              # type checking
```

## Adding a New Analyzer

1. Create a file in `reporeaver/analyzers/` (e.g. `reporeaver/analyzers/my_analyzer.py`)
2. Subclass `BaseAnalyzer` and decorate with `@register_analyzer`
3. Define `name`, `description`, `priority`, `should_analyze()`, and `analyze()`
4. Import it in `reporeaver/analyzers/__init__.py`
5. Add it to `[project.entry-points."reporeaver.analyzers"]` in `pyproject.toml`
6. Add tests in `tests/test_my_analyzer.py`

```python
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

@register_analyzer
class MyAnalyzer(BaseAnalyzer):
    name = "my_analyzer"
    description = "Detects ..."
    priority = 35

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.is_text and entry.path.endswith(".ext")

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings = []
        # ... detection logic ...
        return AnalyzerResult(findings)
```

## Adding New Detection Patterns

- **Regex patterns** for scripts/commands: add to `SUSPICIOUS_PATTERNS` in the relevant analyzer
- **Secret patterns**: add to `SECRET_PATTERNS` in `secrets_analyzer.py` — format is `(regex, severity, category, description, confidence)`
- **Behavioral patterns**: add to `BEHAVIOR_PATTERNS` dict in `behavioral_analyzer.py`
- **C2 domains**: add to `KNOWN_C2_DOMAINS` in `url_analyzer.py`
- **Typosquat targets**: add to `TOP_NPM` set in `dep_analyzer.py`

## Code Style

- Line length: 120 characters
- Ruff rules: E, F, I, W
- Docstrings on all public modules, classes, and functions
- Narrow exception handlers — never bare `except:`
- Tests for every new detection: one positive (must flag) and one negative (must not false-positive)

## Pull Request Process

1. Ensure all tests pass (`pytest -x`)
2. Ensure lint passes (`ruff check .`)
3. Add or update tests for your change
4. Update README.md if the change affects user-facing behavior
5. Mark PR as "Ready for review"

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
