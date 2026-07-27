# Contributing to RepoReaver

Thanks for your interest! RepoReaver is a community-driven security tool and we welcome contributions.

## Quick Start

```bash
git clone https://github.com/srinathsankara/reporeaver.git
cd reporeaver
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## How to Contribute

- **Report bugs** — open an issue with the `bug` template
- **Suggest features** — open an issue with the `feature request` template
- **Write code** — fork, branch, commit, open a pull request

## Guidelines

- Keep it simple: no unnecessary abstractions
- All new features need tests (we use pytest)
- All tests must pass: `python -m pytest tests/ -v`
- Match existing code style (no docstrings unless the logic is non-obvious)
- Use `Optional[X]` for Python 3.8/3.9 compatibility

## Adding an Analyzer

1. Create `reporeaver/analyzers/your_analyzer.py`
2. Subclass `BaseAnalyzer`, implement `should_analyze` and `analyze`
3. Decorate with `@register_analyzer`
4. Add tests in `tests/test_new_analyzers.py`
5. Register it in `engine.py:_register_builtins()`

## Adding a New Category

1. Add the enum value to `models.py:Category`
2. Wire it through `policy.py` default block list if needed
3. Add a test

## Pre-commit

```bash
reporeaver init-precommit
```

This runs the scanner on staged files before every commit.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
