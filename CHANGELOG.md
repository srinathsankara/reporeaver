# Changelog

## 0.2.0 (2026-07-25)

### Added
- 14 analyzer plugins: svg_vector, unicode, script_analyzer, dependency, workflow, entropy, url_network, mime_deception, behavioral, secrets, cargo, python_analyzer, dockerfile_analyzer, wasm_analyzer, yara
- Hardcoded secrets scanner (AWS keys, GitHub tokens, private keys, JWTs, DB URLs, etc.)
- Typo-squatting detection via edit-distance matching against 50+ popular npm packages
- Lockfile analysis (package-lock.json resolved URL and integrity checks)
- Dependency confusion detection for scoped packages
- File-name bidi/RTL override detection (Trojan Source in filenames)
- Python packaging abuse detection (setup.py, pyproject.toml build-time attacks)
- Cargo/Rust build script analysis (Cargo.toml, build.rs)
- Dockerfile security analysis (unsafe patterns, privilege escalation)
- WebAssembly (WASM) binary analysis (suspicious imports, capabilities)
- YARA rule engine with 10 built-in rules + custom rule directory support
- Content-addressable caching (SHA-256 based, `~/.reporeaver/cache/`)
- Git diff mode (`--diff-only`) for PR/commit scanning
- Recursive archive extraction (zip/tar up to 3 levels deep)
- Progress reporting during scans
- Pre-commit hook installer (`reporeaver init-precommit`)
- GitHub Actions Checks API integration
- Cross-workflow CI/CD analysis (artifact chains, reusable workflows, self-hosted runners)
- Dashboard authentication token support
- OSV, MalwareBazaar, and C2 feed stubs (`reporeaver/feeds.py`)
- SQLite-based scan history with CLI viewer
- 107 tests

### Changed
- Project renamed from repo-scanner to reporeaver
- Architecture redesigned to plugin-based analyzer system
- Output formats: human-readable, JSON, SARIF 2.1.0, HTML dashboard
- Policy engine rewritten with YAML-based policy files

### Fixed
- Windows cp1252 encoding via `_safe_print` wrapper
- Thread-safety in workflow analyzer (removed shared mutable state)
- WASM parser uses proper LEB128 decoding
- Nested archive extraction handles tar and zip
- Certificate and SSH key regex patterns
- Dependency declarations now include pyyaml in core

## 0.1.0 (2026-07-20)
- Initial prototype with basic SVG, script, entropy, and URL scanners
