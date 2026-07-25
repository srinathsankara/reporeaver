# RepoReaver

**Pre-clone repo security scanner.** Answers one question: *"Can this codebase safely be cloned, reviewed, built, or executed?"*

[![CI](https://github.com/srinathsankara/reporeaver/actions/workflows/ci.yml/badge.svg)](https://github.com/srinathsankara/reporeaver/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## Quick Start

```bash
pip install reporeaver
reporeaver scan ./suspicious-repo
reporeaver scan project.zip --html report.html --sarif results.sarif
```

## What It Catches

| Category | Threats Detected |
|----------|-----------------|
| **SVG** | XXE, obfuscated JS in `<script>`, inline event handlers, data URIs, foreign objects, `javascript:` URIs, base64 payloads, C2 callbacks |
| **Hardcoded Secrets** | AWS keys, GitHub PATs, Slack tokens, private keys, JWTs, DB connection strings, OpenAI keys, 20+ provider patterns |
| **Unicode** | Zero-width chars, bidi overrides (Trojan Source CVE-2021-42574), homoglyph attacks, invisible chars in filenames |
| **Dependencies** | Typo-squatting (edit-distance vs 50+ packages), URL-resolved packages, lockfile tampering, dependency confusion, postinstall chains |
| **Build Scripts** | `setup.py` `cmdclass`/`os.system`, `Cargo.toml` git deps/`build.rs`, `Dockerfile` `FROM latest`/`curl|bash`/`ADD URL`, `Makefile` abuse |
| **CI/CD** | Unpinned actions, remote exec, secrets exposure, self-hosted runners, artifact chains, reusable workflows, cron persistence |
| **Binary** | WASM dangerous imports (emscripten_run_script, network), YARA rules (reverse shell, webshell, PowerShell encoded) |
| **Behavioral** | Network C2, code execution, persistence, data exfiltration patterns |
| **File Deception** | Extension mismatches, polyglot files, SVG/script in image extensions |
| **Obfuscation** | Base64/hex encoding, high entropy, layered encodings, JS string obfuscation |

## Installation

```bash
# Core (includes YAML policy support)
pip install reporeaver

# With dashboard server
pip install reporeaver[dashboard]

# Everything
pip install reporeaver[all]

# From source
git clone https://github.com/srinathsankara/reporeaver.git
cd reporeaver
pip install -e ".[all]"
```

## Usage

### Scan Commands

```bash
reporeaver scan ./repo                          # Basic scan
reporeaver scan ./repo --verbose                 # Include medium-severity findings
reporeaver scan archive.zip --html report.html   # Scan archive, generate HTML dashboard
reporeaver scan . --diff-only                    # Only scan files changed in this branch
reporeaver scan . --skip entropy,behavioral      # Disable specific analyzers
reporeaver scan . --no-cache                     # Disable content-based caching
reporeaver scan . --policy my-policy.yaml        # Custom policy file
```

### Output Formats

```bash
reporeaver scan ./repo --json                    # Machine-readable JSON
reporeaver scan ./repo --sarif results.sarif     # SARIF (GitHub Security tab)
reporeaver scan ./repo --html report.html        # Self-contained HTML dashboard
```

### View History

```bash
reporeaver history --last 20                     # Recent scans
reporeaver history --stats                       # Aggregate stats
reporeaver history --delete 3                    # Delete a scan record
```

### Dashboard Server

```bash
reporeaver dashboard                             # Launch at http://127.0.0.1:9520

# With auth token
REPOREAVER_DASHBOARD_TOKEN=my-secret reporeaver dashboard

# Custom host/port
reporeaver dashboard --host 0.0.0.0 --port 9000
```

### Pre-commit Hook

```bash
reporeaver init-precommit                        # Installs hook into .git/hooks/
# Runs on staged files before every commit. Bypass with: git commit --no-verify
```

### Configuration Files

RepoReaver auto-discovers these config files in order:
1. `./reporeaver.yaml`
2. `./.reporeaver.yaml`
3. `~/.config/reporeaver/config.yaml`

Example `reporeaver.yaml`:
```yaml
severity_threshold: high
skip_analyzers:
  - entropy
  - yara
max_size_mb: 5
policy: my-policy.yaml
```

## GitHub Action

```yaml
# .github/workflows/reporeaver.yml
name: RepoReaver Security Gate
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: reporeaver/reporeaver@v1
        with:
          target: .
          severity-threshold: high
          diff-only: true
          github-token: ${{ github.token }}
```

The Action:
- Fails CI if risk score exceeds threshold
- Posts a GitHub Check Run with score and summary
- Uploads SARIF to GitHub Security tab
- Attaches HTML/JSON/SARIF as workflow artifacts

## Docker

```bash
docker build -t reporeaver .
docker run --rm -v $(pwd):/scan reporeaver scan /scan
docker run --rm -v $(pwd):/scan reporeaver scan /scan --html /scan/report.html
```

## Architecture

```
reporeaver/
├── cli.py                 # argparse CLI: scan, dashboard, history, init-precommit
├── engine.py              # Orchestrator: ingest -> analyze -> score -> output
├── models.py              # Finding, RiskScore, FileEntry, ScanResult
├── policy.py              # YAML policy engine (allow/block/severity)
├── config.py              # Auto-discover reporeaver.yaml
├── logging.py             # Structured logging to file + console
├── history.py             # SQLite scan history (for dashboard)
├── feeds.py               # OSV, MalwareBazaar, C2 threat feed integration
├── hooks.py               # Pre-commit hook installer
├── analyzers/             # 15 plugin-based detection modules
│   ├── base.py            # Plugin base class + registry
│   ├── svg_analyzer.py, unicode_analyzer.py, secrets_analyzer.py, ...
├── deobfuscation/         # Unicode, encoding, JS deobfuscation
├── ingest/                # File, directory, archive (recursive) ingest
├── output/                # Report, SARIF, HTML dashboard
├── ui/                    # FastAPI dashboard server
└── utils/                 # MIME detection, sandbox
```

## Security Model

- **Never executes repo code on host** — all analysis is static
- **Offline by default** — threat feeds are opt-in, cached locally
- **Sandboxed extraction** — archives extracted to isolated temp dirs
- **No shell injection** — all `subprocess.run()` calls use list form, never `shell=True`
- **Safe YAML** — uses `yaml.safe_load()`, not `yaml.load()`
- **Minimal dependencies** — core requires only `pyyaml`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass — risk score below threshold (no critical/high findings) |
| 1 | Fail — risk score >= 7.0 or policy violations found |

## Development

```bash
git clone https://github.com/srinathsankara/reporeaver.git
cd reporeaver
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## License

MIT. See [LICENSE](LICENSE).
