# RepoReaver 🔍

**Open-source security gate for repositories, archives, and dependency trees.**

Answers one question: *"Can this codebase safely be cloned, reviewed, built, or executed?"*

[![Tests](https://github.com/reporeaver/reporeaver/actions/workflows/ci.yml/badge.svg)](https://github.com/reporeaver/reporeaver/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## The Problem

Attackers hide malware in files that look harmless:

- **SVG architectural diagrams** with obfuscated JavaScript that phones home
- **Build scripts** (`postinstall`) that download and execute remote payloads
- **Unicode tricks** (zero-width chars, bidi overrides, homoglyphs) that hide code in plain sight
- **File-type deception** — SVGs named `.png`, polyglot files that pass extension-based filters
- **CI/CD abuse** — unpinned actions, secrets exfiltration, remote script execution in pipelines
- **Dependency attacks** — URL-resolved packages, postinstall chains, version string injection

This was an actual Upwork attack vector: a fake contracting job with a malicious SVG in the repo diagram.

## Features

| Analyzer | Capability |
|----------|------------|
| **SVG Vector** | XXE, obfuscated `<script>` blocks, inline event handlers, data URIs, foreign objects, `javascript:` URIs, base64 payloads |
| **Unicode** | Zero-width characters, bidi overrides (Trojan Source), homoglyph attacks, invisible Unicode |
| **Script** | `postinstall`/`preinstall` hooks, `curl | bash`, credential theft, remote downloads |
| **Dependency** | URL-resolved packages, shell metacharacters in versions, postinstall chains |
| **Workflow/CI** | Unpinned actions, remote exec in CI, secrets exposure, scheduled triggers |
| **Entropy** | Base64/hex encoded strings, high-entropy obfuscation detection |
| **URL/Network** | C2 callbacks, suspicious TLDs, raw IP targets, known C2 infrastructure |
| **MIME/Type** | Extension mismatch, polyglot files, SVG/script in image extensions |
| **Behavioral** | Network behavior, code execution, persistence, data exfiltration |

## Quick Start

### Install

```bash
pip install reporeaver
```

### Scan a Repository

```bash
# Basic scan
reporeaver scan ./suspicious-repo

# Full report with HTML dashboard and SARIF
reporeaver scan ./suspicious-repo --html report.html --sarif results.sarif --verbose

# JSON output
reporeaver scan ./suspicious-repo --json

# Scan an archive without extracting
reporeaver scan attacker-code.zip --html report.html
```

### GitHub Action (1-minute setup)

Create `.github/workflows/reporeaver.yml`:

```yaml
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
```

The Action:
- Fails CI if risk score exceeds threshold
- Uploads SARIF to GitHub Security tab
- Attaches HTML dashboard as a workflow artifact

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/reporeaver/reporeaver
  rev: v0.2.0
  hooks:
    - id: reporeaver
      args: ["scan", "."]
```

## Architecture

```
reporeaver/
├── cli.py              # CLI entry point
├── engine.py           # Scanning orchestrator
├── models.py           # Finding, RiskScore, FileEntry, ScanResult
├── policy.py           # Policy engine (allow/deny rules)
├── analyzers/          # Plugin-based detection modules
│   ├── svg_analyzer.py
│   ├── unicode_analyzer.py
│   ├── script_analyzer.py
│   ├── dep_analyzer.py
│   ├── workflow_analyzer.py
│   ├── entropy_analyzer.py
│   ├── url_analyzer.py
│   ├── mime_analyzer.py
│   └── behavioral_analyzer.py
├── deobfuscation/      # Decode layered encodings
├── ingest/             # File, directory, archive, git ingest
├── output/             # Report, SARIF, HTML dashboard
└── utils/              # MIME detection, sandbox
```

## Output Formats

- **Terminal**: Colorized severity-grouped report
- **JSON**: Machine-readable for CI and tooling
- **SARIF**: GitHub-native — results appear in Security tab
- **HTML**: Self-contained dashboard — open from any browser (no server needed)

## Example Output

```
  ============================================================
  REPOREAVER — SECURITY GATE REPORT
  Target: ./suspect-repo
  ============================================================

  RISK SCORE: 7.5 / 10.0  (critical)
  2 critical, 3 high, 1 medium, 0 low

  ------------------------------------------------------------
  CRITICAL FINDINGS (2)
  ------------------------------------------------------------

  [!] SVG contains XML External Entity (XXE) declaration
    File: docs/architecture.svg
    Attack chain: SVG parsing -> XXE expansion -> file read

  [!] SVG script uses 'eval(' — arbitrary code execution risk
    File: docs/architecture.svg, line 10
    Attack chain: SVG script -> eval -> remote code execution
    Decoded: var xhr=new XMLHttpRequest();xhr.open("GET",...
```

## Security Model

- **Never executes repository code on host**
- Offline by default — no remote fetch
- All analysis is static (AST, regex, entropy)
- Sandboxed temp directory for archive extraction
- Plugin architecture for custom analyzers

## License

MIT
