# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

RepoReaver itself is a security scanning tool. If you find a vulnerability in RepoReaver's own code, please report it privately.

**Do not open a public issue.** Instead, email: srinathsankara@users.noreply.github.com

You should receive a response within 48 hours. If you don't, please follow up.

## Scope

This policy covers:
- The RepoReaver scanner itself (code execution, bypasses, false negatives)
- Any integration points (GitHub Action, Docker, pre-commit hook)

Out of scope:
- Repos that you scan with RepoReaver (that's the point — finding issues in them)
- Unrelated infrastructure
