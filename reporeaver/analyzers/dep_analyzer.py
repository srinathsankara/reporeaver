"""Dependency Analyzer — typo-squatting, lockfile tampering, lifecycle hooks, malicious indicators."""

import json
import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Set, Tuple

from ..models import Category, Confidence, FileEntry, Finding, Severity
from ..utils.text import trunc
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

# Commonly typosquatted packages — attackers register names one char off
TOP_NPM: Set[str] = {
    "lodash", "react", "express", "axios", "chalk", "moment",
    "request", "async", "bluebird", "underscore", "colors",
    "commander", "body-parser", "mongoose", "passport",
    "socket.io", "jsdom", "cheerio", "babel", "webpack",
    "gulp", "grunt", "yargs", "inquirer", "ora", "glob",
    "rimraf", "mkdirp", "uuid", "debug", "winston", "morgan",
    "cors", "dotenv", "jsonwebtoken", "bcrypt", "ejs", "pug",
    "helmet", "compression", "cookie-parser", "multer",
    "nodemailer", "joi", "validator", "cross-env", "cross-spawn",
    "faker", "chance", "prettier", "eslint", "tslib",
}

COMMON_TYPOSQUAT_PREFIXES = {"node-", "js-", "nodejs-", "lib-", "native-"}
COMMON_TYPOSQUAT_SUFFIXES = {"-js", "-node", "-lib", "-native", "-util", "-helper"}

SUSPICIOUS_PKG_NAMES = [
    "postinstall-", "preinstall-", "install-", "*-backdoor",
    "electron-native-", "node-native-", "*-malware", "payload-",
    "crypto-", "crypt-", "decrypt-", "decoding-",
]

_suspicious_hook_patterns = re.compile(
    r"(?:curl|wget|fetch|https?://|download|chmod|chown|/dev/tcp|eval|exec|base64|python|node)",
    re.IGNORECASE,
)

SUSPICIOUS_VERSION_PATTERNS = [
    (r'https?://[^\s"\']+', Severity.CRITICAL, "URL-resolved package version"),
    (r'git\+https?://[^\s"\']+', Severity.CRITICAL, "Git URL dependency (unpinned)"),
    (r'file://[^\s"\']+', Severity.HIGH, "Local file dependency"),
    (r'^\*$', Severity.LOW, "Wildcard version (unstable)"),
    (r'^[A-Za-z0-9+/]{40,}=*$', Severity.CRITICAL, "Base64 version string"),
    (r'[|;&`$]', Severity.CRITICAL, "Shell metacharacters in version string"),
]

# For lockfile parcel comparisons
NPM_REGISTRY = "registry.npmjs.org"
ALLOWED_REGISTRIES = {NPM_REGISTRY, "registry.yarnpkg.com"}


@register_analyzer
class DepAnalyzer(BaseAnalyzer):
    name = "dependency"
    description = "Dependency manifest analysis: typo-squatting, lockfile tampering, lifecycle hooks, malicious deps"
    priority = 25

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        return name in ("package.json", "package-lock.json", "yarn.lock",
                        "pnpm-lock.yaml", "requirements.txt", "pipfile",
                        "pipfile.lock", "gemfile", "gemfile.lock",
                        "go.mod", "go.sum")

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path
        name = entry.path.rsplit("/", 1)[-1].lower()

        if name == "package.json":
            self._analyze_node_manifest(content, path, findings)
        elif name == "package-lock.json":
            self._analyze_npm_lock(content, path, findings)
        elif name == "yarn.lock":
            self._analyze_yarn_lock(content, path, findings)
        elif name in ("requirements.txt", "pipfile"):
            self._analyze_python(content, path, findings)
        elif name in ("gemfile",):
            self._analyze_ruby(content, path, findings)
        elif name == "pnpm-lock.yaml":
            self._analyze_pnpm_lock(content, path, findings)
        elif name == "pipfile.lock":
            self._analyze_pipfile_lock(content, path, findings)
        elif name == "gemfile.lock":
            self._analyze_gemfile_lock(content, path, findings)
        elif name == "go.mod":
            self._analyze_go_mod(content, path, findings)
        elif name == "go.sum":
            self._analyze_go_sum(content, path, findings)

        return AnalyzerResult(findings)

    # --------------- npm package.json ---------------

    def _analyze_node_manifest(self, content: str, path: str, findings: List[Finding]):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        all_deps = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if isinstance(data.get(key), dict):
                for k, v in data[key].items():
                    all_deps[k] = (v if isinstance(v, str) else "*", key)

        # Pre-check for internal-scoped packages (dependency confusion risk)
        for dep_name in all_deps:
            if dep_name.startswith("@") and "/" in dep_name:
                findings.append(Finding(
                    path, Severity.INFO, Confidence.LOW, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Scoped package '{dep_name}' — verify it resolves to the right registry",
                    description="Scoped packages can be public or private. If private but not configured, "
                                "npm will fall back to public registry — dependency confusion attack.",
                    attack_path=f"npm install -> scoped package resolved from public registry -> malicious package",
                    remediation="Ensure .npmrc has @scope:registry set for private scoped packages.",
                    raw_value=dep_name,
                ))

        for dep_name, (dep_version, dep_type) in all_deps.items():
            self._check_name_squatting(dep_name, dep_version, path, findings)
            self._check_version_safety(dep_name, dep_version, path, findings)

        # Check for postinstall chains
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for hook in ("postinstall", "preinstall", "install"):
                if hook in scripts:
                    val = scripts[hook]
                    if not _suspicious_hook_patterns.search(val):
                        continue
                    findings.append(Finding(
                        path, Severity.HIGH, Confidence.HIGH, Category.POSTINSTALL_CHAIN,
                        title=f"Package has '{hook}' script with suspicious operations",
                        description=f"This script runs during install: {trunc(val, 200)}",
                        attack_path=f"npm install -> {hook} -> {trunc(val, 100)}",
                        remediation="Audit lifecycle scripts. Use `--ignore-scripts` for inspection.",
                        snippet=val,
                    ))

    def _check_name_squatting(self, name: str, version: str, path: str, findings: List[Finding]):
        """Detect typo-squatting by edit distance against known popular packages."""
        base = name.split("/")[-1]  # strip scope
        for popular in TOP_NPM:
            ratio = SequenceMatcher(None, base.lower(), popular).ratio()
            # High similarity but not exact match
            if 0.75 <= ratio < 1.0:
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Possible typo-squatting: '{name}' is similar to '{popular}' ({ratio:.0%})",
                    description=f"Dependency '{name}'@{version} has high similarity to popular package "
                                f"'{popular}'. This may be a typo-squatting attack.",
                    attack_path=f"npm install -> {name} -> potentially mimics {popular} -> malicious code runs",
                    remediation=f"Verify the package name. Did you mean '{popular}'? Check the registry.",
                    raw_value=f"{name}@{version}",
                ))

        # Check for prefix/suffix additions that reek of squatting
        lower = base.lower()
        for prefix in COMMON_TYPOSQUAT_PREFIXES:
            if lower.startswith(prefix) and lower[len(prefix):] in TOP_NPM:
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Suspicious prefix on '{name}': '{prefix}' added to '{base[len(prefix):]}'",
                    description=f"Package adds '{prefix}' to a known package name — common squatting pattern.",
                    attack_path=f"npm install -> prefixed name mistakes -> malicious package",
                    remediation=f"Check if '{prefix}{base[len(prefix):]}' is a legitimate fork or a squat.",
                    raw_value=f"{name}@{version}",
                ))
        for suffix in COMMON_TYPOSQUAT_SUFFIXES:
            if lower.endswith(suffix) and lower[:-len(suffix)] in TOP_NPM:
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Suspicious suffix on '{name}': adds '{suffix}' to '{base[:-len(suffix)]}'",
                    description=f"Package appends '{suffix}' to a known package — common squatting variant.",
                    attack_path=f"npm install -> suffixed name -> malicious package",
                    remediation=f"Verify this is not a squat mimicking '{base[:-len(suffix)]}'.",
                    raw_value=f"{name}@{version}",
                ))

    def _check_version_safety(self, name: str, version: str, path: str, findings: List[Finding]):
        for suspicious in SUSPICIOUS_PKG_NAMES:
            pattern = suspicious.replace("*", "")
            if pattern and pattern.lower() in name.lower():
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"{name}: Package name contains suspicious pattern '{suspicious}'",
                    description=f"Dependency '{name}'@{version}: name matches suspicious pattern '{suspicious}'.",
                    attack_path=f"npm install -> {name} executes -> compromise",
                    remediation="Remove or replace this dependency with a trusted alternative.",
                    raw_value=f"{name}@{version}",
                ))

        for pat, severity, desc in SUSPICIOUS_VERSION_PATTERNS:
            if re.search(pat, version):
                findings.append(Finding(
                    path, severity, Confidence.HIGH, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"{name}: {desc}",
                    description=f"Dependency '{name}' version '{version}' triggered: {desc}",
                    attack_path=f"npm install -> {name}@{version} -> arbitrary code risk",
                    remediation="Pin to a specific registry version and verify integrity.",
                    raw_value=version,
                ))

    # --------------- npm lockfile ---------------

    def _analyze_npm_lock(self, content: str, path: str, findings: List[Finding]):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        packages = data.get("packages", {}) or {}
        for pkg_path, pkg_info in packages.items():
            if pkg_path == "":
                continue
            resolved: Optional[str] = pkg_info.get("resolved")
            if resolved and NPM_REGISTRY not in resolved:
                name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                findings.append(Finding(
                    path, Severity.CRITICAL, Confidence.HIGH, Category.URL_DEPENDENCY,
                    title=f"Lockfile resolved URL outside registry: {trunc(resolved, 100)}",
                    description=f"Package '{name}' resolves to '{resolved}' — not the official npm registry.",
                    attack_path="npm ci -> fetches from attacker-controlled URL -> arbitrary code",
                    remediation="Run `npm audit` and verify integrity hashes. Reset lockfile if suspicious.",
                    raw_value=resolved,
                ))

            integrity = pkg_info.get("integrity", "")
            if integrity and not integrity.startswith("sha"):
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.HIGH, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Suspicious integrity hash: {trunc(integrity, 60)}",
                    description=f"Package '{pkg_path}' has non-standard integrity hash: {integrity}",
                    attack_path="npm ci -> integrity check bypassed -> malicious package installed",
                    remediation="Regenerate lockfile. This indicates lockfile tampering.",
                ))

    def _analyze_yarn_lock(self, content: str, path: str, findings: List[Finding]):
        """Basic yarn.lock check — look for resolved URLs outside allowed registries."""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("resolved ") and "https://" in stripped:
                url = stripped.split("resolved ")[-1].strip().strip("\"'")
                if not any(reg in url for reg in ALLOWED_REGISTRIES):
                    findings.append(Finding(
                        path, Severity.CRITICAL, Confidence.HIGH, Category.URL_DEPENDENCY,
                        title=f"Yarn lockfile resolves to external URL: {trunc(url, 100)}",
                        description=f"Package resolved to non-registry URL: {url}",
                        attack_path="yarn install -> fetches from external URL -> malicious package",
                        remediation="Verify the URL and reset lockfile if needed.",
                        raw_value=url,
                    ))

    # --------------- Python ---------------

    def _analyze_python(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue
            if stripped.startswith("-") and not stripped.startswith("-e "):
                continue
            if "@" in stripped and "://" in stripped:
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.URL_DEPENDENCY,
                    title=f"Python dependency from URL: {trunc(stripped, 100)}",
                    description="URL-based pip dependencies bypass PyPI security guarantees.",
                    attack_path="pip install -> URL dependency -> arbitrary code",
                    remediation="Use PyPI versions with hash verification.",
                    line_number=line_no, snippet=stripped,
                ))
            # Check for editable installs
            if stripped.startswith("-e ") or " --editable" in stripped:
                findings.append(Finding(
                    path, Severity.MEDIUM, Confidence.MEDIUM, Category.SUSPICIOUS_DEPENDENCY,
                    title="Editable pip install — can execute arbitrary setup.py",
                    description=f"Editable install: {trunc(stripped, 100)}",
                    attack_path="pip install -e -> setup.py executes during install -> compromise",
                    remediation="Avoid editable installs in production. Pin exact versions.",
                    line_number=line_no, snippet=stripped,
                ))

    # --------------- Ruby ---------------

    def _analyze_ruby(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            if "git:" in line or "github:" in line or "path:" in line:
                findings.append(Finding(
                    path, Severity.MEDIUM, Confidence.LOW, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Ruby gem from non-standard source: {trunc(line.strip(), 100)}",
                    description="Non-registry gem sources can introduce untrusted code.",
                    attack_path="bundle install -> gem from external source -> potential compromise",
                    remediation="Use rubygems.org sources with lockfiles.",
                    line_number=line_no, snippet=line.strip(),
                ))

    # --------------- pnpm lockfile ---------------

    def _analyze_pnpm_lock(self, content: str, path: str, findings: List[Finding]):
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("resolved:") and "https://" in stripped:
                url = stripped.split("resolved:")[-1].strip().strip("\"'")
                if NPM_REGISTRY not in url:
                    findings.append(Finding(
                        path, Severity.CRITICAL, Confidence.HIGH, Category.URL_DEPENDENCY,
                        title=f"pnpm lockfile resolves to external URL: {trunc(url, 100)}",
                        description=f"Package resolved to non-registry URL: {url}",
                        attack_path="pnpm install -> fetches from external URL -> malicious package",
                        remediation="Verify the URL and run `pnpm install --lockfile-only` to reset.",
                        raw_value=url,
                    ))

    # --------------- Pipfile.lock ---------------

    def _analyze_pipfile_lock(self, content: str, path: str, findings: List[Finding]):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return
        for section in ("default", "develop"):
            pkgs = data.get(section, {}) or {}
            for pkg_name, info in pkgs.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version", "")
                if isinstance(version, str) and "://" in version:
                    findings.append(Finding(
                        path, Severity.HIGH, Confidence.MEDIUM, Category.URL_DEPENDENCY,
                        title=f"Pipfile.lock URL dependency: {pkg_name} -> {trunc(version, 100)}",
                        description=f"Package '{pkg_name}' pins a URL-based version: {version}",
                        attack_path="pip install -> URL dependency -> arbitrary code",
                        remediation="Use PyPI versions with hash verification.",
                        raw_value=f"{pkg_name}=={version}",
                    ))

    # --------------- Gemfile.lock ---------------

    def _analyze_gemfile_lock(self, content: str, path: str, findings: List[Finding]):
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("remote:") and "https://" in stripped:
                url = stripped.split("remote:")[-1].strip().strip("\"'")
                if "rubygems.org" not in url:
                    findings.append(Finding(
                        path, Severity.MEDIUM, Confidence.LOW, Category.URL_DEPENDENCY,
                        title=f"Gemfile.lock remote outside rubygems.org: {trunc(url, 100)}",
                        description=f"Lockfile uses non-standard remote: {url}",
                        attack_path="bundle install -> gem from external remote -> potential compromise",
                        remediation="Use rubygems.org as the sole source in Gemfile.",
                        raw_value=url,
                    ))

    # --------------- go.mod ---------------

    def _analyze_go_mod(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("replace ") and "=>" in stripped:
                findings.append(Finding(
                    path, Severity.MEDIUM, Confidence.LOW, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Go module replace directive: {trunc(stripped, 120)}",
                    description="Replace directives redirect a module version, potentially to a fork or local path.",
                    attack_path="go build -> replace directive -> unexpected module source",
                    remediation="Audit all replace directives. Avoid in production builds.",
                    line_number=line_no, snippet=stripped,
                ))
            if stripped.startswith("// ") and "indirect" in stripped.lower() and "://" in stripped:
                findings.append(Finding(
                    path, Severity.INFO, Confidence.LOW, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Go module comment references URL: {trunc(stripped, 120)}",
                    description="Indirect dependency comment contains a URL — verify the source.",
                    attack_path=None,
                    remediation="Run `go mod tidy` to ensure consistent state.",
                    line_number=line_no, snippet=stripped,
                ))

    # --------------- go.sum ---------------

    def _analyze_go_sum(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) < 3:
                continue
            module, version, algo_hash = parts[0], parts[1], parts[2]
            if not algo_hash.startswith("h1:"):
                findings.append(Finding(
                    path, Severity.LOW, Confidence.LOW, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Non-standard go.sum hash: {trunc(algo_hash, 40)}",
                    description=f"Module '{module}@{version}' uses non-standard hash: {algo_hash}",
                    attack_path="go mod verify -> unexpected hash algorithm",
                    remediation="Run `go mod verify` and review if the hash type is legitimate.",
                    line_number=line_no, snippet=stripped,
                ))


