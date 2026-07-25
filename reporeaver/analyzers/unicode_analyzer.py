"""Unicode Analyzer — detects zero-width characters, homoglyphs, bidi overrides, and other Unicode tricks."""

import re
from typing import Dict, List, Optional

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

ZERO_WIDTH_CHARS = {
    "\u200b": "U+200B ZERO WIDTH SPACE",
    "\u200c": "U+200C ZERO WIDTH NON-JOINER",
    "\u200d": "U+200D ZERO WIDTH JOINER",
    "\ufeff": "U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u2060": "U+2060 WORD JOINER",
    "\u2061": "U+2061 FUNCTION APPLICATION",
    "\u2062": "U+2062 INVISIBLE TIMES",
    "\u2063": "U+2063 INVISIBLE SEPARATOR",
    "\u2064": "U+2064 INVISIBLE PLUS",
    "\u2066": "U+2066 LEFT-TO-RIGHT ISOLATE",
    "\u2067": "U+2067 RIGHT-TO-LEFT ISOLATE",
    "\u2068": "U+2068 FIRST STRONG ISOLATE",
    "\u2069": "U+2069 POP DIRECTIONAL ISOLATE",
    "\u202a": "U+202A LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "U+202B RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "U+202C POP DIRECTIONAL FORMATTING",
    "\u202d": "U+202D LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "U+202E RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "U+2066 LEFT-TO-RIGHT ISOLATE",
    "\u2067": "U+2067 RIGHT-TO-LEFT ISOLATE",
    "\u2068": "U+2068 FIRST STRONG ISOLATE",
    "\u2069": "U+2069 POP DIRECTIONAL ISOLATE",
    "\u180e": "U+180E MONGOLIAN VOWEL SEPARATOR",
    "\u00ad": "U+00AD SOFT HYPHEN",
    "\u034f": "U+034F COMBINING GRAPHEME JOINER",
    "\u061c": "U+061C ARABIC LETTER MARK",
}

BIDI_OVERRIDE_CHARS = {"\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069"}

HOMOGLYPH_DANGEROUS_PAIRS = [
    ("а", "a"),  # Cyrillic 'а' vs Latin 'a'
    ("е", "e"),  # Cyrillic 'е' vs Latin 'e'
    ("о", "o"),  # Cyrillic 'о' vs Latin 'o'
    ("с", "c"),  # Cyrillic 'с' vs Latin 'c'
    ("р", "p"),  # Cyrillic 'р' vs Latin 'p'
    ("х", "x"),  # Cyrillic 'х' vs Latin 'x'
    ("і", "i"),  # Cyrillic 'і' vs Latin 'i'
    ("ѕ", "s"),  # Cyrillic 'ѕ' vs Latin 's'
]

SUSPICIOUS_HOMOGLYPH_KEYWORDS = [
    "require", "import", "eval", "exec", "fetch", "http",
    "https", "localhost", "constructor", "prototype",
    "__proto__", "then", "catch", "async", "await",
]


@register_analyzer
class UnicodeAnalyzer(BaseAnalyzer):
    name = "unicode"
    description = "Detects zero-width chars, homoglyphs, bidi overrides, and Unicode tricks"
    priority = 15

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.is_text and entry.size < 500_000

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path

        self._check_zero_width(content, path, findings)
        self._check_bidi_overrides(content, path, findings)
        self._check_homoglyphs(content, path, findings)
        self._check_filename(entry, findings)

        return AnalyzerResult(findings)

    def _check_zero_width(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            for char, name in ZERO_WIDTH_CHARS.items():
                if char in line:
                    context = self._get_context(line, char)
                    findings.append(Finding(
                        path, Severity.MEDIUM, Confidence.HIGH, Category.ZERO_WIDTH_CHAR,
                        title=f"Zero-width/invisible Unicode character: {name}",
                        description=f"Invisible characters can alter code behavior without being visible "
                                    f"in editors. Used for obfuscation and hidden control flow.",
                        attack_path="Source appears benign -> invisible chars alter logic -> hidden behavior",
                        remediation="Remove invisible Unicode characters. Use a linter or 'cat -A' to reveal them.",
                        line_number=line_no, snippet=context,
                        raw_value=repr(char),
                    ))

    def _check_bidi_overrides(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            for char in BIDI_OVERRIDE_CHARS:
                if char in line:
                    context = self._get_context(line, char)
                    findings.append(Finding(
                        path, Severity.HIGH, Confidence.HIGH, Category.BIDI_OVERRIDE,
                        title="Bidirectional text override character detected (Trojan Source)",
                        description="Bidi override characters can reorder code display, making code appear "
                                    "to do one thing while it does another. This is the 'Trojan Source' attack (CVE-2021-42574).",
                        attack_path="Code reviewed as benign -> bidi reordering changes logic -> hidden vulnerability",
                        remediation="Remove bidi override characters. Most linters now flag these.",
                        line_number=line_no, snippet=context,
                        raw_value=repr(char),
                    ))

    def _check_homoglyphs(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            for keyword in SUSPICIOUS_HOMOGLYPH_KEYWORDS:
                # Check if keyword appears but contains non-ASCII look-alikes
                for cyrillic_char, latin_char in HOMOGLYPH_DANGEROUS_PAIRS:
                    disguised = keyword.replace(latin_char, cyrillic_char)
                    if disguised != keyword and disguised in line:
                        findings.append(Finding(
                            path, Severity.HIGH, Confidence.HIGH, Category.HOMOGLYPH,
                            title=f"Homoglyph attack: '{keyword}' disguised with Cyrillic characters",
                            description=f"The identifier '{disguised}' uses Cyrillic characters that look "
                                        f"identical to Latin '{keyword}' but are different code points. "
                                        f"This can hide malicious imports or variable references.",
                            attack_path="Code reviewed as safe -> homoglyph binds to different function -> supply-chain attack",
                            remediation="Replace homoglyph characters with their ASCII equivalents.",
                            line_number=line_no, snippet=self._get_context(line, disguised),
                        ))

    def _check_filename(self, entry: FileEntry, findings: List[Finding]):
        """Check for bidi override or zero-width chars in the filename itself."""
        fname = entry.path.rsplit("/", 1)[-1]
        for char, name in ZERO_WIDTH_CHARS.items():
            if char in fname:
                findings.append(Finding(
                    entry.path, Severity.HIGH, Confidence.HIGH, Category.BIDI_OVERRIDE,
                    title=f"Filename contains invisible Unicode character: {name}",
                    description=f"File '{repr(fname)}' has invisible chars — may display differently than it truly is.",
                    attack_path="File reviewed under wrong name -> hidden malicious file bypasses review",
                    remediation="Rename file to remove invisible characters.",
                    raw_value=repr(fname),
                ))

        for char in BIDI_OVERRIDE_CHARS:
            if char in fname:
                findings.append(Finding(
                    entry.path, Severity.CRITICAL, Confidence.HIGH, Category.BIDI_OVERRIDE,
                    title="Filename contains bidi override character (Trojan Source in filename)",
                    description=f"File '{repr(fname)}' has a bidi override — its displayed name "
                                f"is different from its actual name. This is a known attack technique.",
                    attack_path="File appears as something safe -> actual name maps to executable -> bypasses review",
                    remediation="Rename file to remove bidi characters immediately.",
                    raw_value=repr(fname),
                ))

    def _get_context(self, line: str, target: str, radius: int = 40) -> str:
        idx = line.find(target)
        if idx == -1:
            return _trunc(line.strip(), 150)
        start = max(0, idx - radius)
        end = min(len(line), idx + radius)
        return _trunc(line[start:end].strip(), 150)


def _trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
