"""Entropy Analyzer — detects high-entropy/encoded strings that may hide payloads."""

import logging
import math
import re
import string
from typing import Dict, List, Optional

log = logging.getLogger("reporeaver.entropy")

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

ENTROPY_THRESHOLD = 5.5
MAX_LINE_LENGTH = 3000
MIN_LINE_LENGTH = 30

B64_PATTERN = re.compile(r'^[A-Za-z0-9+/=]+$')
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')


@register_analyzer
class EntropyAnalyzer(BaseAnalyzer):
    name = "entropy"
    description = "High-entropy string detection — finds encoded/obfuscated payloads"
    priority = 35

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.is_text and entry.size < 2_000_000

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path

        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or len(stripped) < MIN_LINE_LENGTH:
                continue
            if len(stripped) > MAX_LINE_LENGTH:
                stripped = stripped[:MAX_LINE_LENGTH]

            entropy = _shannon_entropy(stripped)
            if entropy < ENTROPY_THRESHOLD:
                continue

            # Check if it looks like encoded data
            is_b64 = bool(B64_PATTERN.match(stripped))
            is_hex = bool(HEX_PATTERN.match(stripped))

            if not (is_b64 or is_hex):
                continue

            decoded = _try_decode(stripped)
            if decoded and _has_meaningful_content(decoded):
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.ENCODED_PAYLOAD,
                    title=f"High-entropy encoded string (entropy={entropy:.1f})",
                    description=f"Found {'base64' if is_b64 else 'hex'}-encoded string "
                                f"({len(stripped)} chars) that decodes to meaningful content",
                    attack_path="Encoded string decoded -> reveals hidden payload or configuration",
                    remediation="Review this string. If intentional, document it. If suspicious, decode and inspect.",
                    line_number=line_no, decoded=_trunc(decoded, 300),
                    raw_value=_trunc(stripped, 80),
                ))
            elif is_b64 and entropy > 6.0:
                findings.append(Finding(
                    path, Severity.MEDIUM, Confidence.LOW, Category.HIGH_ENTROPY,
                    title=f"High-entropy string (entropy={entropy:.1f})",
                    description=f"Long high-entropy string ({len(stripped)} chars) — may be obfuscated payload",
                    attack_path="Could contain hidden data — decoded content not recognizable",
                    remediation="Inspect manually. Check if this is an expected token, key, or configuration.",
                    line_number=line_no, raw_value=_trunc(stripped, 80),
                ))

        return AnalyzerResult(findings)


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    return -sum((c / len(data)) * math.log2(c / len(data)) for c in freq.values())


def _try_decode(data: str) -> Optional[str]:
    try:
        import base64
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        if any(c.isalpha() and c.isascii() for c in decoded[:200]):
            return decoded
    except Exception as exc:
        log.debug("base64 decode failed: %s", exc)
    try:
        decoded = bytes.fromhex(data).decode("utf-8", errors="replace")
        if any(c.isalpha() and c.isascii() for c in decoded[:200]):
            return decoded
    except Exception as exc:
        log.debug("hex decode failed: %s", exc)
    return None


def _has_meaningful_content(text: str) -> bool:
    """Check if decoded text looks like meaningful content (not random bytes)."""
    if len(text) < 10:
        return False
    printable = sum(1 for c in text if c in string.printable)
    return (printable / len(text)) > 0.7


def _trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
