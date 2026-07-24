"""Unicode deobfuscation — normalize, detect, and strip Unicode tricks."""

import re
from typing import Dict, List, Optional, Tuple

ZERO_WIDTH = {
    "\u200b", "\u200c", "\u200d", "\ufeff", "\u2060",
    "\u2061", "\u2062", "\u2063", "\u2064",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u180e", "\u00ad", "\u034f", "\u061c",
}

BIDI_OVERRIDES = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

HOMOGLYPH_MAP = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o",
    "\u0441": "c", "\u0440": "p", "\u0445": "x",
    "\u0456": "i", "\u0455": "s",
    "\u0432": "b", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u0442": "t", "\u0443": "y",
}


def strip_zero_width(text: str) -> str:
    for c in ZERO_WIDTH:
        text = text.replace(c, "")
    return text


def strip_bidi(text: str) -> str:
    result = []
    for c in text:
        if c not in BIDI_OVERRIDES:
            result.append(c)
    return "".join(result)


def normalize_homoglyphs(text: str) -> str:
    result = []
    for c in text:
        result.append(HOMOGLYPH_MAP.get(c, c))
    return "".join(result)


def detect_trojan_source(text: str) -> List[Tuple[int, str]]:
    """Detect Trojan Source-style attacks (CVE-2021-42574) using bidi overrides."""
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for char in BIDI_OVERRIDES:
            if char in line:
                findings.append((line_no, f"Bidi override U+{ord(char):04X}"))
    return findings


def count_zero_width(text: str) -> int:
    return sum(1 for c in text if c in ZERO_WIDTH)
