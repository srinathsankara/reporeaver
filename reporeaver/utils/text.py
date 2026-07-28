# SPDX-License-Identifier: MIT
"""Text utilities."""


def trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s


def get_context(line: str, target: str, radius: int = 40) -> str:
    idx = line.find(target)
    if idx == -1:
        return trunc(line.strip(), 150)
    start = max(0, idx - radius)
    end = min(len(line), idx + radius)
    return trunc(line[start:end].strip(), 150)


def line_of(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def is_meaningful_text(text: str, min_len: int = 5) -> bool:
    """Check if decoded text looks meaningful (not random bytes)."""
    if len(text) < min_len:
        return False
    printable = sum(1 for c in text if c.isprintable() and c.isascii())
    if (printable / len(text)) < 0.7:
        return False
    if min_len > 5:
        return True
    space_count = text.count(" ")
    if space_count == 0 and len(text) > 50 and all(c.isalpha() for c in text):
        return False
    return True
