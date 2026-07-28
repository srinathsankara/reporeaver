# SPDX-License-Identifier: MIT
"""JavaScript deobfuscation helpers — detect and decode obfuscated JS patterns."""

import base64
import binascii
import logging
import re
from typing import List, Tuple

log = logging.getLogger("reporeaver.deobfuscation.js")


# Pattern: hex-encoded strings like \x48\x65\x6c\x6c\x6f
HEX_STRING = re.compile(r'(?:\\x[0-9a-fA-F]{2})+')

# Pattern: unicode-encoded strings like \u0048\u0065
UNICODE_STRING = re.compile(r'(?:\\u[0-9a-fA-F]{4})+')

# Pattern: arrays of encoded strings used for lookup
ENCODED_ARRAY = re.compile(r'\[(["\'])(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|[A-Za-z0-9+/=]{20,})\1(?:\s*,\s*\1[^"]+\1)*\]')

# Pattern: eval(atob(...)) or eval(Buffer.from(...).toString())
EVAL_B64 = re.compile(r'eval\s*\(\s*(?:atob|Buffer\.from)\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']')

# Pattern: String.fromCharCode(...)
FROM_CHARCODE = re.compile(r'String\.fromCharCode\s*\(([^)]+)\)')


def find_obfuscated_strings(text: str) -> List[Tuple[str, int, str]]:
    """Find and decode obfuscated JS string patterns.

    Returns list of (decoded_text, line_number, pattern_type).
    """
    results = []

    for match in HEX_STRING.finditer(text):
        raw = match.group(0)
        try:
            decoded = bytes.fromhex(raw.replace("\\x", "")).decode("utf-8", errors="replace")
            if decoded.isprintable():
                line_no = text[:match.start()].count("\n") + 1
                results.append((decoded, line_no, "hex_escape"))
        except (ValueError, UnicodeDecodeError) as exc:
            log.debug("hex escape decode failed: %s", exc)

    for match in UNICODE_STRING.finditer(text):
        raw = match.group(0)
        try:
            decoded = raw.encode().decode("unicode_escape") if "\\u" in raw else raw
            if decoded.isprintable():
                line_no = text[:match.start()].count("\n") + 1
                results.append((decoded, line_no, "unicode_escape"))
        except (ValueError, UnicodeDecodeError) as exc:
            log.debug("unicode escape decode failed: %s", exc)

    for match in EVAL_B64.finditer(text):
        b64_data = match.group(1)
        try:
            decoded = base64.b64decode(b64_data).decode("utf-8", errors="replace")
            if decoded:
                line_no = text[:match.start()].count("\n") + 1
                results.append((decoded, line_no, "eval_base64"))
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            log.debug("eval base64 decode failed: %s", exc)

    for match in FROM_CHARCODE.finditer(text):
        args = match.group(1)
        try:
            codes = [int(c.strip(), 0) for c in args.split(",")]
            decoded = "".join(chr(c) for c in codes if 0 <= c <= 0x10FFFF)
            if decoded:
                line_no = text[:match.start()].count("\n") + 1
                results.append((decoded, line_no, "from_char_code"))
        except (ValueError, TypeError) as exc:
            log.debug("fromCharCode decode failed: %s", exc)

    return results


def extract_urls_from_script(text: str) -> List[str]:
    """Extract URLs that might be C2 endpoints from JS."""
    urls = re.findall(r'https?://[^\s"\'<>)]+', text)
    return urls
