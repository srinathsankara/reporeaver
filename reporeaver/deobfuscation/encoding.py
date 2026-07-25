"""Encoding deobfuscation — decode base64, hex, gzip, and layered encodings."""

import base64
import gzip
import logging
import re
from io import BytesIO
from typing import Optional

log = logging.getLogger("reporeaver.deobfuscation.encoding")


def try_decode(data: str, max_depth: int = 3) -> Optional[str]:
    """Recursively try to decode layered encodings."""
    if max_depth <= 0:
        return None
    original = data

    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    if hex_pattern.match(data) and len(data) >= 4:
        try:
            decoded = bytes.fromhex(data).decode("utf-8", errors="replace")
            if _is_meaningful(decoded):
                result = try_decode(decoded.strip(), max_depth - 1)
                return result or decoded
        except Exception as exc:
            log.debug("hex decode failed: %s", exc)

    b64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    if b64_pattern.match(data) and len(data) > 10:
        try:
            decoded = base64.b64decode(data).decode("utf-8", errors="replace")
            if _is_meaningful(decoded):
                result = try_decode(decoded.strip(), max_depth - 1)
                return result or decoded
        except Exception as exc:
            log.debug("base64 decode failed: %s", exc)

    # Try gzip decompress
    try:
        raw = base64.b64decode(data)
        decoded = gzip.decompress(raw).decode("utf-8", errors="replace")
        if _is_meaningful(decoded):
            return decoded
    except Exception as exc:
        log.debug("gzip decompress failed: %s", exc)

    # Try URL decode
    try:
        from urllib.parse import unquote
        decoded = unquote(data)
        if decoded != original and _is_meaningful(decoded):
            result = try_decode(decoded, max_depth - 1)
            return result or decoded
    except Exception as exc:
        log.debug("URL decode failed: %s", exc)

    return None


def decode_js_string(text: str) -> Optional[str]:
    try:
        result = text.encode("utf-8").decode("unicode_escape")
        if result != text:
            return result
    except Exception as exc:
        log.debug("unicode_escape decode failed: %s", exc)
    return None


def _is_meaningful(text: str) -> bool:
    if len(text) < 5:
        return False
    printable = sum(1 for c in text if c.isprintable() and c.isascii())
    if (printable / len(text)) < 0.7:
        return False
    space_count = text.count(" ")
    if space_count == 0 and len(text) > 20:
        return False
    return True
