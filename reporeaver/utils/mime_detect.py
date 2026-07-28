# SPDX-License-Identifier: MIT
"""MIME type detection — not trusting file extensions."""



MIME_MAP = {
    ".svg": "image/svg+xml",
    ".xml": "application/xml",
    ".html": "text/html",
    ".htm": "text/html",
    ".js": "text/javascript",
    ".jsx": "text/javascript",
    ".ts": "text/typescript",
    ".tsx": "text/typescript",
    ".json": "application/json",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".sh": "text/x-shellscript",
    ".bash": "text/x-shellscript",
    ".ps1": "text/powershell",
    ".bat": "text/bat",
    ".py": "text/x-python",
    ".rb": "text/x-ruby",
    ".php": "text/x-php",
    ".css": "text/css",
    ".scss": "text/scss",
    ".less": "text/less",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".eot": "font/eot",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".exe": "application/x-msdownload",
    ".dll": "application/x-msdownload",
}

def guess_mime(path: str) -> str:
    """Guess MIME type from path. Returns 'application/octet-stream' if unknown."""
    lower = path.lower()
    for ext, mime in sorted(MIME_MAP.items(), key=lambda x: -len(x[0])):
        if lower.endswith(ext):
            return mime
    return "application/octet-stream"


def is_text_mime(mime: str) -> bool:
    return mime.startswith("text/") or mime in (
        "application/json", "application/xml", "image/svg+xml",
        "text/javascript", "text/typescript",
    )


def detect_svg_by_content(chunk: bytes) -> bool:
    """Detect SVG by content signature, regardless of extension."""
    return b"<svg" in chunk[:200] or b"<SVG" in chunk[:200] or b"xmlns=\"http://www.w3.org/2000/svg\"" in chunk[:500]


def is_script_by_content(chunk: bytes) -> bool:
    head = chunk[:200].lower()
    return any(
        sig in head
        for sig in [b"#!/usr/bin/env", b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/python",
                     b"<script", b"function ", b"const ", b"let ", b"var ",
                     b"require(", b"import ", b"export "]
    )
