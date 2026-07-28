# SPDX-License-Identifier: MIT
"""MIME/File-Type Deception Analyzer — detects extension mismatches, polyglot files, and deceptive naming."""

import re
from typing import List

from ..models import Category, Confidence, FileEntry, Finding, Severity
from ..utils.known import IMAGE_EXTS
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

XML_LIKE_HEADERS = [
    b"<?xml", b"<svg", b"<!DOCTYPE", b"<html", b"<script",
]

SVG_SIGNATURE = re.compile(rb'<svg[\s>]', re.IGNORECASE)
HTML_SIGNATURE = re.compile(rb'<!DOCTYPE\s+html|<html[\s>]', re.IGNORECASE)
SCRIPT_SIGNATURE = re.compile(rb'<script[\s>]', re.IGNORECASE)
JS_CODE_SIGNATURE = re.compile(rb'(?:function\s+\w+\s*\(|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=)', re.IGNORECASE)
XML_DECLARATION = re.compile(rb'<\?xml\s+version', re.IGNORECASE)

ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"
PDF_MAGIC = b"%PDF"
PNG_MAGIC = b"\x89PNG"
JPEG_MAGIC = b"\xff\xd8\xff"


@register_analyzer
class MimeDeceptionAnalyzer(BaseAnalyzer):
    name = "mime_deception"
    description = "Detects file extension MIME mismatches, polyglots, and naming deception"
    priority = 5
    analyze_text = False

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.size > 0

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        return AnalyzerResult([])

    def analyze_binary(self, entry: FileEntry, data: bytes) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path
        ext = entry.declared_ext or ""
        low_ext = ext.lower()

        content_header = data[:100]

        # Check for XML content in non-XML extensions
        if low_ext in IMAGE_EXTS and (SVG_SIGNATURE.search(content_header) or
                                       XML_DECLARATION.search(content_header)):
            findings.append(Finding(
                path, Severity.CRITICAL, Confidence.HIGH, Category.MIME_MISMATCH,
                title=f"File has '{ext}' extension but contains XML/SVG content",
                description=f"File named with image extension '{ext}' is actually an XML/SVG file. "
                            f"This is a common deception technique to hide scripts in image-looking files.",
                attack_path="File appears to be image -> actually SVG -> may contain scripts -> XSS / code execution",
                remediation="Rename file to .svg and review for scripts. Do not open in browser without inspection.",
                raw_value=f"Declared: {ext}, Detected: XML/SVG",
            ))

        # Check for script content in image extensions
        if low_ext in IMAGE_EXTS and JS_CODE_SIGNATURE.search(content_header):
            findings.append(Finding(
                path, Severity.CRITICAL, Confidence.HIGH, Category.POLYGLOT_FILE,
                title=f"File has '{ext}' extension but contains JavaScript code",
                description="File looks like an image but contains JavaScript code. "
                            "This is a polyglot technique to smuggle scripts past security scanners.",
                attack_path="File appears safe (image) -> actually executable JS -> runs in build or browser context",
                remediation="Rename and quarantine. This file is attempting to hide executable code as an image.",
            ))

        # Check for HTML content in non-HTML extensions
        if low_ext not in (".html", ".htm") and HTML_SIGNATURE.search(content_header):
            findings.append(Finding(
                path, Severity.HIGH, Confidence.MEDIUM, Category.MIME_MISMATCH,
                title=f"File has '{ext}' extension but contains HTML markup",
                description="File content is HTML despite having a non-HTML extension. "
                            "HTML files can contain scripts, tracking pixels, and active content.",
                attack_path="File appears harmless -> actually HTML -> browser renders -> scripts execute",
                remediation="Rename to .html if intentional. Review for embedded scripts.",
            ))

        # Check for embedded scripts in non-HTML/XML
        if low_ext not in (".html", ".htm", ".svg", ".xml") and \
           SCRIPT_SIGNATURE.search(content_header):
            findings.append(Finding(
                path, Severity.HIGH, Confidence.MEDIUM, Category.POLYGLOT_FILE,
                title=f"File has '{ext}' extension but contains <script> elements",
                description="Script tags found in a file that doesn't appear to be HTML or SVG. "
                            "This could execute in certain rendering contexts.",
                attack_path="File parsed by build tool or browser -> <script> executes -> compromise",
                remediation="Remove script elements or rename file appropriately.",
            ))

        return AnalyzerResult(findings)
