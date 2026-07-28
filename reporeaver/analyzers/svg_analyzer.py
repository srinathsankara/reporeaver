"""SVG analyzer — scripts, event handlers, XXE, data URIs, foreign objects."""

import base64
import binascii
import logging
import re
from typing import Optional

log = logging.getLogger("reporeaver.svg")

from ..models import Category, Confidence, FileEntry, Finding, Severity
from ..utils.text import trunc, line_of
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

# Event handlers that can fire automatically when SVG renders
AUTO_FIRE_EVENTS = [
    "onload", "onunload", "onerror", "onclick", "ondblclick",
    "onmousedown", "onmouseup", "onmouseover", "onmousemove",
    "onmouseout", "onfocus", "onblur", "onsubmit", "onreset",
    "onkeydown", "onkeypress", "onkeyup", "onchange",
    "onloadstart", "onprogress", "ontimeout", "onplay",
]

# JS functions that can eval/execute strings as code
EXEC_FUNCS = [
    "eval(", "exec(", "Function(", "setTimeout(", "setInterval(",
    "new Function", "document.write(", "document.writeln(",
    "import(", "require(", "fetch(", "XMLHttpRequest(",
    "WebSocket(", "ActiveXObject(", "atob(", "btoa(",
    "unescape(", "escape(", "decodeURI(", "decodeURIComponent(",
]

# Node.js APIs — shouldn't appear in SVGs, ever
NODE_APIS = [
    "child_process", "execSync", "exec(", "spawn(",
    "writeFileSync", "writeFile(", "appendFile(",
    "createWriteStream", "fs.write", "net.connect",
    "dgram.createSocket", "http.request", "https.request",
]

OBFUSCATION_PATTERNS = [
    (r"\\x[0-9a-fA-F]{2}", "hex_escape"),
    (r"\\u[0-9a-fA-F]{4}", "unicode_escape"),
    (r"String\.fromCharCode", "from_char_code"),
    (r"charCodeAt", "char_code_at"),
    (r"_0x[0-9a-fA-F]{4,}", "hex_var_name"),
    (r"split\([\"']{2}\)", "empty_split"),
    (r"join\([\"']{2}\)", "empty_join"),
    (r"parseInt\(str", "parse_int_obf"),
    (r"substr\(.*?\)", "substr_obf"),
    (r"replace\(\.\+", "regex_obf"),
    (r"concat\(.*?\)", "concat_obf"),
    (r"prototype\s*=", "prototype_pollution"),
    (r"__proto__", "proto_reference"),
]

XXE_DOCTYPE = re.compile(r"<!DOCTYPE\s+\w+\s*\[", re.IGNORECASE)
XXE_ENTITY = re.compile(r"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+", re.IGNORECASE)
SCRIPT_TAG = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
EVENT_HANDLER = re.compile(r'(?:{})\s*=\s*(["\'])(.*?)\1'.format("|".join(re.escape(e) for e in AUTO_FIRE_EVENTS)), re.IGNORECASE)
DATA_URI = re.compile(r'data:(?:text/html|text/javascript|application/javascript|image/svg\+xml)(?:;base64)?,([^"\')\s]+)', re.IGNORECASE)
FOREIGN_OBJECT = re.compile(r"<foreignObject[^>]*>(.*?)</foreignObject>", re.IGNORECASE | re.DOTALL)
JAVASCRIPT_URI = re.compile(r'href\s*=\s*(["\'])\s*javascript:([^"\']+)\1', re.IGNORECASE)
EXTERNAL_LINK = re.compile(r'(?:href|xlink:href)\s*=\s*(["\'])(https?://[^"\']+)\1', re.IGNORECASE)
CSS_EXPRESSION = re.compile(r'(?:expression|javascript)\s*:', re.IGNORECASE)
ATOB_B64 = re.compile(r'(?:btoa|atob)\s*\(\s*(["\'])([A-Za-z0-9+/=]{20,})\1\s*\)')
LONG_B64 = re.compile(r'([A-Za-z0-9+/]{20,}={0,2})')


@register_analyzer
class SVGVectorAnalyzer(BaseAnalyzer):
    name = "svg_vector"
    description = "Deep SVG inspection: scripts, event handlers, XXE, data URIs, foreign objects"
    priority = 10

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.is_svg or entry.detected_mime == "image/svg+xml"

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings = []
        p = entry.path

        check_xxe(content, p, findings)
        check_scripts(content, p, findings)
        check_event_handlers(content, p, findings)
        check_data_uris(content, p, findings)
        check_foreign_objects(content, p, findings)
        check_js_uris(content, p, findings)
        check_obfuscation_outside_scripts(content, p, findings)
        check_external_links(content, p, findings)
        check_css_expressions(content, p, findings)

        return AnalyzerResult(findings)


def check_xxe(content, path, findings):
    if XXE_DOCTYPE.search(content) and XXE_ENTITY.search(content):
        findings.append(Finding(
            path, Severity.CRITICAL, Confidence.HIGH, Category.SVG_XXE,
            title="SVG contains XML External Entity (XXE) declaration",
            description="XXE can read local files, SSRF internal services, or DoS the parser. "
                        "Attackers use it to exfiltrate /etc/passwd, cloud metadata, or env files.",
            attack_path="SVG parsed -> XXE expands -> file read / SSRF -> data exfiltration",
            remediation="Strip DOCTYPE and ENTITY declarations. Parse with XXE disabled.",
        ))


def check_scripts(content, path, findings):
    for match in SCRIPT_TAG.finditer(content):
        body = match.group(1).strip()
        if not body:
            continue
        line = line_of(content, match.start())

        if is_obfuscated(body):
            findings.append(Finding(
                path, Severity.HIGH, Confidence.HIGH, Category.OBFUSCATED_SCRIPT,
                title="SVG <script> contains obfuscated JavaScript",
                description="Uses hex escapes, encoding, or other obfuscation to hide intent from reviewers.",
                attack_path="SVG rendered/built -> script executes -> contacts C2 -> downloads payload",
                remediation="Remove <script> from SVGs. Vectors don't need scripts.",
                line_number=line, snippet=trunc(body, 300),
            ))

        for func in EXEC_FUNCS:
            if func.lower() in body.lower():
                sev = Severity.CRITICAL if func in ("eval(", "exec(", "Function(") else Severity.HIGH
                findings.append(Finding(
                    path, sev, Confidence.HIGH, Category.SUSPICIOUS_JS_API,
                    title=f"SVG script uses '{func}' — can execute arbitrary code",
                    description=f"'{func}' evaluates strings as code. This is how attackers run payloads.",
                    attack_path="SVG script -> eval/exec -> arbitrary code execution",
                    remediation=f"Remove {func} from SVGs entirely.",
                    line_number=line, snippet=trunc(body, 300),
                ))

        for api in NODE_APIS:
            if api in body.lower():
                findings.append(Finding(
                    path, Severity.CRITICAL, Confidence.MEDIUM, Category.SUSPICIOUS_NODE_API,
                    title=f"SVG script uses Node.js API '{api}'",
                    description="Node APIs in SVG mean it expects a server runtime — likely triggered during build/install.",
                    attack_path="Build pipeline -> SVG parsed -> Node API runs -> system compromise",
                    remediation="Kill it. Node APIs have no place in vector graphics.",
                    line_number=line, snippet=trunc(body, 300),
                ))

        _safe_domains = {"cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                          "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
                          "fonts.googleapis.com", "ajax.googleapis.com",
                          "cdn.skypack.dev", "esm.sh"}
        for url in re.findall(r'https?://([^\s"\'<>)]+)', body):
            domain = url.split("/")[0]
            if domain not in _safe_domains:
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.RUNTIME_NETWORK_CALL,
                    title="SVG script phones home to external URL",
                    description=f"Script contacts {url} — potential C2 or payload download.",
                    attack_path="SVG script -> HTTP request -> attacker server -> payload retrieval",
                    remediation="Remove network calls from SVGs. SVGs don't phone home.",
                    line_number=line, raw_value=url,
                ))


def check_event_handlers(content, path, findings):
    for match in EVENT_HANDLER.finditer(content):
        val = match.group(2)
        line = line_of(content, match.start())
        decoded = try_base64_decode(val)

        findings.append(Finding(
            path, Severity.HIGH, Confidence.HIGH, Category.SVG_EVENT_HANDLER,
            title=f"Inline '{match.group(0).split('=')[0]}' handler executes JS",
            description=f"Handler: {trunc(val, 200)}",
            attack_path=f"SVG rendered -> event fires -> JS executes -> malicious action",
            remediation="Remove inline handlers. SVGs should not run code.",
            line_number=line, snippet=val, decoded=decoded,
        ))

        if decoded and "eval" in decoded.lower():
            findings.append(Finding(
                path, Severity.CRITICAL, Confidence.HIGH, Category.ENCODED_PAYLOAD,
                title="Base64-encoded eval in SVG event handler",
                description="atob(...) decodes to eval() call — classic obfuscation for hiding payloads.",
                attack_path="SVG rendered -> onload fires -> base64 decode -> eval() -> RCE",
                remediation="Remove entirely. This is a dropper.",
                line_number=line, decoded=decoded,
            ))


def check_data_uris(content, path, findings):
    for match in DATA_URI.finditer(content):
        data = match.group(1)
        line = line_of(content, match.start())
        decoded = try_base64_decode(data)
        if decoded and any(kw in decoded.lower() for kw in ["script", "eval(", "onload", "javascript:", "fetch("]):
            findings.append(Finding(
                path, Severity.CRITICAL, Confidence.HIGH, Category.SVG_DATA_URI,
                title="Data URI contains executable JS",
                description=f"Decodes to: {trunc(decoded, 200)}",
                attack_path="Data URI parsed -> content executed -> script runs -> compromise",
                remediation="Remove data URIs with executable content from SVGs.",
                line_number=line, decoded=decoded,
            ))


def check_foreign_objects(content, path, findings):
    for match in FOREIGN_OBJECT.finditer(content):
        inner = match.group(1)
        if any(kw in inner.lower() for kw in ["<script", "onload", "onerror", "javascript:"]):
            findings.append(Finding(
                path, Severity.HIGH, Confidence.MEDIUM, Category.SVG_FOREIGN_OBJECT,
                title="SVG <foreignObject> sneaks in executable HTML/JS",
                description="foreignObject can embed HTML with scripts. Bypasses scanners that only check <svg>.",
                attack_path="SVG rendered -> foreignObject parsed -> embedded script executes",
                remediation="Remove <foreignObject> or sanitize its contents.",
        line_number=line_of(content, match.start()),
            ))


def check_js_uris(content, path, findings):
    for match in JAVASCRIPT_URI.finditer(content):
        js = match.group(2)
        findings.append(Finding(
            path, Severity.HIGH, Confidence.HIGH, Category.SVG_EVENT_HANDLER,
            title="javascript: URI in SVG link",
            description=f"Link executes: {trunc(js, 200)}",
            attack_path="User clicks -> javascript: URI executes -> XSS / redirect",
            remediation="Remove javascript: URIs from SVGs.",
            line_number=line_of(content, match.start()), snippet=js,
        ))


def check_obfuscation_outside_scripts(content, path, findings):
    script_bodies = set()
    for m in SCRIPT_TAG.finditer(content):
        script_bodies.add(m.group(1).strip())

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or len(stripped) < 20 or stripped in script_bodies:
            continue
        if is_obfuscated(stripped):
            findings.append(Finding(
                path, Severity.HIGH, Confidence.MEDIUM, Category.OBFUSCATED_ENCODING,
                title="Obfuscated string outside <script> tags",
                description=f"Line contains obfuscation indicators: {trunc(stripped, 200)}",
                attack_path="Build tooling may process this unsafely",
                remediation="Review and remove obfuscated content.",
                line_number=i, snippet=stripped,
            ))


def check_external_links(content, path, findings):
    for match in EXTERNAL_LINK.finditer(content):
        url = match.group(2)
        findings.append(Finding(
            path, Severity.LOW, Confidence.LOW, Category.C2_CALLBACK,
            title="SVG links to external URL",
            description=f"External resource: {url}",
            attack_path="SVG rendered -> fetches external resource -> tracking / SSRF",
            remediation="Verify external URLs are necessary and trusted.",
            line_number=line_of(content, match.start()), raw_value=url,
        ))


def check_css_expressions(content, path, findings):
    for match in CSS_EXPRESSION.finditer(content):
        findings.append(Finding(
            path, Severity.HIGH, Confidence.MEDIUM, Category.SVG_EVENT_HANDLER,
            title="CSS expression or javascript: in style context",
            description="CSS expressions can execute JS in some renderers (old IE, some parsers).",
            attack_path="SVG rendered -> CSS expression evaluated -> JS execution",
            remediation="Remove CSS expressions from SVG styles.",
            line_number=line_of(content, match.start()),
        ))


def is_obfuscated(text: str) -> bool:
    if len(text) < 40:
        return False
    score = 0
    for pat, _ in OBFUSCATION_PATTERNS:
        if re.search(pat, text):
            score += 1
    return score >= 2


def try_base64_decode(text: str) -> Optional[str]:
    for match in ATOB_B64.finditer(text):
        try:
            return base64.b64decode(match.group(2)).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            log.debug("atob decode failed: %s", exc)
    long_match = LONG_B64.search(text)
    if long_match:
        try:
            return base64.b64decode(long_match.group(1)).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            log.debug("base64 decode failed: %s", exc)
    return None






