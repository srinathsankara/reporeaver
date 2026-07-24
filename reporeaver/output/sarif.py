"""SARIF output — static analysis results interchange format.

GitHub natively displays SARIF in the Security tab.
"""

from typing import Any, Dict, List

from ..models import Finding, Severity, ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
    Severity.ERROR: "error",
}


def render_sarif(result: ScanResult) -> Dict[str, Any]:
    """Render scan result as SARIF 2.1.0 document."""
    rules: Dict[str, dict] = {}
    results: List[dict] = []

    for i, f in enumerate(result.findings):
        rule_id = f"RR-{f.category.value.upper()}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.category.value,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": LEVEL_MAP.get(f.severity, "warning")},
                "helpUri": f"https://reporeaver.dev/rules/{f.category.value}",
                "properties": {
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "attack_path": f.attack_path,
                    "remediation": f.remediation,
                },
            }

        result_entry = {
            "ruleId": rule_id,
            "ruleIndex": list(rules.keys()).index(rule_id),
            "level": LEVEL_MAP.get(f.severity, "warning"),
            "message": {
                "text": f"{f.title}: {f.description}" if f.description else f.title,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file_path,
                    },
                },
            }],
        }

        if f.line_number:
            result_entry["locations"][0]["physicalLocation"]["region"] = {
                "startLine": f.line_number,
            }
        if f.snippet:
            result_entry["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.snippet,
            }

        if f.decoded:
            result_entry["properties"] = {
                "decoded": f.decoded,
            }

        results.append(result_entry)

    tool = {
        "driver": {
            "name": "reporeaver",
            "version": result.version,
            "informationUri": "https://github.com/reporeaver/reporeaver",
            "rules": list(rules.values()),
        }
    }

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": tool,
            "results": results,
            "properties": {
                "target": result.target,
                "files_scanned": result.files_scanned,
                "risk_score": result.risk_score.to_dict() if result.risk_score else None,
            },
        }],
    }

    return sarif_doc
