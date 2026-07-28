"""Scan orchestration — entry point for all scans."""

import json
import logging
from pathlib import Path
from typing import Optional

from .config import RepoReaverConfig
from .output.html_dashboard import render_html
from .output.sarif import render_sarif
from .output.report import print_report
from .pipeline import ScanPipeline, EXIT_THRESHOLD
from .history import save_scan_history

log = logging.getLogger("reporeaver.engine")


def scan_target(
    target_path: Path,
    config: RepoReaverConfig,
    output_file: Optional[str] = None,
    html_output: Optional[str] = None,
    sarif_output: Optional[str] = None,
    verbose: bool = False,
    json_output: bool = False,
    save_history: bool = True,
) -> int:
    pipeline = ScanPipeline(target_path, config)
    result, elapsed = pipeline.run()

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"  JSON report: {output_file}")

    if sarif_output:
        sarif_doc = render_sarif(result)
        with open(sarif_output, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)
        print(f"  SARIF output: {sarif_output}")

    if html_output:
        render_html(result, html_output)
        print(f"  HTML dashboard: {html_output}")

    print_report(result, verbose=verbose, json_output=json_output)
    print(f"  Scan completed in {elapsed:.1f}s")
    print(f"{'-'*60}\n")

    if save_history:
        try:
            save_scan_history(result)
        except Exception as exc:
            log.warning("Failed to save scan history: %s", exc)

    risk_score = result.risk_score.score if result.risk_score else 0.0
    if risk_score >= EXIT_THRESHOLD or result.blocked:
        return 1
    return 0
