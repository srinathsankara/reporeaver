"""Generate self-contained HTML dashboard from scan results."""

import html
import json
from typing import Dict, List

from ..models import ScanResult

DASHBOARD_CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
header{text-align:center;padding:30px 0;border-bottom:1px solid #30363d;margin-bottom:30px}
h1{color:#58a6ff;font-size:28px}
h2{color:#f0f6fc;margin:20px 0 10px;font-size:18px}
.score-card{display:flex;gap:15px;justify-content:center;flex-wrap:wrap;margin:20px 0}
.score{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center;min-width:140px}
.score .label{font-size:12px;color:#8b949e;text-transform:uppercase}
.score .value{font-size:28px;font-weight:700;margin-top:5px}
.score.critical .value{color:#f85149}
.score.high .value{color:#d29922}
.score.medium .value{color:#58a6ff}
.score.low .value{color:#3fb950}
.severity-filters{display:flex;gap:10px;margin:20px 0;flex-wrap:wrap}
.filter-btn{padding:8px 16px;border:1px solid #30363d;border-radius:6px;background:#161b22;color:#c9d1d9;cursor:pointer;font-size:13px}
.filter-btn:hover{background:#21262d}
.filter-btn.active{border-color:#58a6ff;color:#58a6ff}
.finding{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}
.finding.critical{border-left:4px solid #f85149}
.finding.high{border-left:4px solid #d29922}
.finding.medium{border-left:4px solid #58a6ff}
.finding.low{border-left:4px solid #3fb950}
.finding-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px}
.finding-title{font-weight:600;color:#f0f6fc;font-size:15px}
.finding-severity{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase}
.severity-critical{background:#f8514920;color:#f85149;border:1px solid #f8514940}
.severity-high{background:#d2992220;color:#d29922;border:1px solid #d2992240}
.severity-medium{background:#58a6ff20;color:#58a6ff;border:1px solid #58a6ff40}
.severity-low{background:#3fb95020;color:#3fb950;border:1px solid #3fb95040}
.finding-meta{font-size:12px;color:#8b949e;margin:6px 0}
.finding-desc{font-size:13px;color:#c9d1d9;margin:8px 0;line-height:1.5}
.finding-path{font-size:12px;color:#8b949e;margin-top:4px}
pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;margin:8px 0;overflow-x:auto;font-size:12px;color:#7ee787}
.summary-bar{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin:20px 0}
.summary-bar .stat{display:inline-block;margin-right:24px}
.summary-bar .stat .num{font-size:24px;font-weight:700}
.summary-bar .stat .lbl{font-size:12px;color:#8b949e}
.hidden{display:none}
"""

DASHBOARD_JS = """
let findings = [];
let filterSeverity = null;

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function render() {
  const container = document.getElementById('findings');
  container.innerHTML = '';
  const filtered = filterSeverity
    ? findings.filter(f => f.severity === filterSeverity)
    : findings;

  if (filtered.length === 0) {
    container.innerHTML = '<p style="color:#8b949e;text-align:center;padding:40px">No findings match this filter.</p>';
    return;
  }

  filtered.forEach(f => {
    const sev = f.severity || 'info';
    const div = document.createElement('div');
    div.className = `finding ${sev}`;
    div.innerHTML = `
      <div class="finding-header">
        <span class="finding-title">${escapeHtml(f.title)}</span>
        <span class="finding-severity severity-${sev}">${sev}</span>
      </div>
      <div class="finding-meta">
        ${escapeHtml(f.file)}${f.line ? ', line ' + f.line : ''} &middot; confidence: ${f.confidence || 'medium'}
      </div>
      ${f.description ? `<div class="finding-desc">${escapeHtml(f.description)}</div>` : ''}
      ${f.attack_path ? `<pre>Attack chain: ${escapeHtml(f.attack_path)}</pre>` : ''}
      ${f.remediation ? `<pre>Remediation: ${escapeHtml(f.remediation)}</pre>` : ''}
      ${f.decoded ? `<pre>Decoded: ${escapeHtml(f.decoded)}</pre>` : ''}
      ${f.raw ? `<pre>Raw: ${escapeHtml(f.raw)}</pre>` : ''}
    `;
    container.appendChild(div);
  });
}

function setFilter(sev) {
  filterSeverity = sev;
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.severity === (sev || 'all'));
  });
  render();
}
"""


def render_html(result: ScanResult, output_path: str):
    data = result.to_dict()
    risk = data.get("risk_score", {}) or {}

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RepoReaver Report — {html.escape(result.target)}</title>
<style>{DASHBOARD_CSS}</style>
</head>
<body>
<header>
  <h1>RepoReaver Security Gate Report</h1>
  <p style="color:#8b949e;margin-top:6px">
    Target: {html.escape(result.target)} &middot; {html.escape(str(result.files_scanned))} files scanned &middot; {html.escape(str(result.scan_time))}
  </p>
</header>

<div class="score-card">
  <div class="score critical">
    <div class="label">Risk Score</div>
    <div class="value">{html.escape(str(risk.get("score", 0)))}/10</div>
  </div>
  <div class="score critical">
    <div class="label">Critical</div>
    <div class="value">{html.escape(str(risk.get("critical", 0)))}</div>
  </div>
  <div class="score high">
    <div class="label">High</div>
    <div class="value">{html.escape(str(risk.get("high", 0)))}</div>
  </div>
  <div class="score medium">
    <div class="label">Medium</div>
    <div class="value">{html.escape(str(risk.get("medium", 0)))}</div>
  </div>
  <div class="score low">
    <div class="label">Low</div>
    <div class="value">{html.escape(str(risk.get("low", 0)))}</div>
  </div>
</div>

<div class="severity-filters">
  <button class="filter-btn active" data-severity="all" onclick="setFilter(null)">All ({html.escape(str(risk.get("total", 0)))})</button>
  <button class="filter-btn" data-severity="critical" onclick="setFilter('critical')">Critical ({html.escape(str(risk.get("critical", 0)))})</button>
  <button class="filter-btn" data-severity="high" onclick="setFilter('high')">High ({html.escape(str(risk.get("high", 0)))})</button>
  <button class="filter-btn" data-severity="medium" onclick="setFilter('medium')">Medium ({html.escape(str(risk.get("medium", 0)))})</button>
  <button class="filter-btn" data-severity="low" onclick="setFilter('low')">Low ({html.escape(str(risk.get("low", 0)))})</button>
</div>

<div id="findings"></div>

<script id="scan-data" type="application/json">{json.dumps(data.get("findings", []), ensure_ascii=True, default=str)}</script>
<script>
findings = JSON.parse(document.getElementById('scan-data').textContent);
render();
{DASHBOARD_JS}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
