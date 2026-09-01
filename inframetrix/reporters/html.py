"""Self-contained interactive offline HTML report generator."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from inframetrix.models.finding import Finding


def render_html(report: dict[str, Any], output_path: Path | None = None) -> str:
    """Generate modern, offline, interactive HTML report."""
    findings: list[Finding] = report.get("findings", [])
    project = html.escape(str(report.get("project", "Project")))
    risk_score = report.get("risk_score", 0)
    risk_level = str(report.get("risk_level", "low")).upper()

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>InfraMetrix Security Report - {project}</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
    --info: #64748b;
    --accent: #6366f1;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .title {{ font-size: 1.8rem; font-weight: bold; }}
  .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: bold; font-size: 0.875rem; }}
  .badge-critical {{ background: var(--critical); color: white; }}
  .badge-high {{ background: var(--high); color: white; }}
  .badge-medium {{ background: var(--medium); color: black; }}
  .badge-low {{ background: var(--low); color: white; }}
  .badge-info {{ background: var(--info); color: white; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; }}
  .card-val {{ font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }}
  .search-box {{ width: 100%; padding: 0.75rem 1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem; color: var(--text); margin-bottom: 1.5rem; font-size: 1rem; }}
  .table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 0.5rem; overflow: hidden; }}
  .table th, .table td {{ padding: 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
  .table th {{ background: rgba(0,0,0,0.2); color: var(--text-muted); font-size: 0.875rem; text-transform: uppercase; }}
  .table tr:hover {{ background: rgba(255,255,255,0.02); }}
  .rec {{ color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="title">🛡️ InfraMetrix Security Report</div>
      <div style="color: var(--text-muted); margin-top: 0.25rem;">Project: <strong>{project}</strong></div>
    </div>
    <div>
      <span class="badge badge-{risk_level.lower()}">RISK SCORE: {risk_score}/100 [{risk_level}]</span>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div style="color: var(--text-muted);">Total Findings</div>
      <div class="card-val">{len(findings)}</div>
    </div>
    <div class="card" style="border-left: 4px solid var(--critical);">
      <div style="color: var(--critical);">Critical</div>
      <div class="card-val">{sev_counts['critical']}</div>
    </div>
    <div class="card" style="border-left: 4px solid var(--high);">
      <div style="color: var(--high);">High</div>
      <div class="card-val">{sev_counts['high']}</div>
    </div>
    <div class="card" style="border-left: 4px solid var(--medium);">
      <div style="color: var(--medium);">Medium</div>
      <div class="card-val">{sev_counts['medium']}</div>
    </div>
    <div class="card" style="border-left: 4px solid var(--low);">
      <div style="color: var(--low);">Low</div>
      <div class="card-val">{sev_counts['low']}</div>
    </div>
  </div>

  <input type="text" id="filterInput" class="search-box" placeholder="Filter findings by title, file, CVE, or engine..." onkeyup="filterTable()">

  <table class="table" id="findingsTable">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Title & Recommendation</th>
        <th>Engine</th>
        <th>Location</th>
      </tr>
    </thead>
    <tbody>
"""

    for f in findings:
        loc = html.escape(str(f.file_path or f.url or "-"))
        if f.line:
            loc += f":{f.line}"
        rec = f'<div class="rec">💡 {html.escape(f.recommendation)}</div>' if f.recommendation else ""
        html_content += f"""
      <tr>
        <td><span class="badge badge-{f.severity}">{f.severity.upper()}</span></td>
        <td>
          <strong>{html.escape(f.title)}</strong>
          <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem;">{html.escape(f.message or f.description or '')}</div>
          {rec}
        </td>
        <td><code>{html.escape(f.source_engine)}</code></td>
        <td><code>{loc}</code></td>
      </tr>
"""

    html_content += """
    </tbody>
  </table>
</div>
<script>
  function filterTable() {
    const val = document.getElementById('filterInput').value.toLowerCase();
    const rows = document.querySelectorAll('#findingsTable tbody tr');
    rows.forEach(row => {
      const text = row.innerText.toLowerCase();
      row.style.display = text.includes(val) ? '' : 'none';
    });
  }
</script>
</body>
</html>
"""

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")

    return html_content
