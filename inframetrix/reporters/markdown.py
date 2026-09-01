"""Markdown report output."""

from __future__ import annotations

from pathlib import Path

from inframetrix.finding import Finding


def render_markdown(report: dict, output_path: Path | None = None) -> str:
    """Serialize the report as Markdown. Optionally write to a file."""
    findings: list[Finding] = report["findings"]

    rules_loaded = report.get("rules_loaded", [])
    lines: list[str] = [
        "# InfraMetrix Report",
        "",
        f"- **Project:** {report['project']}",
        f"- **Risk Score:** {report['risk_score']}/100",
        f"- **Risk Level:** {report['risk_level'].upper()}",
        f"- **Findings:** {len(findings)}",
    ]

    if rules_loaded:
        lines.append(f"- **Rules Loaded:** {len(rules_loaded)} ({', '.join(rules_loaded)})")

    lines.append("")

    if not findings:
        lines.append("No findings.")
    else:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            lines.append(f"### [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **ID:** {f.id}")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **File:** `{f.file_path}`")
            if f.line is not None:
                lines.append(f"- **Line:** {f.line}")
            lines.append(f"- **Message:** {f.message}")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")

    text = "\n".join(lines)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")

    return text