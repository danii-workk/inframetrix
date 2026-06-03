"""Rich-based console reporter."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from inframetrix.finding import Finding

SEVERITY_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "magenta",
    "medium": "yellow",
    "low": "blue",
    "info": "white",
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _relative_path(file_path: str, project_path: str) -> str:
    """Return a relative path from the project root."""
    try:
        return str(Path(file_path).relative_to(project_path))
    except ValueError:
        return file_path


def _severity_summary(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_console(report: dict, *, no_color: bool = False) -> None:
    """Print the report to the terminal using Rich."""
    console = Console(no_color=no_color)

    console.print()
    console.rule("[bold]InfraMetrix Report[/bold]")
    console.print()

    console.print(f"  Project:   [bold]{report['project']}[/bold]")
    console.print(f"  Path:      {report['path']}")
    rules_loaded = report.get("rules_loaded", [])
    if rules_loaded:
        console.print(f"  Rules:     {len(rules_loaded)} loaded ({', '.join(rules_loaded)})")
    console.print()

    score = report["risk_score"]
    level = report["risk_level"]
    color = SEVERITY_COLORS.get(level, "white")

    score_text = Text()
    score_text.append(f"  Risk Score: {score}/100  ", style="bold")
    score_text.append(f"[{level.upper()}]", style=f"bold {color}")
    console.print(score_text)

    findings: list[Finding] = report["findings"]
    console.print(f"  Findings:  {len(findings)}")
    console.print()
    console.rule()
    console.print()

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    # Severity summary
    summary = _severity_summary(findings)
    summary_parts = []
    for sev in reversed(SEVERITY_ORDER):
        count = summary.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            summary_parts.append(f"[bold {color}]{count} {sev}[/bold {color}]")
    if summary_parts:
        console.print(f"  Summary: {' | '.join(summary_parts)}")
        console.print()

    table = Table(show_header=True, header_style="bold", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=20)
    table.add_column("File", min_width=16)
    table.add_column("Line", width=6, justify="right")
    table.add_column("Message", min_width=30)
    table.add_column("Recommendation", min_width=20)

    project_path = report.get("path", "")

    for f in findings:
        sev_color = SEVERITY_COLORS.get(f.severity, "white")
        rel_file = _relative_path(f.file_path, project_path)
        table.add_row(
            Text(f.severity.upper(), style=f"bold {sev_color}"),
            f.title,
            rel_file,
            str(f.line) if f.line else "-",
            f.message,
            f.recommendation or "-",
        )

    console.print(table)
    console.print()