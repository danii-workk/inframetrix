"""Rich-based console reporter."""

from __future__ import annotations

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


def render_console(report: dict) -> None:
    """Print the report to the terminal using Rich."""
    console = Console()

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

    table = Table(show_header=True, header_style="bold", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=20)
    table.add_column("File", min_width=16)
    table.add_column("Line", width=6, justify="right")
    table.add_column("Message", min_width=30)
    table.add_column("Recommendation", min_width=20)

    for f in findings:
        sev_color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            Text(f.severity.upper(), style=f"bold {sev_color}"),
            f.title,
            f.file_path,
            str(f.line) if f.line else "-",
            f.message,
            f.recommendation or "-",
        )

    console.print(table)
    console.print()