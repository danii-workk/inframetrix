"""Typer CLI entry point for InfraMetrix."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from inframetrix import __version__
from inframetrix.scanner import scan_project

app = typer.Typer(
    name="inframetrix",
    help="Security, architecture, and infrastructure risk analyzer for AI-built projects.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[
        bool,
        typer.Option("--version", "-v", help="Show version and exit."),
    ] = False,
) -> None:
    """InfraMetrix - Security, architecture, and infrastructure risk analyzer for AI-built projects."""
    if version:
        typer.echo(f"inframetrix {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    path: Annotated[str, typer.Argument(help="Path to the project directory to scan.")],
    preset: Annotated[
        str,
        typer.Option("--preset", "-p", help="Scan preset: quick, full, web."),
    ] = "quick",
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json, markdown, sarif, html."),
    ] = "console",
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path for json, markdown, sarif or html reports."),
    ] = None,
    rules: Annotated[
        str | None,
        typer.Option("--rules", help="Path to a directory of YAML ruleset files."),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit code 1 if risk level >= threshold: info, low, medium, high, critical, never.",
        ),
    ] = "critical",
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output."),
    ] = False,
) -> None:
    """Scan a project directory for security, architecture, and AI-slop risks."""
    project_path = Path(path)

    if not project_path.is_dir():
        typer.echo(f"Error: '{path}' is not a valid directory.", err=True)
        raise typer.Exit(code=1)

    rules_path = Path(rules) if rules else None
    report = scan_project(project_path, rules_path=rules_path)

    # Output
    if format == "json":
        from inframetrix.reporters.json_report import render_json

        output_path = Path(output) if output else None
        result = render_json(report, output_path)
        if output_path is None:
            console = Console(no_color=no_color)
            console.print(result)
    elif format == "markdown":
        from inframetrix.reporters.markdown import render_markdown

        output_path = Path(output) if output else None
        result = render_markdown(report, output_path)
        if output_path is None:
            console = Console(no_color=no_color)
            console.print(result)
    else:
        from inframetrix.reporters.console import render_console

        render_console(report, no_color=no_color)

    # Fail-on logic
    if fail_on != "never":
        if fail_on not in SEVERITY_ORDER:
            typer.echo(f"Error: invalid --fail-on value '{fail_on}'.", err=True)
            raise typer.Exit(code=1)

        # Do not fail if there are no findings
        if not report.get("findings") or report.get("risk_score", 0) == 0:
            return

        threshold = SEVERITY_ORDER.index(fail_on)
        level_index = SEVERITY_ORDER.index(report["risk_level"]) if report["risk_level"] in SEVERITY_ORDER else -1

        if level_index >= threshold:
            raise typer.Exit(code=1)


@app.command()
def ui(
    project: Annotated[
        str | None,
        typer.Option("--project", "-p", help="Initial project path to open in GUI."),
    ] = None,
) -> None:
    """Launch the InfraMetrix Desktop AppSec Workstation (PySide6 GUI)."""
    try:
        from inframetrix.ui.app import launch_app  # type: ignore[import-not-found]

        launch_app(initial_project=project)
    except ImportError as exc:
        typer.echo(
            f"PySide6 desktop dependencies not found ({exc}).\n"
            "Install desktop dependencies with: pip install \"inframetrix[desktop]\" or pip install PySide6",
            err=True,
        )
        raise typer.Exit(code=1) from exc