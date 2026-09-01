"""Report generation service coordinating all export formats."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inframetrix.reporters.console import render_console
from inframetrix.reporters.html import render_html
from inframetrix.reporters.json_report import render_json
from inframetrix.reporters.markdown import render_markdown
from inframetrix.reporters.sarif import render_sarif


class ReportService:
    """Exports scan reports into machine-readable and visual formats."""

    @staticmethod
    def export_report(
        report: dict[str, Any],
        format_type: str,
        output_path: Path | None = None,
        no_color: bool = False,
    ) -> str:
        """Render report into target format."""
        fmt = format_type.lower()
        if fmt == "json":
            return render_json(report, output_path)
        if fmt == "markdown" or fmt == "md":
            return render_markdown(report, output_path)
        if fmt == "sarif":
            return render_sarif(report, output_path)
        if fmt == "html":
            return render_html(report, output_path)
        if fmt == "console":
            render_console(report, no_color=no_color)
            return ""

        raise ValueError(f"Unsupported report format '{format_type}'.")
