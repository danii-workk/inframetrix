"""Reports Export Page."""

from __future__ import annotations

from pathlib import Path

try:
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import (
        QFileDialog,
        QFrame,
        QGridLayout,
        QLabel,
        QMessageBox,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.services.report_service import ReportService


class ReportsPage(QWidget):
    """Export scan results into multiple machine-readable and visual formats."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.current_report_data: dict | None = None

        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(20, 20, 20, 20)

            title = QLabel("<h2>Export Security Reports</h2>")
            layout.addWidget(title)

            grid = QGridLayout()

            # HTML Report
            grid.addWidget(self._create_export_card("🌐 Offline HTML Report", "Interactive dashboard viewable in any browser.", "html", "report.html"), 0, 0)
            # SARIF Report
            grid.addWidget(self._create_export_card("📄 OASIS SARIF v2.1.0", "GitHub Security & VS Code compatible static analysis format.", "sarif", "report.sarif"), 0, 1)
            # JSON Report
            grid.addWidget(self._create_export_card("📊 JSON Report", "Standard raw data export for CI/CD integration.", "json", "report.json"), 1, 0)
            # Markdown Report
            grid.addWidget(self._create_export_card("📝 Markdown Report", "Human-readable summary for pull requests & documentation.", "markdown", "report.md"), 1, 1)

            layout.addLayout(grid)
            layout.addStretch()

    def set_report_data(self, report_data: dict) -> None:
        self.current_report_data = report_data

    def _create_export_card(self, title: str, desc: str, fmt: str, default_name: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet("background: #1e293b; border-radius: 8px; padding: 15px;")
        l = QVBoxLayout(card)
        t = QLabel(f"<h3>{title}</h3>")
        d = QLabel(desc)
        d.setStyleSheet("color: #94a3b8;")
        btn = QPushButton(f"Export {fmt.upper()}")
        btn.clicked.connect(lambda: self._export(fmt, default_name))
        l.addWidget(t)
        l.addWidget(d)
        l.addWidget(btn)
        return card

    def _export(self, fmt: str, default_name: str) -> None:
        if not self.current_report_data:
            QMessageBox.warning(self, "No Scan Data", "Please perform a scan before exporting reports.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, f"Save {fmt.upper()} Report", default_name)
        if file_path:
            p = Path(file_path)
            ReportService.export_report(self.current_report_data, format_type=fmt, output_path=p)
            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{p}")
