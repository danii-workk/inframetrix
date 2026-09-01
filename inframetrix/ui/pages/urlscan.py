"""urlscan.io Analysis Page."""

from __future__ import annotations

try:
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import (
        QComboBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.models.finding import Finding
from inframetrix.ui.widgets.findings_table import FindingsTableWidget


class URLScanPage(QWidget):
    """External website inspection and DOM/screenshot analysis."""

    scan_url_requested = Signal(str, str) if callable(Signal) else None  # url, visibility

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(15, 15, 15, 15)

            title = QLabel("<h2>urlscan.io URL Analysis</h2>")
            layout.addWidget(title)

            # Input bar
            bar = QHBoxLayout()
            self.url_input = QLineEdit()
            self.url_input.setPlaceholderText("https://example.com")

            self.vis_combo = QComboBox()
            self.vis_combo.addItems(["Unlisted", "Private", "Public"])

            self.scan_btn = QPushButton("🌐 Scan URL")
            self.scan_btn.clicked.connect(self._on_scan)

            bar.addWidget(QLabel("Target URL:"))
            bar.addWidget(self.url_input)
            bar.addWidget(QLabel("Visibility:"))
            bar.addWidget(self.vis_combo)
            bar.addWidget(self.scan_btn)
            layout.addLayout(bar)

            # Results
            self.table = FindingsTableWidget()
            layout.addWidget(self.table)

    def _on_scan(self) -> None:
        url = self.url_input.text().strip()
        vis = self.vis_combo.currentText().lower()
        if url and self.scan_url_requested:
            self.scan_url_requested.emit(url, vis)

    def set_findings(self, findings: list[Finding]) -> None:
        url_findings = [f for f in findings if f.source_engine == "urlscan"]
        self.table.set_findings(url_findings)
