"""DAST (Dynamic Application Security Testing) Page."""

from __future__ import annotations

try:
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import (
        QCheckBox,
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


class DASTPage(QWidget):
    """Dynamic Application Security Testing page with TargetPolicy authorization."""

    scan_dast_requested = Signal(str, bool) if callable(Signal) else None  # url, allow_active

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(15, 15, 15, 15)

            title = QLabel("<h2>Dynamic Application Security Testing (DAST)</h2>")
            layout.addWidget(title)

            # Target Bar
            target_layout = QHBoxLayout()
            self.url_input = QLineEdit()
            self.url_input.setPlaceholderText("https://staging.example.com")

            self.active_cb = QCheckBox("Allow Active Scan (Exploratory attack payloads)")
            self.auth_btn = QPushButton("🎯 Start DAST Scan")
            self.auth_btn.clicked.connect(self._on_start)

            target_layout.addWidget(QLabel("Target URL:"))
            target_layout.addWidget(self.url_input)
            target_layout.addWidget(self.active_cb)
            target_layout.addWidget(self.auth_btn)
            layout.addLayout(target_layout)

            self.table = FindingsTableWidget()
            layout.addWidget(self.table)

    def _on_start(self) -> None:
        url = self.url_input.text().strip()
        if url and self.scan_dast_requested:
            self.scan_dast_requested.emit(url, self.active_cb.isChecked())

    def set_findings(self, findings: list[Finding]) -> None:
        dast_findings = [f for f in findings if f.source_engine == "zap-dast"]
        self.table.set_findings(dast_findings)
