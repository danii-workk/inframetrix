"""Supply Chain & CI/CD Security Page."""

from __future__ import annotations

try:
    from PySide6.QtWidgets import (
        QLabel,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]

from inframetrix.models.finding import Finding
from inframetrix.ui.widgets.findings_table import FindingsTableWidget


class SupplyChainPage(QWidget):
    """Supply chain hygiene and CI/CD workflow security auditor."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(15, 15, 15, 15)

            title = QLabel("<h2>Supply Chain & CI/CD Security</h2>")
            layout.addWidget(title)

            self.table = FindingsTableWidget()
            layout.addWidget(self.table)

    def set_findings(self, findings: list[Finding]) -> None:
        sc_findings = [f for f in findings if f.source_engine == "supply-chain"]
        self.table.set_findings(sc_findings)
