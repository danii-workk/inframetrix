"""Interactive Findings Table Widget."""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import (
        QHeaderView,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.models.finding import Finding

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#64748b",
}


class FindingsTableWidget(QWidget):
    """Filterable table of security findings with selection signal."""

    finding_selected = Signal(object) if callable(Signal) else None

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.findings: list[Finding] = []
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            self.table = QTableWidget()
            self.table.setColumnCount(5)
            self.table.setHorizontalHeaderLabels(["Severity", "Title", "Category", "Engine", "Location"])
            self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.table.itemSelectionChanged.connect(self._on_selection_changed)
            layout.addWidget(self.table)

    def set_findings(self, findings: list[Finding]) -> None:
        self.findings = findings
        if not hasattr(self, "table"):
            return
        self.table.setRowCount(len(findings))

        for row, f in enumerate(findings):
            # Severity item
            sev_item = QTableWidgetItem(f.severity.upper())
            sev_color = QColor(SEVERITY_COLORS.get(f.severity, "#ffffff"))
            sev_item.setForeground(sev_color)
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            title_item = QTableWidgetItem(f.title)
            cat_item = QTableWidgetItem(f.category)
            eng_item = QTableWidgetItem(f.source_engine)

            loc_str = str(f.file_path or f.url or f.package_name or "-")
            if f.line:
                loc_str += f":{f.line}"
            loc_item = QTableWidgetItem(loc_str)

            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, title_item)
            self.table.setItem(row, 2, cat_item)
            self.table.setItem(row, 3, eng_item)
            self.table.setItem(row, 4, loc_item)

    def _on_selection_changed(self) -> None:
        selected_rows = self.table.selectedIndexes()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if 0 <= row < len(self.findings) and self.finding_selected:
            self.finding_selected.emit(self.findings[row])
