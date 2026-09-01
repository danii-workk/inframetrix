"""Findings Page with detailed vulnerability inspector and triage actions."""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtWidgets import (
        QComboBox,
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QSplitter,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.models.finding import Finding
from inframetrix.ui.widgets.code_viewer import CodeViewerWidget
from inframetrix.ui.widgets.findings_table import FindingsTableWidget


class FindingsPage(QWidget):
    """Unified finding browser with inspection panel and triage action buttons."""

    status_changed = Signal(str, str) if callable(Signal) else None  # finding_id, new_status
    ask_ai_requested = Signal(object) if callable(Signal) else None

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.all_findings: list[Finding] = []
        self.active_finding: Finding | None = None

        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(15, 15, 15, 15)

            # Filter Bar
            filter_bar = QHBoxLayout()
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("Filter by title, CVE, CWE, or path...")
            self.search_input.textChanged.connect(self._apply_filter)

            self.sev_filter = QComboBox()
            self.sev_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info"])
            self.sev_filter.currentTextChanged.connect(self._apply_filter)

            filter_bar.addWidget(QLabel("🔍 Search:"))
            filter_bar.addWidget(self.search_input)
            filter_bar.addWidget(self.sev_filter)
            layout.addLayout(filter_bar)

            # Splitter: Left = Table, Right = Inspector
            splitter = QSplitter(Qt.Orientation.Horizontal)

            self.table_widget = FindingsTableWidget()
            if self.table_widget.finding_selected:
                self.table_widget.finding_selected.connect(self._on_finding_selected)
            splitter.addWidget(self.table_widget)

            # Right Inspector Frame
            inspector = QFrame()
            inspector.setStyleSheet("background: #1e293b; border-radius: 6px; padding: 10px;")
            insp_layout = QVBoxLayout(inspector)

            self.detail_title = QLabel("<h3>Select a finding</h3>")
            self.detail_meta = QLabel("")
            self.detail_meta.setStyleSheet("color: #94a3b8;")

            self.detail_desc = QTextEdit()
            self.detail_desc.setReadOnly(True)
            self.detail_desc.setMaximumHeight(120)

            self.code_viewer = CodeViewerWidget()

            # Actions bar
            actions = QHBoxLayout()
            self.tp_btn = QPushButton("✓ True Positive")
            self.tp_btn.clicked.connect(lambda: self._set_status("open"))

            self.fp_btn = QPushButton("✗ False Positive")
            self.fp_btn.setObjectName("btn-secondary")
            self.fp_btn.clicked.connect(lambda: self._set_status("false_positive"))

            self.accept_btn = QPushButton("Accept Risk")
            self.accept_btn.setObjectName("btn-secondary")
            self.accept_btn.clicked.connect(lambda: self._set_status("accepted_risk"))

            self.ai_btn = QPushButton("🤖 Ask AI Analyst")
            self.ai_btn.clicked.connect(self._ask_ai)

            actions.addWidget(self.tp_btn)
            actions.addWidget(self.fp_btn)
            actions.addWidget(self.accept_btn)
            actions.addWidget(self.ai_btn)

            insp_layout.addWidget(self.detail_title)
            insp_layout.addWidget(self.detail_meta)
            insp_layout.addWidget(self.detail_desc)
            insp_layout.addWidget(self.code_viewer)
            insp_layout.addLayout(actions)

            splitter.addWidget(inspector)
            splitter.setSizes([550, 450])
            layout.addWidget(splitter)

    def set_findings(self, findings: list[Finding]) -> None:
        self.all_findings = findings
        self._apply_filter()

    def _apply_filter(self) -> None:
        if not hasattr(self, "search_input"):
            return
        query = self.search_input.text().lower()
        sev = self.sev_filter.currentText().lower()

        filtered = []
        for f in self.all_findings:
            if sev != "all severities" and f.severity.lower() != sev:
                continue
            text_corpus = f"{f.title} {f.description or ''} {f.file_path or ''} {f.cve or ''} {f.cwe or ''}".lower()
            if query and query not in text_corpus:
                continue
            filtered.append(f)

        self.table_widget.set_findings(filtered)

    def _on_finding_selected(self, finding: Finding) -> None:
        self.active_finding = finding
        self.detail_title.setText(f"<h3>[{finding.severity.upper()}] {finding.title}</h3>")
        meta_txt = f"Engine: {finding.source_engine} | Category: {finding.category}"
        if finding.cve:
            meta_txt += f" | CVE: {finding.cve}"
        if finding.cwe:
            meta_txt += f" | {finding.cwe}"
        self.detail_meta.setText(meta_txt)

        desc = finding.description or finding.message
        if finding.recommendation:
            desc += f"\n\n💡 Recommendation:\n{finding.recommendation}"
        self.detail_desc.setPlainText(desc)

        if finding.file_path:
            self.code_viewer.load_file_snippet(finding.file_path, finding.line)

    def _set_status(self, status: str) -> None:
        if self.active_finding and self.status_changed:
            self.status_changed.emit(self.active_finding.id, status)
            self.active_finding.status = status  # type: ignore[assignment]

    def _ask_ai(self) -> None:
        if self.active_finding and self.ask_ai_requested:
            self.ask_ai_requested.emit(self.active_finding)
