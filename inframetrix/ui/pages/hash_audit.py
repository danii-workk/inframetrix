"""Password Storage & Hash Audit Page."""

from __future__ import annotations

try:
    from PySide6.QtWidgets import (
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]

from inframetrix.engines.hash_audit.analyzer import HashAnalyzer
from inframetrix.engines.hash_audit.local_lookup import LocalLookup


class HashAuditPage(QWidget):
    """Defensive password storage and cryptographic hash strength auditor."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(15, 15, 15, 15)

            title = QLabel("<h2>Password Storage & Hash Security Audit</h2>")
            layout.addWidget(title)

            # Input bar
            bar = QHBoxLayout()
            self.hash_input = QLineEdit()
            self.hash_input.setPlaceholderText("Paste password hash (e.g. 5f4dcc3b5aa765d61d8327deb882cf99 or $argon2id$...)")

            self.audit_btn = QPushButton("🔒 Audit Hash")
            self.audit_btn.clicked.connect(self._audit_hash)

            bar.addWidget(self.hash_input)
            bar.addWidget(self.audit_btn)
            layout.addLayout(bar)

            # Results Area
            self.result_frame = QFrame()
            self.result_frame.setStyleSheet("background: #1e293b; border-radius: 8px; padding: 15px;")
            r_layout = QVBoxLayout(self.result_frame)

            self.algo_lbl = QLabel("<strong>Algorithm:</strong> -")
            self.risk_lbl = QLabel("<strong>Security Assessment:</strong> -")
            self.reason_txt = QTextEdit()
            self.reason_txt.setReadOnly(True)

            r_layout.addWidget(self.algo_lbl)
            r_layout.addWidget(self.risk_lbl)
            r_layout.addWidget(QLabel("<strong>Security Analysis & Recommendations:</strong>"))
            r_layout.addWidget(self.reason_txt)

            layout.addWidget(self.result_frame)

    def _audit_hash(self) -> None:
        raw = self.hash_input.text().strip()
        if not raw:
            return

        assessment = HashAnalyzer.assess_hash(raw)
        self.algo_lbl.setText(f"<strong>Algorithm Detected:</strong> {assessment.algorithm} ({'Salted' if assessment.is_salted else 'Unsalted'})")

        color_map = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "secure": "#10b981",
        }
        c = color_map.get(assessment.risk_level, "#94a3b8")
        self.risk_lbl.setText(f"<strong>Security Assessment:</strong> <span style='color:{c}; font-weight:bold;'>{assessment.risk_level.upper()}</span>")

        report = f"Risk Reason:\n{assessment.reason}\n\nRecommendation:\n{assessment.recommendation}"

        # Check offline dictionary
        cleartext = LocalLookup.audit_hash(raw)
        if cleartext:
            report += f"\n\n⚠️ CRITICAL: Password hash matches common dictionary password: '{cleartext}'"

        self.reason_txt.setPlainText(report)
