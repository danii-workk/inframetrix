"""Visual Risk Score Gauge Widget."""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QFont, QPainter, QPen
    from PySide6.QtWidgets import QWidget
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]


class RiskGaugeWidget(QWidget):
    """Circular risk gauge showing numerical score and colored severity level."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._score = 0
        self._level = "LOW"
        if hasattr(self, "setMinimumSize"):
            self.setMinimumSize(140, 140)

    def set_score(self, score: float, level: str) -> None:
        self._score = int(score)
        self._level = str(level).upper()
        if hasattr(self, "update"):
            self.update()

    def paintEvent(self, event) -> None:
        if not hasattr(self, "width"):
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        side = min(w, h)
        rect = self.rect()

        # Choose color
        color_map = {
            "CRITICAL": QColor("#ef4444"),
            "HIGH": QColor("#f97316"),
            "MEDIUM": QColor("#eab308"),
            "LOW": QColor("#3b82f6"),
        }
        color = color_map.get(self._level, QColor("#3b82f6"))

        # Background track
        pen_bg = QPen(QColor("#334155"), 12)
        painter.setPen(pen_bg)
        margin = 16
        painter.drawArc(margin, margin, side - 2 * margin, side - 2 * margin, -90 * 16, 360 * 16)

        # Active progress arc
        pen_fg = QPen(color, 12)
        pen_fg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_fg)
        angle = int((self._score / 100.0) * 360 * 16)
        painter.drawArc(margin, margin, side - 2 * margin, side - 2 * margin, 90 * 16, -angle)

        # Center Text
        painter.setPen(QColor("#f8fafc"))
        font = QFont("sans-serif", 20, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{self._score}")

        painter.setPen(color)
        font_sub = QFont("sans-serif", 10, QFont.Weight.Bold)
        painter.setFont(font_sub)
        sub_rect = rect.adjusted(0, 45, 0, 0)
        painter.drawText(sub_rect, Qt.AlignmentFlag.AlignCenter, self._level)
