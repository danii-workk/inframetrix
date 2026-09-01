"""Code viewer widget with line numbers and vulnerability highlight."""

from __future__ import annotations

from pathlib import Path

try:
    from PySide6.QtGui import QFont, QTextCursor
    from PySide6.QtWidgets import (
        QPlainTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]


class CodeViewerWidget(QWidget):
    """Source code snippet inspector with highlight for vulnerable lines."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            self.editor = QPlainTextEdit()
            self.editor.setReadOnly(True)
            font = QFont("Consolas, Courier New, monospace", 11)
            self.editor.setFont(font)
            layout.addWidget(self.editor)

    def load_file_snippet(self, file_path: str | Path, target_line: int | None = None) -> None:
        if not hasattr(self, "editor"):
            return

        p = Path(file_path)
        if not p.is_file():
            self.editor.setPlainText(f"File '{file_path}' not accessible.")
            return

        try:
            content = p.read_text(encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            self.editor.setPlainText(f"Error reading file: {exc}")
            return

        lines = content.splitlines()
        numbered_lines = [f"{i:4d} | {line}" for i, line in enumerate(lines, start=1)]
        self.editor.setPlainText("\n".join(numbered_lines))

        if target_line and 1 <= target_line <= len(lines):
            cursor = self.editor.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            for _ in range(target_line - 1):
                cursor.movePosition(QTextCursor.MoveOperation.Down)
            self.editor.setTextCursor(cursor)
            self.editor.centerCursor()
