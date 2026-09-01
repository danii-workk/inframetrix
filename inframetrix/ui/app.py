"""Desktop application bootstrap entry point."""

from __future__ import annotations

import sys

try:
    from PySide6.QtWidgets import QApplication
except ImportError as exc:
    raise ImportError("PySide6 is not installed. Run: pip install inframetrix[desktop]") from exc

from inframetrix.ui.main_window import MainWindow


def launch_app(initial_project: str | None = None) -> int:
    """Initialize QApplication and show main window."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    window = MainWindow(initial_project=initial_project)
    window.show()

    return app.exec()
