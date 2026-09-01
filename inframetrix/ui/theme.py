"""Dark AppSec Workstation theme styling for PySide6."""

from __future__ import annotations

DARK_STYLE = """
QMainWindow, QDialog, QWidget {
    background-color: #0f172a;
    color: #f8fafc;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 13px;
}

QTabBar::tab {
    background: #1e293b;
    color: #94a3b8;
    padding: 8px 16px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}

QTabBar::tab:selected {
    background: #334155;
    color: #f8fafc;
    font-weight: bold;
}

QTableView, QTableWidget, QListView, QTreeView {
    background-color: #1e293b;
    border: 1px solid #334155;
    gridline-color: #334155;
    selection-background-color: #4f46e5;
    selection-color: #ffffff;
    color: #f8fafc;
    border-radius: 4px;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 6px;
    border: 1px solid #334155;
    font-weight: bold;
}

QPushButton {
    background-color: #6366f1;
    color: #ffffff;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #4f46e5;
}

QPushButton:pressed {
    background-color: #4338ca;
}

QPushButton:disabled {
    background-color: #334155;
    color: #64748b;
}

QPushButton#btn-danger {
    background-color: #ef4444;
}

QPushButton#btn-danger:hover {
    background-color: #dc2626;
}

QPushButton#btn-secondary {
    background-color: #334155;
    color: #f8fafc;
}

QPushButton#btn-secondary:hover {
    background-color: #475569;
}

QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 10px;
    color: #f8fafc;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #6366f1;
}

QProgressBar {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 4px;
    text-align: center;
    color: #f8fafc;
}

QProgressBar::chunk {
    background-color: #6366f1;
    border-radius: 3px;
}

QScrollBar:vertical {
    background: #0f172a;
    width: 10px;
}

QScrollBar::handle:vertical {
    background: #334155;
    border-radius: 5px;
}
"""
