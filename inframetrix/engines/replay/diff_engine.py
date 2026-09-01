"""Unified diff computation engine."""

from __future__ import annotations

import difflib


class DiffEngine:
    """Computes standard unified diffs between snapshots."""

    @staticmethod
    def compute_diff(old_text: str, new_text: str, filename: str = "file") -> str:
        """Generate unified diff text."""
        old_lines = old_text.splitlines(keepends=True)
        new_lines = new_text.splitlines(keepends=True)

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff)
