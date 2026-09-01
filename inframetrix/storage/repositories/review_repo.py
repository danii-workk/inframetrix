"""Review label repository for ML training data."""

from __future__ import annotations

from datetime import UTC, datetime

from inframetrix.storage.database import DatabaseManager


class ReviewRepository:
    """Repository for storing human triage labels (TP/FP/Accepted Risk)."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def add_label(self, finding_fingerprint: str, label: str, notes: str = "") -> int:
        """Add a triage review label for a finding fingerprint."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO review_labels (finding_fingerprint, label, notes, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (finding_fingerprint, label, notes, now),
            )
            return cursor.lastrowid or 0

    def list_all_labels(self) -> list[dict]:
        """Fetch all recorded review labels."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, finding_fingerprint, label, notes, created_at FROM review_labels ORDER BY created_at ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def count_labels(self) -> int:
        """Count total human review labels available for training."""
        with self.db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM review_labels").fetchone()
            return row["cnt"] if row else 0
