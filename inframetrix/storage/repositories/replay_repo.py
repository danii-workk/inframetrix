"""Replay snapshots and events repository for Code Replay."""

from __future__ import annotations

from datetime import datetime

from inframetrix.storage.database import DatabaseManager


class ReplayRepository:
    """Repository for content-addressed snapshot storage and file save events."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def save_snapshot(self, content_hash: str, content_bytes: bytes) -> None:
        """Store a content-addressed snapshot blob (idempotent)."""
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO replay_snapshots (hash, content_blob, size_bytes, created_at)
                VALUES (?, ?, ?, datetime('now'));
                """,
                (content_hash, content_bytes, len(content_bytes)),
            )

    def get_snapshot(self, content_hash: str) -> bytes | None:
        """Retrieve content blob by hash."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT content_blob FROM replay_snapshots WHERE hash = ?",
                (content_hash,),
            ).fetchone()
            if row:
                return row["content_blob"]
            return None

    def save_event(
        self,
        project_id: str,
        timestamp: datetime,
        file_path: str,
        old_hash: str | None,
        new_hash: str | None,
        diff_text: str | None,
        snapshot_hash: str | None,
    ) -> int:
        """Record a file modification event."""
        with self.db.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO replay_events (
                    project_id, timestamp, file_path, old_hash, new_hash, diff_text, snapshot_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    timestamp.isoformat(),
                    file_path,
                    old_hash,
                    new_hash,
                    diff_text,
                    snapshot_hash,
                ),
            )
            return cursor.lastrowid or 0

    def list_events_by_project(self, project_id: str, limit: int = 100) -> list[dict]:
        """Fetch replay events for a project ordered by timestamp."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, project_id, timestamp, file_path, old_hash, new_hash, diff_text, snapshot_hash
                FROM replay_events WHERE project_id = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
