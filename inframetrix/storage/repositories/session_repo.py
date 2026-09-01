"""Scan session repository for SQLite storage."""

from __future__ import annotations

import json
from datetime import datetime

from inframetrix.models.scan_session import ScanSession
from inframetrix.storage.database import DatabaseManager


class SessionRepository:
    """CRUD repository for ScanSession records."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def save(self, session: ScanSession) -> ScanSession:
        """Insert or update a scan session."""
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_sessions (
                    id, project_id, preset, status, started_at, finished_at,
                    risk_score_v1, risk_score_v2, risk_level, findings_count,
                    enabled_engines, tool_versions, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    finished_at = excluded.finished_at,
                    risk_score_v1 = excluded.risk_score_v1,
                    risk_score_v2 = excluded.risk_score_v2,
                    risk_level = excluded.risk_level,
                    findings_count = excluded.findings_count,
                    enabled_engines = excluded.enabled_engines,
                    tool_versions = excluded.tool_versions,
                    metadata = excluded.metadata;
                """,
                (
                    session.id,
                    session.project_id,
                    session.preset,
                    session.status,
                    session.started_at.isoformat(),
                    session.finished_at.isoformat() if session.finished_at else None,
                    session.risk_score_v1,
                    session.risk_score_v2,
                    session.risk_level,
                    session.findings_count,
                    json.dumps(session.enabled_engines),
                    json.dumps(session.tool_versions),
                    json.dumps(session.metadata),
                ),
            )
        return session

    def get_by_id(self, session_id: str) -> ScanSession | None:
        """Find a scan session by ID."""
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT id, project_id, preset, status, started_at, finished_at,
                       risk_score_v1, risk_score_v2, risk_level, findings_count,
                       enabled_engines, tool_versions, metadata
                FROM scan_sessions WHERE id = ?
                """,
                (session_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_session(row)

    def list_by_project(self, project_id: str, limit: int = 50) -> list[ScanSession]:
        """List scan sessions for a project ordered by recency."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, project_id, preset, status, started_at, finished_at,
                       risk_score_v1, risk_score_v2, risk_level, findings_count,
                       enabled_engines, tool_versions, metadata
                FROM scan_sessions WHERE project_id = ?
                ORDER BY started_at DESC LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
            return [self._row_to_session(r) for r in rows]

    @staticmethod
    def _row_to_session(row) -> ScanSession:
        return ScanSession(
            id=row["id"],
            project_id=row["project_id"],
            preset=row["preset"],
            status=row["status"],
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            risk_score_v1=row["risk_score_v1"],
            risk_score_v2=row["risk_score_v2"],
            risk_level=row["risk_level"],
            findings_count=row["findings_count"],
            enabled_engines=json.loads(row["enabled_engines"] or "[]"),
            tool_versions=json.loads(row["tool_versions"] or "{}"),
            metadata=json.loads(row["metadata"] or "{}"),
        )
