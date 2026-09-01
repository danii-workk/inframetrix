"""Finding repository for SQLite storage."""

from __future__ import annotations

import json
from datetime import datetime

from inframetrix.models.finding import Finding
from inframetrix.storage.database import DatabaseManager


class FindingRepository:
    """CRUD repository for security Finding records."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def save_many(self, findings: list[Finding], project_id: str, session_id: str) -> None:
        """Bulk insert or update findings for a session."""
        if not findings:
            return

        with self.db.transaction() as conn:
            for idx, f in enumerate(findings):
                db_id = f"{session_id}:{idx}:{f.fingerprint}"
                conn.execute(
                    """
                    INSERT INTO findings (
                        id, rule_id, fingerprint, project_id, session_id, title, description, message,
                        severity, confidence, category, source_engine, file_path, line, column,
                        url, endpoint, http_method, package_name, package_version, cve, cwe,
                        owasp, cvss, epss, evidence, recommendation, references_json,
                        first_seen, last_seen, status, suppression_reason,
                        ml_fp_probability, ml_priority_score, tags
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?,
                        ?, ?, ?
                    )
                    ON CONFLICT(id) DO UPDATE SET
                        status = excluded.status,
                        last_seen = excluded.last_seen,
                        ml_fp_probability = excluded.ml_fp_probability,
                        ml_priority_score = excluded.ml_priority_score,
                        suppression_reason = excluded.suppression_reason;
                    """,
                    (
                        db_id,
                        f.id,
                        f.fingerprint or f.compute_fingerprint(),
                        project_id,
                        session_id,
                        f.title,
                        f.description,
                        f.message,
                        f.severity,
                        f.confidence,
                        f.category,
                        f.source_engine,
                        f.file_path,
                        f.line,
                        f.column,
                        f.url,
                        f.endpoint,
                        f.http_method,
                        f.package_name,
                        f.package_version,
                        f.cve,
                        f.cwe,
                        f.owasp,
                        f.cvss,
                        f.epss,
                        f.evidence,
                        f.recommendation,
                        json.dumps(f.references),
                        f.first_seen.isoformat(),
                        f.last_seen.isoformat(),
                        f.status,
                        f.suppression_reason,
                        f.ml_fp_probability,
                        f.ml_priority_score,
                        json.dumps(f.tags),
                    ),
                )

    def list_by_session(self, session_id: str) -> list[Finding]:
        """Fetch all findings attached to a specific scan session."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY line ASC, id ASC",
                (session_id,),
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def list_by_project(self, project_id: str, status: str | None = None) -> list[Finding]:
        """Fetch findings for a project, optionally filtered by status."""
        with self.db.connection() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE project_id = ? AND status = ? ORDER BY first_seen DESC",
                    (project_id, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE project_id = ? ORDER BY first_seen DESC",
                    (project_id,),
                ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def update_status(self, target_key: str, status: str, suppression_reason: str | None = None) -> bool:
        """Update finding status (open, fixed, false_positive, accepted_risk, suppressed)."""
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "UPDATE findings SET status = ?, suppression_reason = ? WHERE id = ? OR fingerprint = ? OR rule_id = ?",
                (status, suppression_reason, target_key, target_key, target_key),
            )
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_finding(row) -> Finding:
        try:
            rule_or_id = row["rule_id"] or row["id"]
        except (IndexError, KeyError):
            rule_or_id = row["id"]

        return Finding(
            id=rule_or_id,
            fingerprint=row["fingerprint"],
            title=row["title"],
            description=row["description"],
            message=row["message"] or row["description"] or "",
            severity=row["severity"],
            confidence=row["confidence"],
            category=row["category"],
            source_engine=row["source_engine"],
            file_path=row["file_path"],
            line=row["line"],
            column=row["column"],
            url=row["url"],
            endpoint=row["endpoint"],
            http_method=row["http_method"],
            package_name=row["package_name"],
            package_version=row["package_version"],
            cve=row["cve"],
            cwe=row["cwe"],
            owasp=row["owasp"],
            cvss=row["cvss"],
            epss=row["epss"],
            evidence=row["evidence"],
            recommendation=row["recommendation"],
            references=json.loads(row["references_json"] or "[]"),
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            status=row["status"],
            suppression_reason=row["suppression_reason"],
            ml_fp_probability=row["ml_fp_probability"],
            ml_priority_score=row["ml_priority_score"],
            tags=json.loads(row["tags"] or "[]"),
        )
