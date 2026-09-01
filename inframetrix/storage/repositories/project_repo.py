"""Project repository for SQLite storage."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from inframetrix.models.project import Project
from inframetrix.storage.database import DatabaseManager


class ProjectRepository:
    """CRUD repository for Project entities."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def save(self, project: Project) -> Project:
        """Insert or update a project."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO projects (id, name, root_path, created_at, updated_at, description, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    root_path = excluded.root_path,
                    updated_at = excluded.updated_at,
                    description = excluded.description,
                    tags = excluded.tags;
                """,
                (
                    project.id,
                    project.name,
                    project.root_path,
                    project.created_at.isoformat(),
                    now,
                    project.description,
                    json.dumps(project.tags),
                ),
            )
        return project

    def get_by_id(self, project_id: str) -> Project | None:
        """Find a project by its primary key ID."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id, name, root_path, created_at, updated_at, description, tags FROM projects WHERE id = ?",
                (project_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_project(row)

    def get_by_path(self, root_path: str) -> Project | None:
        """Find a project by its normalized root path."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id, name, root_path, created_at, updated_at, description, tags FROM projects WHERE root_path = ?",
                (root_path,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_project(row)

    def list_all(self) -> list[Project]:
        """List all registered projects ordered by last update."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, name, root_path, created_at, updated_at, description, tags FROM projects ORDER BY updated_at DESC"
            ).fetchall()
            return [self._row_to_project(r) for r in rows]

    def delete(self, project_id: str) -> bool:
        """Delete a project and cascade associated sessions and findings."""
        with self.db.transaction() as conn:
            cursor = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_project(row) -> Project:
        return Project(
            id=row["id"],
            name=row["name"],
            root_path=row["root_path"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            description=row["description"],
            tags=json.loads(row["tags"] or "[]"),
        )
