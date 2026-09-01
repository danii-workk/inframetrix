"""Project management service."""

from __future__ import annotations

import uuid
from pathlib import Path

from inframetrix.models.project import Project
from inframetrix.storage.database import DatabaseManager
from inframetrix.storage.repositories.project_repo import ProjectRepository


class ProjectService:
    """Service for managing workspace projects."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or DatabaseManager()
        self.project_repo = ProjectRepository(self.db)

    def register_project(self, root_path: Path, name: str | None = None) -> Project:
        """Register or retrieve an existing project by path."""
        resolved = root_path.resolve()
        existing = self.project_repo.get_by_path(str(resolved))
        if existing:
            return existing

        project = Project(
            id=str(uuid.uuid4()),
            name=name or resolved.name,
            root_path=str(resolved),
        )
        return self.project_repo.save(project)

    def list_projects(self) -> list[Project]:
        """List all workspace projects."""
        return self.project_repo.list_all()

    def get_project(self, project_id: str) -> Project | None:
        """Get project by ID."""
        return self.project_repo.get_by_id(project_id)

    def delete_project(self, project_id: str) -> bool:
        """Delete project by ID."""
        return self.project_repo.delete(project_id)
