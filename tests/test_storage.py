"""Tests for SQLite database storage and repositories."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

from inframetrix.models.finding import Finding
from inframetrix.models.project import Project
from inframetrix.models.scan_session import ScanSession
from inframetrix.storage.database import DatabaseManager
from inframetrix.storage.repositories.finding_repo import FindingRepository
from inframetrix.storage.repositories.project_repo import ProjectRepository
from inframetrix.storage.repositories.replay_repo import ReplayRepository
from inframetrix.storage.repositories.review_repo import ReviewRepository
from inframetrix.storage.repositories.session_repo import SessionRepository


def test_database_manager_in_memory():
    db = DatabaseManager(":memory:")
    with db.connection() as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "projects" in table_names
        assert "scan_sessions" in table_names
        assert "findings" in table_names
        assert "replay_events" in table_names


def test_project_repository_crud(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db = DatabaseManager(db_path)
    repo = ProjectRepository(db)

    project = Project(
        id=str(uuid.uuid4()),
        name="Test App",
        root_path=str(tmp_path / "test_app"),
        description="Demo project",
    )
    repo.save(project)

    fetched = repo.get_by_id(project.id)
    assert fetched is not None
    assert fetched.name == "Test App"

    by_path = repo.get_by_path(str(tmp_path / "test_app"))
    assert by_path is not None
    assert by_path.id == project.id

    projects = repo.list_all()
    assert len(projects) == 1

    repo.delete(project.id)
    assert repo.get_by_id(project.id) is None


def test_session_and_finding_repository(tmp_path: Path):
    db = DatabaseManager(":memory:")
    project_repo = ProjectRepository(db)
    session_repo = SessionRepository(db)
    finding_repo = FindingRepository(db)

    project = Project(id="p1", name="Proj", root_path="/tmp/proj")
    project_repo.save(project)

    session = ScanSession(
        id="s1",
        project_id="p1",
        preset="quick",
        status="completed",
        risk_score_v1=25,
        risk_score_v2=35.0,
        risk_level="medium",
        findings_count=1,
    )
    session_repo.save(session)

    finding = Finding(
        id="f1",
        title="Test Vuln",
        severity="high",
        category="sast",
        file_path="src/main.py",
        line=10,
        source_engine="native-sast",
    )
    finding_repo.save_many([finding], project_id="p1", session_id="s1")

    session_findings = finding_repo.list_by_session("s1")
    assert len(session_findings) == 1
    assert session_findings[0].title == "Test Vuln"
    assert session_findings[0].fingerprint == finding.fingerprint

    # Update status
    finding_repo.update_status(finding.id, status="false_positive", suppression_reason="Test FP")
    updated_findings = finding_repo.list_by_session("s1")
    assert updated_findings[0].status == "false_positive"
    assert updated_findings[0].suppression_reason == "Test FP"


def test_replay_and_review_repositories():
    db = DatabaseManager(":memory:")
    project_repo = ProjectRepository(db)
    replay_repo = ReplayRepository(db)
    review_repo = ReviewRepository(db)

    # Register project first
    project_repo.save(Project(id="p1", name="Proj", root_path="/tmp/p1"))

    # Snapshot
    content = b"print('hello world')"
    h = "hash123"
    replay_repo.save_snapshot(h, content)
    retrieved = replay_repo.get_snapshot(h)
    assert retrieved == content

    # Event
    replay_repo.save_event(
        project_id="p1",
        timestamp=datetime.now(UTC),
        file_path="main.py",
        old_hash="hash0",
        new_hash=h,
        diff_text="+print('hello world')",
        snapshot_hash=h,
    )
    events = replay_repo.list_events_by_project("p1")
    assert len(events) == 1
    assert events[0]["file_path"] == "main.py"

    # Review labels
    review_repo.add_label("fp-123", "true_positive", "Confirmed vulnerability")
    assert review_repo.count_labels() == 1
    labels = review_repo.list_all_labels()
    assert labels[0]["label"] == "true_positive"
