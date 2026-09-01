"""Tests for Code Replay and Security Regression correlation."""

from datetime import UTC, datetime
from pathlib import Path

from inframetrix.engines.replay.diff_engine import DiffEngine
from inframetrix.engines.replay.replay_engine import ReplayEngine
from inframetrix.models.finding import Finding
from inframetrix.services.replay_service import ReplayService
from inframetrix.storage.database import DatabaseManager


def test_diff_engine():
    old = "def login():\n    return False\n"
    new = "def login():\n    return True\n"
    diff = DiffEngine.compute_diff(old, new, filename="auth.py")

    assert "-    return False" in diff
    assert "+    return True" in diff


def test_replay_service_record_and_restore(tmp_path: Path):
    db = DatabaseManager(":memory:")
    from inframetrix.models.project import Project
    from inframetrix.storage.repositories.project_repo import ProjectRepository

    ProjectRepository(db).save(Project(id="p1", name="Proj", root_path=str(tmp_path)))
    service = ReplayService(db)

    f = tmp_path / "app.py"
    f.write_text("v1 = 1", encoding="utf-8")

    event_id = service.record_file_change(project_id="p1", file_path=f)
    assert event_id is not None

    f.write_text("v2 = 2", encoding="utf-8")
    event_id2 = service.record_file_change(project_id="p1", file_path=f)
    assert event_id2 is not None

    timeline = service.get_timeline(project_id="p1")
    assert len(timeline) == 2


def test_replay_security_regression_correlation():
    f1 = Finding(id="r1", title="Existing", severity="low", file_path="app.py")
    f2 = Finding(id="r2", title="New SQL Injection", severity="high", file_path="src/auth.py")

    events = [
        {
            "file_path": "src/auth.py",
            "timestamp": datetime.now(UTC).isoformat(),
            "diff_text": "+ raw_sql_query()",
        }
    ]

    regressions = ReplayEngine.correlate_regressions(
        findings_before=[f1],
        findings_after=[f1, f2],
        recent_events=events,
        risk_before=10.0,
        risk_after=45.0,
    )

    assert len(regressions) == 1
    assert regressions[0].file_path == "src/auth.py"
    assert regressions[0].new_findings[0].id == "r2"
