"""End-to-end integration test for InfraMetrix AppSec Workstation."""

from pathlib import Path

from inframetrix.core.tool_registry import ToolRegistry
from inframetrix.engines.native.adapter import NativeScannerAdapter
from inframetrix.engines.secrets.native_secrets import NativeSecretsAdapter
from inframetrix.engines.supply_chain.analyzer import SupplyChainAdapter
from inframetrix.services.report_service import ReportService
from inframetrix.services.scan_service import ScanService
from inframetrix.storage.database import DatabaseManager

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "vulnerable_app"


def test_end_to_end_workstation_scan(tmp_path: Path):
    db_path = tmp_path / "workstation.db"
    db = DatabaseManager(db_path)

    reg = ToolRegistry()
    reg.register(NativeScannerAdapter())
    reg.register(NativeSecretsAdapter())
    reg.register(SupplyChainAdapter())

    service = ScanService(db=db, registry=reg)

    session, findings = service.scan_project(
        project_path=FIXTURE_DIR,
        preset="quick",
    )

    assert session.status == "completed"
    assert session.risk_score_v1 > 0
    assert len(findings) >= 4

    # Verify findings categories
    categories = {f.category for f in findings}
    engines = {f.source_engine for f in findings}

    assert "infrastructure" in categories or "ai-slop" in categories
    assert "native-sast" in engines

    # Verify Database persistence
    persisted_findings = service.finding_repo.list_by_session(session.id)
    assert len(persisted_findings) == len(findings)

    # Test report export from persisted scan
    report_data = {
        "project": "vulnerable_app",
        "path": str(FIXTURE_DIR),
        "risk_score": session.risk_score_v1,
        "risk_level": session.risk_level,
        "findings": persisted_findings,
    }

    html_out = tmp_path / "report.html"
    ReportService.export_report(report_data, "html", output_path=html_out)
    assert html_out.is_file()

    sarif_out = tmp_path / "report.sarif"
    ReportService.export_report(report_data, "sarif", output_path=sarif_out)
    assert sarif_out.is_file()
