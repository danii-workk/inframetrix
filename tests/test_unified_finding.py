"""Tests for the Unified Finding Model."""

from inframetrix.models.finding import Finding


def test_finding_backward_compatibility():
    # Legacy initialization
    f = Finding(
        id="legacy-rule",
        title="Legacy Finding",
        severity="high",
        category="security",
        file_path="app.py",
        line=42,
        message="Legacy message format",
        recommendation="Fix it",
    )
    assert f.id == "legacy-rule"
    assert f.title == "Legacy Finding"
    assert f.message == "Legacy message format"
    assert f.description == "Legacy message format"
    assert f.status == "open"
    assert len(f.fingerprint) == 16


def test_finding_fingerprint_deterministic():
    f1 = Finding(
        id="sql-injection",
        title="SQL Injection",
        severity="critical",
        file_path="src/db.py",
        line=10,
        source_engine="native-sast",
    )
    f2 = Finding(
        id="sql-injection",
        title="SQL Injection",
        severity="critical",
        file_path="src/db.py",
        line=10,
        source_engine="native-sast",
    )
    assert f1.fingerprint == f2.fingerprint


def test_finding_web_and_package_fields():
    f = Finding(
        id="cve-2023-1234",
        title="Vulnerable Lodash",
        severity="high",
        package_name="lodash",
        package_version="4.17.15",
        cve="CVE-2023-1234",
        cvss=8.5,
        source_engine="osv-sca",
    )
    assert f.package_name == "lodash"
    assert f.cve == "CVE-2023-1234"
    assert f.cvss == 8.5
