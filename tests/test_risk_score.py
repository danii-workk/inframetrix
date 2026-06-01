"""Tests for risk score calculation."""

from inframetrix.finding import Finding
from inframetrix.risk_score import calculate_risk_score


def _make_finding(severity: str) -> Finding:
    return Finding(
        id="test",
        title="Test finding",
        severity=severity,  # type: ignore[arg-type]
        category="test",
        file_path="test.txt",
        message="test message",
    )


def test_info_finding_produces_score_1_level_low():
    findings = [_make_finding("info")]
    score, level = calculate_risk_score(findings)
    assert score == 1
    assert level == "low"


def test_many_critical_findings_cap_at_100():
    # 25 points each, 5 findings = 125, capped to 100
    findings = [_make_finding("critical") for _ in range(5)]
    score, level = calculate_risk_score(findings)
    assert score == 100
    assert level == "critical"


def test_no_findings():
    score, level = calculate_risk_score([])
    assert score == 0
    assert level == "low"


def test_mixed_severities():
    findings = [
        _make_finding("critical"),  # 25
        _make_finding("high"),  # 15
        _make_finding("medium"),  # 7
        _make_finding("low"),  # 3
        _make_finding("info"),  # 1
    ]
    score, level = calculate_risk_score(findings)
    assert score == 51
    assert level == "high"


def test_medium_threshold():
    # 3 medium = 21, which is >= 21 -> medium
    findings = [_make_finding("medium") for _ in range(3)]
    score, level = calculate_risk_score(findings)
    assert score == 21
    assert level == "medium"


def test_high_threshold():
    # 2 high = 30, which is >= 46? No. 3 high = 45 -> medium still.
    # 4 high = 60 -> high
    findings = [_make_finding("high") for _ in range(4)]
    score, level = calculate_risk_score(findings)
    assert score == 60
    assert level == "high"