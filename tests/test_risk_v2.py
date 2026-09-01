"""Tests for Risk Score Engine v2."""

from inframetrix.models.finding import Finding
from inframetrix.scoring.risk_v2 import calculate_risk_score_v2


def test_risk_score_v2_empty_findings():
    score, level = calculate_risk_score_v2([])
    assert score == 0.0
    assert level == "low"


def test_risk_score_v2_single_critical():
    f = Finding(
        id="rce-vuln",
        title="Remote Code Execution",
        severity="critical",
        confidence="high",
        cvss=9.8,
    )
    score, level = calculate_risk_score_v2([f])
    assert score > 30.0
    assert level in ("medium", "high", "critical")


def test_risk_score_v2_suppressed_findings_do_not_contribute():
    f = Finding(
        id="rce-vuln",
        title="Remote Code Execution",
        severity="critical",
        status="false_positive",
    )
    score, level = calculate_risk_score_v2([f])
    assert score == 0.0
    assert level == "low"


def test_risk_score_v2_duplicate_dampening():
    # 10 duplicate findings with identical fingerprint
    f_list = [
        Finding(
            id="duplicate-item",
            title="Duplicate Item",
            severity="medium",
            file_path="src/file.py",
            line=10,
        )
        for _ in range(10)
    ]
    score_many, _ = calculate_risk_score_v2(f_list)
    score_single, _ = calculate_risk_score_v2([f_list[0]])

    # 10 duplicates should not be 10x the score due to logarithmic dampening
    assert score_many > score_single
    assert score_many < (score_single * 4)
