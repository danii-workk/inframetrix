"""Tests for AI Security Analyst."""

from inframetrix.models.finding import Finding
from inframetrix.services.ai_analyst import AISecurityAnalyst


def test_ai_analyst_without_key_gracefully_informs():
    analyst = AISecurityAnalyst(api_key=None)
    assert not analyst.available()

    f = Finding(id="test-f", title="Test", severity="medium")
    res = analyst.explain_finding(f)
    assert "Gemini API key is not configured" in res
