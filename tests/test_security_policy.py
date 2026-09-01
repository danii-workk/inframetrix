"""Tests for Security Policies, Redaction, and Process Runner."""

import pytest

from inframetrix.core.exceptions import TargetPolicyViolationError
from inframetrix.security.redaction import RedactionService
from inframetrix.security.subprocess_policy import SecureProcessRunner
from inframetrix.security.target_policy import TargetPolicy


def test_target_policy_valid_host():
    policy = TargetPolicy(allowed_hosts=["example.com"])
    policy.validate_target("https://example.com/api/v1")


def test_target_policy_blocks_localhost_by_default():
    policy = TargetPolicy()
    with pytest.raises(TargetPolicyViolationError, match="Localhost scanning is restricted"):
        policy.validate_target("http://localhost:8080/dashboard")

    with pytest.raises(TargetPolicyViolationError, match="Localhost scanning is restricted"):
        policy.validate_target("http://127.0.0.1:3000")


def test_target_policy_blocks_sensitive_query():
    policy = TargetPolicy(allow_private_ips=True)
    with pytest.raises(TargetPolicyViolationError, match="sensitive credential query parameter"):
        policy.validate_target("https://example.com/login?token=secret123")


def test_redaction_service():
    raw_text = "My API key is sk-proj-1234567890123456789012345678 and token is ghp_123456789012345678901234567890123456"
    sanitized, count = RedactionService.redact_text(raw_text)

    assert count >= 2
    assert "sk-proj-1234567890123456789012345678" not in sanitized
    assert "ghp_123456789012345678901234567890123456" not in sanitized
    assert "sk-***REDACTED***" in sanitized
    assert "gh*-***REDACTED***" in sanitized


def test_secure_process_runner():
    runner = SecureProcessRunner(default_timeout=10)
    result = runner.run(["python", "-c", "print('safe execution')"])
    assert result.exit_code == 0
    assert "safe execution" in result.stdout
    assert not result.timed_out
    assert not result.cancelled
