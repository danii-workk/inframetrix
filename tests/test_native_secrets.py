"""Tests for Native Secret Scanner."""

from pathlib import Path

from inframetrix.core.scan_context import ScanContext
from inframetrix.engines.secrets.native_secrets import NativeSecretsAdapter


def test_native_secrets_detects_aws_key(tmp_path: Path):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

    adapter = NativeSecretsAdapter()
    context = ScanContext(project_path=tmp_path, project_id="p1", session_id="s1")
    result = adapter.scan(context)

    ids = [f.id for f in result.findings]
    assert "secret-aws-access-key-id" in ids
    assert result.findings[0].evidence is not None
    assert "AKIA" in result.findings[0].evidence


def test_native_secrets_detects_openai_key(tmp_path: Path):
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234\n", encoding="utf-8")

    adapter = NativeSecretsAdapter()
    context = ScanContext(project_path=tmp_path, project_id="p1", session_id="s1")
    result = adapter.scan(context)

    ids = [f.id for f in result.findings]
    assert "secret-openai-api-key" in ids
