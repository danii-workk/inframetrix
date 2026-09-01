"""Optional Gemini AI Security Analyst with mandatory secret redaction."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from inframetrix.models.finding import Finding
from inframetrix.security.redaction import RedactionService
from inframetrix.security.secrets_store import SecretsStore

logger = logging.getLogger(__name__)


class AISecurityAnalyst:
    """Provides AI-powered finding explanations and remediation proposals."""

    GEMINI_ENDPOINT = (
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    )

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or SecretsStore.get_secret("GEMINI_API_KEY")

    def available(self) -> bool:
        """Check if Gemini API key is configured."""
        return bool(self.api_key)

    def explain_finding(self, finding: Finding, code_context: str | None = None) -> str:
        """Generate a clear explanation of vulnerability root cause and impact."""
        if not self.available():
            return "Gemini API key is not configured in Settings -> Tools -> AI Analyst."

        # 1. Sanitize code context
        sanitized_context, redaction_count = RedactionService.redact_text(code_context or "")

        prompt = (
            f"You are an AppSec Security Architect.\n"
            f"Analyze the following vulnerability finding and explain its risk, root cause, and remediation:\n\n"
            f"Finding: [{finding.severity.upper()}] {finding.title}\n"
            f"Category: {finding.category}\n"
            f"Engine: {finding.source_engine}\n"
            f"File: {finding.file_path or 'N/A'}:{finding.line or 'N/A'}\n"
            f"Description: {finding.description or finding.message}\n"
            f"Recommendation: {finding.recommendation or 'N/A'}\n"
            f"Sanitized Code Context ({redaction_count} secret(s) redacted):\n"
            f"```\n{sanitized_context}\n```\n\n"
            f"Provide a concise, practical developer explanation with a secure code fix."
        )

        return self._call_gemini(prompt)

    def propose_remediation_diff(self, finding: Finding, code_snippet: str) -> str:
        """Generate a patch proposal for the flagged finding."""
        if not self.available():
            return "Gemini API key is not configured."

        sanitized_context, _ = RedactionService.redact_text(code_snippet)

        prompt = (
            f"You are an expert secure coding assistant.\n"
            f"Generate a unified diff patch to fix this vulnerability:\n"
            f"Title: {finding.title}\n"
            f"Message: {finding.message}\n\n"
            f"Original Code:\n```\n{sanitized_context}\n```\n\n"
            f"Output only the remediation explanation and a clean code replacement."
        )

        return self._call_gemini(prompt)

    def _call_gemini(self, prompt: str) -> str:
        """Execute HTTPS request to Gemini API."""
        try:
            url = f"{self.GEMINI_ENDPOINT}?key={self.api_key}"
            payload = json.dumps(
                {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024},
                }
            ).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=30.0) as resp:
                data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return str(parts[0].get("text", ""))
                return "No analysis output returned by Gemini."
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Gemini API call failed: {exc}")
            return f"Error contacting AI service: {exc}"
