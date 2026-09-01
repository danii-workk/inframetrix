"""Secret redaction service for logs, UI, reports, and AI context."""

from __future__ import annotations

import re

# Regex patterns for common secret formats
SECRET_PATTERNS = [
    # OpenAI / Anthropic
    (r"(sk-[a-zA-Z0-9_-]{20,})", "sk-***REDACTED***"),
    # GitHub Tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    (r"(gh[pousr]_[a-zA-Z0-9_]{20,})", "gh*-***REDACTED***"),
    # AWS Access Key ID
    (r"(AKIA[0-9A-Z]{16})", "AKIA***REDACTED***"),
    # AWS Secret Access Key
    (r"(aws_secret_access_key\s*=\s*['\"]?)([a-zA-Z0-9/+=]{40})(['\"]?)", r"\1***REDACTED***\3"),
    # Generic password / secret assignments
    (
        r"(?i)(password|passwd|secret|jwt_secret|api_key|token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
        r"\1='***REDACTED***'",
    ),
    # Private Key Headers
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END \1?PRIVATE KEY-----", "[***PRIVATE KEY REDACTED***]"),
    # Bearer tokens
    (r"(?i)bearer\s+([a-zA-Z0-9\-._~+/]+=*)", "Bearer ***REDACTED***"),
]


class RedactionService:
    """Sanitizes text by removing and masking sensitive credentials and tokens."""

    @classmethod
    def mask_secret(cls, raw: str) -> str:
        """Create a safe preview of a secret (e.g. sk-proj-***...*8kQ)."""
        if not raw or len(raw) <= 8:
            return "******"
        prefix = raw[:4]
        suffix = raw[-4:]
        masked_middle = "*" * max(len(raw) - 8, 6)
        return f"{prefix}{masked_middle}{suffix}"

    @classmethod
    def redact_text(cls, text: str) -> tuple[str, int]:
        """Redact sensitive patterns from text. Returns (sanitized_text, count_of_redactions)."""
        if not text:
            return "", 0

        sanitized = text
        total_redactions = 0

        for pattern, replacement in SECRET_PATTERNS:
            matches = len(re.findall(pattern, sanitized))
            if matches:
                total_redactions += matches
                sanitized = re.sub(pattern, replacement, sanitized)

        return sanitized, total_redactions
