"""Native high-precision secret scanner with automated masking."""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime

from inframetrix import __version__
from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.file_walker import collect_files
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.security.redaction import RedactionService

KNOWN_SECRET_PATTERNS = [
    (
        "aws-access-key-id",
        "AWS Access Key ID",
        r"\b(AKIA[0-9A-Z]{16})\b",
        "critical",
        "Revoke the exposed AWS Access Key ID immediately and rotate credentials.",
    ),
    (
        "aws-secret-access-key",
        "AWS Secret Access Key",
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
        "critical",
        "Rotate the exposed AWS Secret Access Key in IAM console immediately.",
    ),
    (
        "github-personal-access-token",
        "GitHub Personal Access Token",
        r"\b(gh[pousr]_[a-zA-Z0-9_]{36,})\b",
        "critical",
        "Revoke the compromised GitHub token in GitHub developer settings.",
    ),
    (
        "openai-api-key",
        "OpenAI API Key",
        r"\b(sk-[a-zA-Z0-9_-]{20,})\b",
        "critical",
        "Revoke the exposed OpenAI key in platform.openai.com.",
    ),
    (
        "private-key-block",
        "Exposed Private Key",
        r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "critical",
        "Remove the private key from source control and generate a new keypair.",
    ),
    (
        "slack-webhook-url",
        "Slack Incoming Webhook",
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "high",
        "Revoke and regenerate the Slack webhook URL.",
    ),
    (
        "generic-database-connection-string",
        "Hardcoded Database Credentials",
        r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:([^@]+)@",
        "high",
        "Use environment variables or secrets manager for database connection strings.",
    ),
]


def _shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy


class NativeSecretsAdapter:
    """Built-in secrets detection engine with automated masking."""

    name = "native-secrets"
    category = "secrets"
    is_builtin = True
    install_hint = "Built into InfraMetrix."

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return __version__

    def scan(
        self,
        context: ScanContext,
        cancellation_token: CancellationToken | None = None,
    ) -> ScanResult:
        started_at = datetime.now(UTC)
        files = collect_files(context.project_path)
        findings: list[Finding] = []

        for fp in files:
            if cancellation_token and cancellation_token.is_cancelled:
                break

            try:
                content = fp.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

            lines = content.splitlines()
            for lineno, line in enumerate(lines, start=1):
                # Skip comments that are clearly examples
                if "example" in line.lower() and "your_" in line.lower():
                    continue

                for rule_id, title, pattern, severity, rec in KNOWN_SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        matched_str = match.group(0)
                        masked_val = RedactionService.mask_secret(matched_str)
                        findings.append(
                            Finding(
                                id=f"secret-{rule_id}",
                                title=f"{title} detected",
                                description=f"Potential {title} found in {fp.name}:{lineno}",
                                message=f"Secret match: {masked_val}",
                                severity=severity,  # type: ignore[arg-type]
                                confidence="high",
                                category="secrets",
                                source_engine=self.name,
                                file_path=str(fp),
                                line=lineno,
                                evidence=f"Line {lineno}: {line.replace(matched_str, masked_val)}",
                                recommendation=rec,
                                tags=["secrets", "credential"],
                            )
                        )
                        break

        return ScanResult(
            engine_name=self.name,
            findings=findings,
            tool_run=ToolRun(
                tool_name=self.name,
                tool_version=self.version(),
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status="completed",
            ),
        )
