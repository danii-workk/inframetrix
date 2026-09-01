"""Evidence models for security findings."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CodeSnippetEvidence(BaseModel):
    """Source code snippet evidence for SAST and Secret findings."""

    file_path: str
    line_start: int
    line_end: int
    code: str
    highlight_lines: list[int] = Field(default_factory=list)


class HttpEvidence(BaseModel):
    """HTTP request/response evidence for DAST and API findings."""

    method: str
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None


class MaskedSecretEvidence(BaseModel):
    """Masked secret evidence ensuring no raw secrets are stored in database."""

    secret_type: str
    masked_value: str
    fingerprint: str
    file_path: str
    line: int | None = None


class Evidence(BaseModel):
    """Generic container for rich finding evidence."""

    evidence_type: Literal["code", "http", "secret", "generic"] = "generic"
    code_snippet: CodeSnippetEvidence | None = None
    http_evidence: HttpEvidence | None = None
    secret_evidence: MaskedSecretEvidence | None = None
    raw_text: str | None = None
