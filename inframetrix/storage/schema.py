"""SQLite database schema DDL."""

from __future__ import annotations

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    root_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    description TEXT,
    tags TEXT
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    preset TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    risk_score_v1 INTEGER NOT NULL DEFAULT 0,
    risk_score_v2 REAL NOT NULL DEFAULT 0.0,
    risk_level TEXT NOT NULL DEFAULT 'low',
    findings_count INTEGER NOT NULL DEFAULT 0,
    enabled_engines TEXT NOT NULL,
    tool_versions TEXT,
    metadata TEXT,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_project ON scan_sessions(project_id);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    rule_id TEXT,
    fingerprint TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    message TEXT,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    category TEXT NOT NULL,
    source_engine TEXT NOT NULL,
    file_path TEXT,
    line INTEGER,
    column INTEGER,
    url TEXT,
    endpoint TEXT,
    http_method TEXT,
    package_name TEXT,
    package_version TEXT,
    cve TEXT,
    cwe TEXT,
    owasp TEXT,
    cvss REAL,
    epss REAL,
    evidence TEXT,
    recommendation TEXT,
    references_json TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    suppression_reason TEXT,
    ml_fp_probability REAL,
    ml_priority_score REAL,
    tags TEXT,
    FOREIGN KEY(project_id) REFERENCES projects(id),
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);

CREATE TABLE IF NOT EXISTS replay_snapshots (
    hash TEXT PRIMARY KEY,
    content_blob BLOB,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS replay_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    file_path TEXT NOT NULL,
    old_hash TEXT,
    new_hash TEXT,
    diff_text TEXT,
    snapshot_hash TEXT REFERENCES replay_snapshots(hash)
);
CREATE INDEX IF NOT EXISTS idx_replay_project_time ON replay_events(project_id, timestamp);

CREATE TABLE IF NOT EXISTS review_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_fingerprint TEXT NOT NULL,
    label TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_labels_fp ON review_labels(finding_fingerprint);

CREATE TABLE IF NOT EXISTS suppressions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""
