# InfraMetrix

**Open-source security, architecture, and infrastructure risk analyzer for AI-built projects.**

AI coding tools can generate working software quickly. But working software is not always secure, maintainable, or production-ready.

InfraMetrix gives AI-built projects a measurable risk score.

## Features

- **Security scanning** -- detects committed env files, unsafe secret fallbacks, permissive CORS, and frontend-only auth patterns.
- **AI-slop detection** -- flags security TODOs, FIXMEs, and other temporary auth bypass markers.
- **Infrastructure scanning** -- Docker, Docker Compose, Nginx, CI/CD pipeline security checks.
- **Dependency auditing** -- unpinned versions, deprecated packages, missing lock files, SSL verification bypass.
- **Risk scoring** -- calculates a 0-100 risk score with severity-weighted findings.
- **Multiple report formats** -- console (Rich), JSON, and Markdown.
- **CI-ready exit codes** -- `--fail-on` threshold for integration with GitHub Actions or other pipelines.
- **Zero LLM dependency** -- deterministic, fast, offline-first.
- **Custom rules** -- extend with your own YAML rulesets via `--rules`.

## Installation

### From GitHub (recommended)

```bash
pip install git+https://github.com/danii-workk/inframetrix.git
```

### Local development

```bash
git clone https://github.com/danii-workk/inframetrix.git
cd inframetrix
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS

pip install -e ".[dev]"
```

### From PyPI (when published)

```bash
pip install inframetrix
```

## Quick Start

```bash
# Scan the current directory
inframetrix scan .

# Scan a specific project
inframetrix scan /path/to/my-project

# Show version
inframetrix --version
```

## Usage

### Options

| Flag              | Description                                                                          | Default    |
| ----------------- | ------------------------------------------------------------------------------------ | ---------- |
| `--format`, `-f`  | Output format: `console`, `json`, `markdown`                                         | `console`  |
| `--output`, `-o`  | Output file path (for `json` or `markdown`)                                          | -          |
| `--rules`         | Path to a directory of custom YAML ruleset files                                     | built-in   |
| `--fail-on`       | Exit code 1 if risk level >= threshold: `low`, `medium`, `high`, `critical`, `never` | `critical` |
| `--no-color`      | Disable colored output (useful in CI)                                                | `false`    |
| `-v`, `--version` | Show version and exit                                                                | -          |

### Examples

**Console output (default):**

```bash
inframetrix scan .
```

**JSON report to file:**

```bash
inframetrix scan . --format json --output report.json
```

**Markdown report to file:**

```bash
inframetrix scan . --format markdown --output report.md
```

**Fail CI on high or above:**

```bash
inframetrix scan . --fail-on high
```

**Use custom rules:**

```bash
inframetrix scan . --rules ./my-rules/
```

**No-color mode for CI:**

```bash
inframetrix scan . --no-color --fail-on medium
```

### JSON Report Example

```json
{
  "project": "my-app",
  "path": "/path/to/my-app",
  "risk_score": 40,
  "risk_level": "medium",
  "findings": [
    {
      "id": "committed-env-file",
      "title": "Environment file detected",
      "severity": "critical",
      "category": "secrets",
      "file_path": "/path/to/my-app/.env",
      "line": null,
      "message": "File `.env` is present in the project tree.",
      "recommendation": "Do not commit real .env files. Use .env.example without secrets.",
      "confidence": "high"
    }
  ]
}
```

### Markdown Report Example

```markdown
# InfraMetrix Report

- **Project:** my-app
- **Risk Score:** 40/100
- **Risk Level:** MEDIUM
- **Findings:** 1

## Findings

### [CRITICAL] Environment file detected

- **ID:** committed-env-file
- **Category:** secrets
- **File:** `.env`
- **Message:** File `.env` is present in the project tree.
- **Recommendation:** Do not commit real .env files. Use .env.example without secrets.
```

## Built-in Detection Rules

### Secrets

| ID                         | Title                     | Severity | Category |
| -------------------------- | ------------------------- | -------- | -------- |
| `committed-env-file`       | Environment file detected | critical | secrets  |
| `unsafe-secret-fallback-*` | Unsafe secret fallback    | critical | auth     |

### Authentication & CORS

| ID                        | Title                            | Severity | Category |
| ------------------------- | -------------------------------- | -------- | -------- |
| `permissive-cors-*`       | Permissive CORS configuration    | high     | cors     |
| `frontend-only-auth-hint` | Frontend-only authorization hint | high     | auth     |

### AI Slop

| ID              | Title                  | Severity | Category |
| --------------- | ---------------------- | -------- | -------- |
| `security-todo` | Security TODO detected | medium   | ai-slop  |

### Infrastructure (Docker, CI/CD)

| ID                                   | Title                      | Severity | Category       |
| ------------------------------------ | -------------------------- | -------- | -------------- |
| `docker-expose-ssh`                  | SSH port exposed           | critical | infrastructure |
| `compose-privileged-mode`            | Privileged container       | critical | infrastructure |
| `docker-run-as-root`                 | Container running as root  | high     | infrastructure |
| `compose-host-network`               | Host network mode          | high     | infrastructure |
| `github-actions-script-injection`    | Script injection risk      | high     | infrastructure |
| `docker-latest-tag`                  | Using :latest tag          | medium   | infrastructure |
| `github-actions-persist-credentials` | Persisting credentials     | medium   | infrastructure |
| `compose-writable-filesystem`        | Writable root filesystem   | medium   | infrastructure |
| `docker-missing-healthcheck`         | No HEALTHCHECK instruction | low      | infrastructure |

### Dependencies

| ID                             | Title                        | Severity | Category   |
| ------------------------------ | ---------------------------- | -------- | ---------- |
| `python-requests-verify-false` | SSL verification disabled    | critical | dependency |
| `missing-lock-file`            | No lock file detected        | medium   | dependency |
| `python-requirements-no-pins`  | Unpinned Python dependencies | medium   | dependency |
| `npm-dev-dep-in-prod`          | Dev dependency in production | medium   | dependency |
| `npm-caret-version`            | Caret version ranges         | low      | dependency |
| `python-setup-py-deprecated`   | setup.py detected            | low      | dependency |

## Custom Rules

Create a directory with YAML files following this schema:

```yaml
rules:
  - id: my-custom-rule
    title: My Custom Rule
    severity: high
    category: custom
    patterns:
      - "DANGEROUS_PATTERN"
    file_patterns:
      - "*.py"
    message: "Found dangerous pattern in code."
    recommendation: "Fix this issue before deployment."
    confidence: high
    match_mode: contains # or "case_insensitive_contains"
    languages: # optional language filter
      - python
```

Then run:

```bash
inframetrix scan . --rules ./my-rules/
```

## Python API

```python
from pathlib import Path
from inframetrix import scan_project, Finding, calculate_risk_score

# Scan a project
report = scan_project(Path("./my-project"))

print(f"Risk: {report['risk_score']}/100 ({report['risk_level']})")

for finding in report["findings"]:
    print(f"  [{finding.severity}] {finding.title} in {finding.file_path}")
```

## GitHub Actions Integration

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/danii-workk/inframetrix.git
      - run: inframetrix scan . --fail-on high --no-color
```

## License

MIT
