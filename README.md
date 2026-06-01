# InfraMetrix

**Open-source security, architecture, and infrastructure risk analyzer for AI-built projects.**

AI coding tools can generate working software quickly. But working software is not always secure, maintainable, or production-ready.

InfraMetrix gives AI-built projects a measurable risk score.

## Features

- **Security scanning** -- detects committed env files, unsafe secret fallbacks, permissive CORS, and frontend-only auth patterns.
- **AI-slop detection** -- flags security TODOs, FIXMEs, and other temporary auth bypass markers.
- **Risk scoring** -- calculates a 0-100 risk score with severity-weighted findings.
- **Multiple report formats** -- console (Rich), JSON, and Markdown.
- **CI-ready exit codes** -- `--fail-on` threshold for integration with GitHub Actions or other pipelines.
- **Zero LLM dependency** -- deterministic, fast, offline-first.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

Scan the current directory:

```bash
inframetrix scan .
```

### Options

| Flag             | Description                                                                          | Default    |
| ---------------- | ------------------------------------------------------------------------------------ | ---------- |
| `--format`, `-f` | Output format: `console`, `json`, `markdown`                                         | `console`  |
| `--output`, `-o` | Output file path (for `json` or `markdown`)                                          | -          |
| `--fail-on`      | Exit code 1 if risk level >= threshold: `low`, `medium`, `high`, `critical`, `never` | `critical` |

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
      "confidence": "medium"
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

## Detection Rules

| ID                        | Title                            | Severity | Category |
| ------------------------- | -------------------------------- | -------- | -------- |
| `committed-env-file`      | Environment file detected        | critical | secrets  |
| `security-todo`           | Security TODO detected           | medium   | ai-slop  |
| `unsafe-secret-fallback`  | Unsafe secret fallback           | critical | auth     |
| `permissive-cors`         | Permissive CORS configuration    | high     | cors     |
| `frontend-only-auth-hint` | Frontend-only authorization hint | high     | auth     |

## Roadmap

- [ ] YAML-based custom rule engine
- [ ] SARIF output format
- [ ] GitHub Actions integration
- [ ] Semgrep integration
- [ ] Gitleaks integration
- [ ] OSV Scanner integration
- [ ] Web dashboard

## License

MIT
