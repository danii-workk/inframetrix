"""CI/CD Security Analyzer for GitHub Actions and pipeline configurations."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from inframetrix.models.finding import Finding


class CISecurityAnalyzer:
    """Audits CI/CD workflows for security risks, script injections, and excessive permissions."""

    @classmethod
    def audit_project_workflows(cls, project_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        workflows_dir = project_path / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return findings

        for wf in sorted(workflows_dir.glob("*")):
            if wf.suffix.lower() not in (".yml", ".yaml"):
                continue

            try:
                content = wf.read_text(encoding="utf-8")
                parsed = yaml.safe_load(content) or {}
            except Exception:  # noqa: BLE001, S112
                continue

            lines = content.splitlines()

            # 1. Script injection check in run steps
            for lineno, line in enumerate(lines, start=1):
                if re.search(r"\$\{\{\s*github\.event\.(issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|head_ref)\s*\}\}", line):
                    findings.append(
                        Finding(
                            id="github-actions-script-injection",
                            title="GitHub Actions expression injection in workflow",
                            description="Untrusted context '${ github.event... }' is interpolated directly in shell command.",
                            message="Untrusted user input interpolated in workflow command.",
                            severity="high",
                            confidence="high",
                            category="infrastructure",
                            source_engine="supply-chain",
                            file_path=str(wf),
                            line=lineno,
                            evidence=line.strip(),
                            recommendation="Pass untrusted inputs via environment variables: `env: TITLE: ${{ github.event.issue.title }}` instead of inline expressions.",
                            tags=["ci-cd", "github-actions", "injection"],
                        )
                    )

                # 2. Persist-credentials check
                if "persist-credentials: true" in line.lower():
                    findings.append(
                        Finding(
                            id="github-actions-persist-credentials",
                            title="Git credentials persisted in Actions checkout",
                            description="actions/checkout is configured with persist-credentials: true",
                            message="Git credentials persisted on runner.",
                            severity="medium",
                            confidence="high",
                            category="infrastructure",
                            source_engine="supply-chain",
                            file_path=str(wf),
                            line=lineno,
                            evidence=line.strip(),
                            recommendation="Set `persist-credentials: false` in actions/checkout steps.",
                            tags=["ci-cd", "github-actions"],
                        )
                    )

                # 3. Mutable action tag (e.g. actions/checkout@v2, actions/checkout@master instead of commit SHA)
                match_uses = re.search(r"uses:\s*([a-zA-Z0-9_\-\.\/]+)@(master|main|v\d+[\.\d]*)\b", line)
                if match_uses:
                    action_name = match_uses.group(1)
                    ref = match_uses.group(2)
                    findings.append(
                        Finding(
                            id="github-actions-unpinned-action",
                            title=f"Unpinned action reference @{ref}",
                            description=f"Action '{action_name}' is referenced with mutable tag @{ref} instead of an immutable commit SHA.",
                            message=f"Action '{action_name}' pinned to mutable tag @{ref}",
                            severity="medium",
                            confidence="medium",
                            category="supply-chain",
                            source_engine="supply-chain",
                            file_path=str(wf),
                            line=lineno,
                            evidence=line.strip(),
                            recommendation=f"Pin '{action_name}' to a full 40-character commit SHA (e.g. {action_name}@<commit-sha>).",
                            tags=["ci-cd", "supply-chain"],
                        )
                    )

            # 4. Check for pull_request_target trigger
            triggers = parsed.get("on")
            if (
                (isinstance(triggers, str) and triggers == "pull_request_target")
                or (isinstance(triggers, dict) and "pull_request_target" in triggers)
                or (isinstance(triggers, list) and "pull_request_target" in triggers)
            ) and "actions/checkout" in content:
                findings.append(
                    Finding(
                        id="github-actions-dangerous-pr-target",
                        title="Dangerous pull_request_target workflow with checkout",
                        description="Workflow triggers on 'pull_request_target' and checks out repository code with write access / secrets.",
                        message="pull_request_target with checkout can lead to secret exfiltration.",
                        severity="high",
                        confidence="medium",
                        category="infrastructure",
                        source_engine="supply-chain",
                        file_path=str(wf),
                        recommendation="Do not checkout untrusted pull request code in pull_request_target workflows.",
                        tags=["ci-cd", "github-actions"],
                    )
                )

        return findings
