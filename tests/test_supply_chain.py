"""Tests for Supply Chain and CI/CD workflow security."""

from pathlib import Path

from inframetrix.engines.supply_chain.ci_security import CISecurityAnalyzer
from inframetrix.engines.supply_chain.package_reputation import PackageReputationAnalyzer


def test_ci_security_detects_script_injection(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        """
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Title is ${{ github.event.issue.title }}"
""",
        encoding="utf-8",
    )

    findings = CISecurityAnalyzer.audit_project_workflows(tmp_path)
    ids = [f.id for f in findings]
    assert "github-actions-script-injection" in ids


def test_ci_security_detects_unpinned_action(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "deploy.yaml"
    wf_file.write_text(
        """
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
""",
        encoding="utf-8",
    )

    findings = CISecurityAnalyzer.audit_project_workflows(tmp_path)
    ids = [f.id for f in findings]
    assert "github-actions-unpinned-action" in ids


def test_package_reputation_detects_missing_lockfile(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.2"}}', encoding="utf-8")

    findings = PackageReputationAnalyzer.audit_dependencies(tmp_path)
    ids = [f.id for f in findings]
    assert "supply-chain-missing-lockfile" in ids


def test_package_reputation_detects_typosquat(tmp_path: Path):
    # 'lodas' is distance 1 from 'lodash'
    (tmp_path / "package.json").write_text('{"dependencies": {"lodas": "1.0.0"}}', encoding="utf-8")

    findings = PackageReputationAnalyzer.audit_dependencies(tmp_path)
    ids = [f.id for f in findings]
    assert "supply-chain-potential-typosquat" in ids
