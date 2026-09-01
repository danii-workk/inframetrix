"""Native InfraMetrix SAST scanner adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inframetrix import __version__
from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.file_walker import collect_files
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.rules.engine import evaluate_rules
from inframetrix.rules.loader import load_rulesets

_DEFAULT_RULESETS_DIR = Path(__file__).parent.parent.parent / "rulesets"


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


class NativeScannerAdapter:
    """Built-in deterministic SAST scanner executing YAML detection rules."""

    name = "native-sast"
    category = "sast"
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

        # 1. Collect files
        files = collect_files(context.project_path)

        if cancellation_token and cancellation_token.is_cancelled:
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    status="cancelled",
                ),
            )

        # 2. Load rulesets
        rules_dir = context.custom_rules_path or _DEFAULT_RULESETS_DIR
        yaml_files = sorted(set(rules_dir.glob("*.yaml")) | set(rules_dir.glob("*.yml")))
        ruleset, loaded_names = load_rulesets(yaml_files)

        # 3. Evaluate rules
        raw_findings = evaluate_rules(files, ruleset, _read_text)

        # Tag source engine
        for f in raw_findings:
            f.source_engine = self.name

        finished_at = datetime.now(UTC)
        return ScanResult(
            engine_name=self.name,
            findings=raw_findings,
            tool_run=ToolRun(
                tool_name=self.name,
                tool_version=self.version(),
                started_at=started_at,
                finished_at=finished_at,
                status="completed",
            ),
            metadata={
                "rules_loaded": loaded_names,
                "rules_path": str(rules_dir.resolve()),
                "files_scanned": len(files),
            },
        )
