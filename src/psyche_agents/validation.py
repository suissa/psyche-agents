from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .artifacts import ArtifactRecord
from .models import ValidationReport
from .registry import ToolBinding
from .sandbox import SandboxCheck, SandboxExecution, SandboxRunner


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    report: ValidationReport
    executions: tuple[SandboxExecution, ...]


class SandboxOrchestrator:
    """Runs a declared validation matrix against one immutable candidate artifact."""

    def __init__(self, runner: SandboxRunner) -> None:
        self.runner = runner

    def run(
        self,
        artifact: ArtifactRecord,
        checks: Sequence[SandboxCheck],
    ) -> ValidationOutcome:
        if not artifact.verify():
            raise RuntimeError("candidate artifact failed SHA-256 verification")
        if not checks:
            raise ValueError("at least one sandbox validation check is required")
        names = [check.name for check in checks]
        if len(names) != len(set(names)):
            raise ValueError("sandbox validation check names must be unique")

        executions: list[SandboxExecution] = []
        failures: list[str] = []
        for check in checks:
            try:
                result = self.runner.run(artifact, check)
            except Exception as exc:
                failures.append(f"{check.name}: runner error ({type(exc).__name__})")
                continue
            if result.check_name != check.name:
                failures.append(f"{check.name}: sandbox runner returned a mismatched check identity")
                continue
            executions.append(result)
            if result.timed_out:
                failures.append(f"{check.name}: timed out")
            elif result.output_truncated and result.exit_code == 0:
                failures.append(f"{check.name}: output was truncated; passing evidence is incomplete")
            elif result.exit_code != 0:
                detail = result.stderr.strip() or result.stdout.strip()
                if result.output_truncated:
                    detail = f"{detail} [output truncated]".strip()
                failures.append(
                    f"{check.name}: exit code {result.exit_code}"
                    + (f" — {detail[:1000]}" if detail else "")
                )

        report = ValidationReport(
            passed=not failures and len(executions) == len(checks),
            checks=tuple(names),
            failures=tuple(failures),
            artifact_sha256=artifact.sha256,
        )
        return ValidationOutcome(report=report, executions=tuple(executions))


class SandboxCandidateValidator:
    """EvolutionaryEngine adapter backed by the sandbox validation matrix."""

    def __init__(
        self,
        orchestrator: SandboxOrchestrator,
        checks: Sequence[SandboxCheck],
    ) -> None:
        self.orchestrator = orchestrator
        self.checks = tuple(checks)
        if not self.checks:
            raise ValueError("candidate validator requires at least one check")

    def validate(
        self,
        candidate: ToolBinding,
        artifact: ArtifactRecord,
    ) -> ValidationReport:
        if candidate.manifest.action == "" or candidate.manifest.version == "":
            return ValidationReport(
                passed=False,
                failures=("candidate manifest is incomplete",),
                artifact_sha256=artifact.sha256,
            )
        return self.orchestrator.run(artifact, self.checks).report
