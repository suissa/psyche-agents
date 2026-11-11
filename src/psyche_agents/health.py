from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import Enum

from .audit import AuditSink, InMemoryAuditLog
from .evolution import EvolutionaryEngine, ProposalStatus
from .models import AuditEvent


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RECOVERED = "recovered"
    RECOVERY_FAILED = "recovery_failed"


@dataclass(frozen=True, slots=True)
class HealthSample:
    error_rate: float
    p95_latency_ms: float
    contract_failures: int = 0
    observed_at: float = 0.0

    def __post_init__(self) -> None:
        if not math.isfinite(self.error_rate) or not 0 <= self.error_rate <= 1:
            raise ValueError("error_rate must be a finite number between 0 and 1")
        if not math.isfinite(self.p95_latency_ms) or self.p95_latency_ms < 0:
            raise ValueError("p95_latency_ms must be finite and non-negative")
        if self.contract_failures < 0:
            raise ValueError("contract_failures cannot be negative")


@dataclass(frozen=True, slots=True)
class HealthThresholds:
    max_error_rate: float = 0.05
    max_p95_latency_ms: float = 2_000.0
    max_contract_failures: int = 0

    def __post_init__(self) -> None:
        if not math.isfinite(self.max_error_rate) or not 0 <= self.max_error_rate <= 1:
            raise ValueError("max_error_rate must be between 0 and 1")
        if (
            not math.isfinite(self.max_p95_latency_ms)
            or self.max_p95_latency_ms <= 0
        ):
            raise ValueError("max_p95_latency_ms must be positive")
        if self.max_contract_failures < 0:
            raise ValueError("max_contract_failures cannot be negative")


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    proposal_id: str
    succeeded: bool
    restored_version: str | None
    reason: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class HealthDecision:
    proposal_id: str
    state: HealthState
    reasons: tuple[str, ...]
    recovery: RecoveryResult | None = None


class RecoveryController:
    """Performs policy-authorized rollback and records the outcome."""

    def __init__(
        self,
        engine: EvolutionaryEngine,
        *,
        audit: AuditSink | None = None,
    ) -> None:
        self.engine = engine
        self.audit = audit or InMemoryAuditLog()

    def recover(self, proposal_id: str, reason: str) -> RecoveryResult:
        if not reason.strip():
            raise ValueError("recovery reason is required")
        proposal = self.engine.get(proposal_id)
        restored_version = proposal.previous_binding.manifest.version
        try:
            rolled_back = self.engine.rollback(proposal_id)
            result = RecoveryResult(
                proposal_id=proposal_id,
                succeeded=rolled_back.status is ProposalStatus.ROLLED_BACK,
                restored_version=restored_version,
                reason=reason,
            )
        except Exception as exc:
            result = RecoveryResult(
                proposal_id=proposal_id,
                succeeded=False,
                restored_version=None,
                reason=reason,
                error=f"{type(exc).__name__}: {exc}",
            )
        self.audit.record(
            AuditEvent(
                event_type="recovery_completed" if result.succeeded else "recovery_failed",
                intent_id=proposal_id,
                actor_id="recovery-controller",
                timestamp=time.time(),
                details={
                    "reason": reason,
                    "restored_version": result.restored_version,
                    "error": result.error,
                },
            )
        )
        return result


class RuntimeHealthMonitor:
    """Evaluates post-activation samples and can invoke a configured rollback policy."""

    def __init__(
        self,
        engine: EvolutionaryEngine,
        thresholds: HealthThresholds | None = None,
        *,
        recovery_controller: RecoveryController | None = None,
        auto_recover: bool = True,
    ) -> None:
        self.engine = engine
        self.thresholds = thresholds or HealthThresholds()
        self.recovery_controller = recovery_controller or RecoveryController(engine)
        self.auto_recover = auto_recover

    def observe(self, proposal_id: str, sample: HealthSample) -> HealthDecision:
        proposal = self.engine.get(proposal_id)
        if proposal.status is not ProposalStatus.ACTIVE:
            raise RuntimeError("health observations require an active evolution proposal")

        reasons: list[str] = []
        if sample.error_rate > self.thresholds.max_error_rate:
            reasons.append(
                f"error_rate {sample.error_rate:.4f} exceeded "
                f"{self.thresholds.max_error_rate:.4f}"
            )
        if sample.p95_latency_ms > self.thresholds.max_p95_latency_ms:
            reasons.append(
                f"p95_latency_ms {sample.p95_latency_ms:.1f} exceeded "
                f"{self.thresholds.max_p95_latency_ms:.1f}"
            )
        if sample.contract_failures > self.thresholds.max_contract_failures:
            reasons.append(
                f"contract_failures {sample.contract_failures} exceeded "
                f"{self.thresholds.max_contract_failures}"
            )

        if not reasons:
            return HealthDecision(proposal_id, HealthState.HEALTHY, ())

        if not self.auto_recover:
            return HealthDecision(proposal_id, HealthState.DEGRADED, tuple(reasons))

        reason = "; ".join(reasons)
        recovery = self.recovery_controller.recover(proposal_id, reason)
        state = HealthState.RECOVERED if recovery.succeeded else HealthState.RECOVERY_FAILED
        return HealthDecision(proposal_id, state, tuple(reasons), recovery)
