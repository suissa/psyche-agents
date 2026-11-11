from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, replace
from enum import Enum
from threading import RLock
from typing import Callable, Protocol

from .artifacts import ArtifactRecord, ArtifactStore, InMemoryArtifactStore
from .audit import AuditSink, InMemoryAuditLog
from .models import AuditEvent, ValidationReport
from .registry import ToolBinding, ToolRegistry
from .loader import ArtifactLoader, PreparedArtifactLoader
from .replay import InMemoryNonceStore, NonceStore


class ProposalStatus(str, Enum):
    PROPOSED = "proposed"
    VALIDATING = "validating"
    VALIDATED = "validated"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    ACTIVATING = "activating"
    ACTIVE = "active"
    ACTIVATED = "active"  # Backward-compatible alias.
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    CHANGES_REQUESTED = "changes_requested"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class FailureSignal:
    action: str
    error_code: str
    evidence: tuple[str, ...] = ()
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class EvolutionApproval:
    """Signed human approval bound to one proposal, artifact and validation report."""

    proposal_id: str
    artifact_sha256: str
    validation_id: str
    approver_id: str
    issued_at: int
    expires_at: int
    nonce: str
    signature: str


@dataclass(frozen=True, slots=True)
class EvolutionProposal:
    proposal_id: str
    replacement: ToolBinding
    previous_binding: ToolBinding
    artifact: ArtifactRecord
    expected_generation: int
    created_by: str
    status: ProposalStatus = ProposalStatus.PROPOSED
    validation: ValidationReport | None = None
    approver_id: str | None = None
    approval_nonce: str | None = None
    activation_generation: int | None = None


class CandidateValidator(Protocol):
    def validate(
        self, candidate: ToolBinding, artifact: ArtifactRecord
    ) -> ValidationReport: ...


class EvolutionApprovalVerifier(Protocol):
    def verify(
        self, proposal: EvolutionProposal, approval: EvolutionApproval
    ) -> bool: ...


def _approval_payload(approval: EvolutionApproval) -> bytes:
    value = [
        approval.proposal_id,
        approval.artifact_sha256,
        approval.validation_id,
        approval.approver_id,
        approval.issued_at,
        approval.expires_at,
        approval.nonce,
    ]
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def sign_evolution_approval(
    secret: bytes,
    proposal: EvolutionProposal,
    approver_id: str,
    expires_at: int,
    *,
    issued_at: int | None = None,
    nonce: str | None = None,
) -> EvolutionApproval:
    """Issue only inside a trusted approval gateway after authenticating a human."""
    if len(secret) < 32:
        raise ValueError("approval secret must contain at least 32 bytes")
    if not approver_id.strip() or approver_id == proposal.created_by:
        raise ValueError("approval requires an independent, authenticated approver")
    if proposal.validation is None or not proposal.validation.passed:
        raise ValueError("proposal must have a passing validation report")
    if (
        not isinstance(proposal.validation.validation_id, str)
        or not proposal.validation.validation_id.strip()
    ):
        raise ValueError("validation report must have a non-empty validation ID")
    if proposal.validation.artifact_sha256 != proposal.artifact.sha256:
        raise ValueError("validation report does not match the stored candidate artifact")
    now = int(time.time()) if issued_at is None else issued_at
    if expires_at <= now:
        raise ValueError("approval expiry must be later than its issue time")
    unsigned = EvolutionApproval(
        proposal_id=proposal.proposal_id,
        artifact_sha256=proposal.artifact.sha256,
        validation_id=proposal.validation.validation_id,
        approver_id=approver_id,
        issued_at=now,
        expires_at=expires_at,
        nonce=nonce or secrets.token_urlsafe(24),
        signature="",
    )
    signature = hmac.new(secret, _approval_payload(unsigned), hashlib.sha256).hexdigest()
    return replace(unsigned, signature=signature)


class HmacEvolutionApprovalVerifier:
    """Verifies approvals and consumes each nonce through an injected replay store.

    InMemoryNonceStore is the default for tests. Production should inject SQLiteNonceStore
    for one host or a shared transactional NonceStore for multi-host deployments.
    The trusted approval gateway must authenticate the human before token issuance.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        clock: Callable[[], float] = time.time,
        max_lifetime_seconds: int = 900,
        nonce_store: NonceStore | None = None,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("approval secret must contain at least 32 bytes")
        if max_lifetime_seconds < 1:
            raise ValueError("approval lifetime must be positive")
        self._secret = secret
        self._clock = clock
        self._max_lifetime = max_lifetime_seconds
        self._nonce_store = nonce_store or InMemoryNonceStore()

    def verify(self, proposal: EvolutionProposal, approval: EvolutionApproval) -> bool:
        report = proposal.validation
        if report is None or not report.passed:
            return False
        if (
            not approval.nonce
            or approval.proposal_id != proposal.proposal_id
            or approval.artifact_sha256 != proposal.artifact.sha256
            or approval.validation_id != report.validation_id
            or report.artifact_sha256 != proposal.artifact.sha256
            or not isinstance(report.validation_id, str)
            or not report.validation_id.strip()
            or not approval.approver_id
            or approval.approver_id == proposal.created_by
        ):
            return False
        now = int(self._clock())
        if approval.issued_at > now or approval.expires_at <= now:
            return False
        if approval.expires_at - approval.issued_at > self._max_lifetime:
            return False
        expected = hmac.new(
            self._secret, _approval_payload(approval), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, approval.signature):
            return False
        return self._nonce_store.consume(approval.nonce, approval.expires_at, now)


class EvolutionaryEngine:
    """Governed evolution controller for already-loaded capability handlers.

    The engine stores immutable candidate bytes, validates that exact content, requires
    a signed approval bound to its hash and validation ID, then performs CAS activation.
    It never executes LLM-generated source, installs dependencies, commits to GitHub or
    deploys a binary. Those operations belong in a separate isolated release pipeline.
    """

    _TRANSITIONS: dict[ProposalStatus, frozenset[ProposalStatus]] = {
        ProposalStatus.PROPOSED: frozenset({ProposalStatus.VALIDATING, ProposalStatus.REJECTED}),
        ProposalStatus.VALIDATING: frozenset({
            ProposalStatus.VALIDATED, ProposalStatus.REJECTED, ProposalStatus.FAILED
        }),
        ProposalStatus.VALIDATED: frozenset({
            ProposalStatus.AWAITING_APPROVAL,
            ProposalStatus.CHANGES_REQUESTED,
            ProposalStatus.REJECTED,
        }),
        ProposalStatus.AWAITING_APPROVAL: frozenset({
            ProposalStatus.APPROVED,
            ProposalStatus.CHANGES_REQUESTED,
            ProposalStatus.REJECTED,
        }),
        ProposalStatus.CHANGES_REQUESTED: frozenset(),
        ProposalStatus.APPROVED: frozenset({
            ProposalStatus.ACTIVATING, ProposalStatus.REJECTED
        }),
        ProposalStatus.ACTIVATING: frozenset({
            ProposalStatus.ACTIVE, ProposalStatus.FAILED
        }),
        ProposalStatus.ACTIVE: frozenset({ProposalStatus.ROLLING_BACK}),
        ProposalStatus.ROLLING_BACK: frozenset({
            ProposalStatus.ROLLED_BACK, ProposalStatus.FAILED
        }),
    }

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        artifact_store: ArtifactStore | None = None,
        approval_verifier: EvolutionApprovalVerifier | None = None,
        artifact_loader: ArtifactLoader | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self.registry = registry
        self.artifact_store = artifact_store or InMemoryArtifactStore()
        self.artifact_loader = artifact_loader or PreparedArtifactLoader(self.artifact_store)
        self.approval_verifier = approval_verifier
        self.audit = audit or InMemoryAuditLog()
        self._proposals: dict[str, EvolutionProposal] = {}
        self._lock = RLock()

    def propose(
        self,
        replacement: ToolBinding,
        expected_generation: int,
        *,
        artifact: bytes,
        creator_id: str = "evolution-controller",
        media_type: str = "application/octet-stream",
    ) -> EvolutionProposal:
        generation, bindings = self.registry.snapshot()
        if generation != expected_generation:
            raise RuntimeError("registry changed before proposal creation")
        if not creator_id.strip():
            raise ValueError("proposal creator identity is required")
        current = next(
            (item for item in bindings if item.manifest.action == replacement.manifest.action),
            None,
        )
        if current is None:
            raise KeyError("cannot evolve an action that is not registered")
        if current.manifest.name != replacement.manifest.name:
            raise ValueError("candidate must preserve tool identity")
        if current.manifest.version == replacement.manifest.version:
            raise ValueError("candidate must use a new immutable version")

        stored_artifact = self.artifact_store.put(artifact, media_type)
        if not stored_artifact.verify():
            raise RuntimeError("artifact store returned an invalid artifact")
        self.artifact_loader.stage(stored_artifact, replacement)
        proposal = EvolutionProposal(
            proposal_id=secrets.token_urlsafe(18),
            replacement=replacement,
            previous_binding=current,
            artifact=stored_artifact,
            expected_generation=expected_generation,
            created_by=creator_id,
        )
        with self._lock:
            self._proposals[proposal.proposal_id] = proposal
        self._record(proposal, "proposal_created", status=proposal.status.value)
        return proposal

    def propose_from_failure(
        self,
        signal: FailureSignal,
        synthesize: Callable[[FailureSignal], ToolBinding],
        expected_generation: int,
        *,
        artifact: bytes,
        creator_id: str = "magician-agent",
    ) -> EvolutionProposal:
        """Ask an external synthesizer for a candidate; no generated code is run here."""
        candidate = synthesize(signal)
        if not isinstance(candidate, ToolBinding) or candidate.manifest.action != signal.action:
            raise ValueError("synthesizer returned an invalid candidate")
        return self.propose(
            candidate,
            expected_generation,
            artifact=artifact,
            creator_id=creator_id,
        )

    def validate(
        self, proposal_id: str, validator: CandidateValidator
    ) -> EvolutionProposal:
        with self._lock:
            proposal = self._require(proposal_id, ProposalStatus.PROPOSED)
            proposal = self._transition(proposal, ProposalStatus.VALIDATING)
        try:
            stored = self.artifact_store.get(proposal.artifact.sha256)
            if stored.content != proposal.artifact.content or not stored.verify():
                raise RuntimeError("candidate artifact changed after proposal creation")
            report = validator.validate(proposal.replacement, stored)
            if not isinstance(report, ValidationReport):
                raise TypeError("candidate validator must return a ValidationReport")
            if (
                not isinstance(report.validation_id, str)
                or not report.validation_id.strip()
            ):
                raise ValueError("validation report must contain a non-empty validation ID")
        except Exception:
            with self._lock:
                current = self._proposals[proposal_id]
                self._transition(current, ProposalStatus.FAILED)
            raise

        exact_artifact = report.artifact_sha256 == proposal.artifact.sha256
        passed = report.passed and exact_artifact
        if report.passed and not exact_artifact:
            report = replace(
                report,
                passed=False,
                failures=report.failures + (
                    "validation report artifact hash does not match the stored candidate",
                ),
            )
        with self._lock:
            current = self._proposals[proposal_id]
            next_status = ProposalStatus.VALIDATED if passed else ProposalStatus.REJECTED
            updated = replace(current, validation=report)
            self._proposals[proposal_id] = updated
            return self._transition(updated, next_status)

    def reject(
        self, proposal_id: str, actor_id: str, reason: str
    ) -> EvolutionProposal:
        if not actor_id.strip() or not reason.strip():
            raise ValueError("rejection requires an actor identity and reason")
        with self._lock:
            proposal = self._proposals[proposal_id]
            if proposal.status not in (
                ProposalStatus.PROPOSED,
                ProposalStatus.VALIDATED,
                ProposalStatus.AWAITING_APPROVAL,
                ProposalStatus.APPROVED,
            ):
                raise RuntimeError(
                    f"proposal cannot be rejected from {proposal.status.value}"
                )
            return self._transition(
                proposal,
                ProposalStatus.REJECTED,
                decision_by=actor_id,
                reason=reason,
            )

    def request_changes(
        self, proposal_id: str, reviewer_id: str, reason: str
    ) -> EvolutionProposal:
        if not reviewer_id.strip() or not reason.strip():
            raise ValueError("change request requires a reviewer identity and reason")
        with self._lock:
            proposal = self._proposals[proposal_id]
            if proposal.status not in (
                ProposalStatus.VALIDATED,
                ProposalStatus.AWAITING_APPROVAL,
            ):
                raise RuntimeError(
                    f"changes cannot be requested from {proposal.status.value}"
                )
            return self._transition(
                proposal,
                ProposalStatus.CHANGES_REQUESTED,
                decision_by=reviewer_id,
                reason=reason,
            )

    def approve(
        self, proposal_id: str, approval: EvolutionApproval
    ) -> EvolutionProposal:
        if self.approval_verifier is None:
            raise PermissionError("no trusted evolution approval verifier is configured")
        with self._lock:
            proposal = self._proposals[proposal_id]
            if proposal.status not in (
                ProposalStatus.VALIDATED,
                ProposalStatus.AWAITING_APPROVAL,
            ):
                raise RuntimeError(
                    f"proposal must be validated or awaiting approval, got {proposal.status.value}"
                )
            if proposal.status is ProposalStatus.VALIDATED:
                proposal = self._transition(proposal, ProposalStatus.AWAITING_APPROVAL)
            if not self.approval_verifier.verify(proposal, approval):
                raise PermissionError(
                    "approval is invalid, expired, replayed or bound to different artifacts"
                )
            updated = replace(
                proposal,
                approver_id=approval.approver_id,
                approval_nonce=approval.nonce,
            )
            self._proposals[proposal_id] = updated
            return self._transition(updated, ProposalStatus.APPROVED)

    def activate(self, proposal_id: str) -> EvolutionProposal:
        with self._lock:
            proposal = self._require(proposal_id, ProposalStatus.APPROVED)
            proposal = self._transition(proposal, ProposalStatus.ACTIVATING)

        try:
            stored = self.artifact_store.get(proposal.artifact.sha256)
            if not stored.verify() or stored.content != proposal.artifact.content:
                raise RuntimeError("candidate artifact failed integrity verification")
            prepared_binding = self.artifact_loader.load(proposal.artifact.sha256)
            if prepared_binding.manifest != proposal.replacement.manifest:
                raise RuntimeError(
                    "prepared handler manifest does not match the approved candidate"
                )
            new_generation = self.registry.replace(
                prepared_binding,
                expected_generation=proposal.expected_generation,
            )
        except Exception:
            with self._lock:
                current = self._proposals[proposal_id]
                if current.status is ProposalStatus.ACTIVATING:
                    self._transition(current, ProposalStatus.FAILED)
            raise

        with self._lock:
            current = self._proposals[proposal_id]
            updated = replace(current, activation_generation=new_generation)
            self._proposals[proposal_id] = updated
            return self._transition(updated, ProposalStatus.ACTIVE)

    def rollback(self, proposal_id: str) -> EvolutionProposal:
        """Restore the previously active binding using CAS; never overwrite a newer change."""
        with self._lock:
            proposal = self._require(proposal_id, ProposalStatus.ACTIVE)
            if proposal.activation_generation is None:
                raise RuntimeError("active proposal is missing its activation generation")
            proposal = self._transition(proposal, ProposalStatus.ROLLING_BACK)

        try:
            restored_generation = self.registry.replace(
                proposal.previous_binding,
                expected_generation=proposal.activation_generation,
            )
        except Exception:
            with self._lock:
                current = self._proposals[proposal_id]
                if current.status is ProposalStatus.ROLLING_BACK:
                    self._transition(current, ProposalStatus.FAILED)
            raise

        with self._lock:
            current = self._proposals[proposal_id]
            updated = replace(current, activation_generation=restored_generation)
            self._proposals[proposal_id] = updated
            return self._transition(updated, ProposalStatus.ROLLED_BACK)

    def get(self, proposal_id: str) -> EvolutionProposal:
        with self._lock:
            return self._proposals[proposal_id]

    def _require(
        self, proposal_id: str, expected_status: ProposalStatus
    ) -> EvolutionProposal:
        proposal = self._proposals[proposal_id]
        if proposal.status is not expected_status:
            raise RuntimeError(
                f"proposal must be {expected_status.value}, got {proposal.status.value}"
            )
        return proposal

    def _transition(
        self,
        proposal: EvolutionProposal,
        target: ProposalStatus,
        **details: object,
    ) -> EvolutionProposal:
        if target not in self._TRANSITIONS.get(proposal.status, frozenset()):
            raise RuntimeError(
                f"invalid evolution transition: {proposal.status.value} -> {target.value}"
            )
        self._record(
            proposal,
            "evolution_state_transition",
            previous_status=proposal.status.value,
            new_status=target.value,
            **details,
        )
        updated = replace(proposal, status=target)
        self._proposals[proposal.proposal_id] = updated
        return updated

    def _record(self, proposal: EvolutionProposal, event_type: str, **details: object) -> None:
        self.audit.record(
            AuditEvent(
                event_type=event_type,
                intent_id=proposal.proposal_id,
                actor_id=proposal.approver_id or proposal.created_by,
                timestamp=time.time(),
                details={
                    "artifact_sha256": proposal.artifact.sha256,
                    "action": proposal.replacement.manifest.action,
                    "candidate_version": proposal.replacement.manifest.version,
                    **details,
                },
            )
        )
