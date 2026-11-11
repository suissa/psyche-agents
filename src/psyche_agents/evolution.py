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
from .deployment import ReleaseExecutionService
from .models import AuditEvent, ValidationReport
from .registry import ToolBinding, ToolRegistry
from .loader import ArtifactLoader, PreparedArtifactLoader, TrustedBindingResolver
from .persistence import EvolutionProposalStore, manifest_from_dict, manifest_to_dict
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
    approval_issued_at: int | None = None
    approval_expires_at: int | None = None
    approval_signature: str | None = None
    activation_generation: int | None = None
    release_target_id: str | None = None
    release_owner_id: str | None = None
    release_expected_generation: int | None = None
    release_idempotency_key: str | None = None
    release_generation: int | None = None
    release_fencing_token: int | None = None


class CandidateValidator(Protocol):
    def validate(
        self, candidate: ToolBinding, artifact: ArtifactRecord
    ) -> ValidationReport: ...


class EvolutionApprovalVerifier(Protocol):
    def verify(
        self, proposal: EvolutionProposal, approval: EvolutionApproval
    ) -> bool: ...

    def verify_recorded(self, proposal: EvolutionProposal) -> bool: ...


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

    def verify_recorded(self, proposal: EvolutionProposal) -> bool:
        """Verify durable approval evidence without consuming its nonce a second time."""
        report = proposal.validation
        if (
            report is None
            or not report.passed
            or report.artifact_sha256 != proposal.artifact.sha256
            or not isinstance(report.validation_id, str)
            or not report.validation_id.strip()
            or not proposal.approver_id
            or proposal.approver_id == proposal.created_by
            or not proposal.approval_nonce
            or proposal.approval_issued_at is None
            or proposal.approval_expires_at is None
            or not proposal.approval_signature
        ):
            return False
        if (
            proposal.approval_issued_at < 0
            or proposal.approval_expires_at <= proposal.approval_issued_at
            or proposal.approval_expires_at - proposal.approval_issued_at
            > self._max_lifetime
        ):
            return False
        approval = EvolutionApproval(
            proposal_id=proposal.proposal_id,
            artifact_sha256=proposal.artifact.sha256,
            validation_id=report.validation_id,
            approver_id=proposal.approver_id,
            issued_at=proposal.approval_issued_at,
            expires_at=proposal.approval_expires_at,
            nonce=proposal.approval_nonce,
            signature=proposal.approval_signature,
        )
        expected = hmac.new(
            self._secret, _approval_payload(approval), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, approval.signature)


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
            ProposalStatus.ACTIVE, ProposalStatus.APPROVED, ProposalStatus.FAILED
        }),
        ProposalStatus.ACTIVE: frozenset({ProposalStatus.ROLLING_BACK}),
        ProposalStatus.ROLLING_BACK: frozenset({
            ProposalStatus.ROLLED_BACK, ProposalStatus.ACTIVE, ProposalStatus.FAILED
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
        proposal_store: EvolutionProposalStore | None = None,
        binding_resolver: TrustedBindingResolver | None = None,
    ) -> None:
        self.registry = registry
        self.artifact_store = artifact_store or InMemoryArtifactStore()
        self.artifact_loader = artifact_loader or PreparedArtifactLoader(self.artifact_store)
        self.approval_verifier = approval_verifier
        self.audit = audit or InMemoryAuditLog()
        self.proposal_store = proposal_store
        self.binding_resolver = binding_resolver
        self._proposals: dict[str, EvolutionProposal] = {}
        self._revisions: dict[str, int] = {}
        self._lock = RLock()
        if self.proposal_store is not None:
            self._restore_persisted_proposals()

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
            self._persist_and_record(
                proposal,
                "proposal_created",
                creating=True,
                status=proposal.status.value,
            )
            self._proposals[proposal.proposal_id] = proposal
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
                approval_issued_at=approval.issued_at,
                approval_expires_at=approval.expires_at,
                approval_signature=approval.signature,
            )
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
            return self._transition(updated, ProposalStatus.ACTIVE)

    def activate_with_release(
        self,
        proposal_id: str,
        release_service: ReleaseExecutionService,
        *,
        target_id: str,
        owner_id: str,
        ttl_seconds: float = 60.0,
    ) -> EvolutionProposal:
        """Deploy an approved proposal and activate its trusted local binding.

        The release intent is persisted before the external side effect. If the
        provider succeeds but the coordinator or local registry step fails, the
        proposal remains ACTIVATING and can be resumed with the same target/owner.
        The persisted generation and idempotency key are never silently rebased.
        """
        if not isinstance(target_id, str) or not target_id.strip():
            raise ValueError("release target ID is required")
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("release owner ID is required")

        with self._lock:
            proposal = self._proposals[proposal_id]
            if proposal.status is ProposalStatus.APPROVED:
                if any(
                    value is not None
                    for value in (
                        proposal.release_target_id,
                        proposal.release_owner_id,
                        proposal.release_expected_generation,
                        proposal.release_idempotency_key,
                        proposal.release_generation,
                        proposal.release_fencing_token,
                    )
                ):
                    raise RuntimeError("approved proposal already contains release metadata")
                baseline = release_service.coordinator.get(target_id)
                release_key = f"psyche-evolution:{proposal.proposal_id}"
                proposal = replace(
                    proposal,
                    release_target_id=target_id,
                    release_owner_id=owner_id,
                    release_expected_generation=baseline.generation,
                    release_idempotency_key=release_key,
                )
                proposal = self._transition(
                    proposal,
                    ProposalStatus.ACTIVATING,
                    release_target_id=target_id,
                    release_expected_generation=baseline.generation,
                    release_idempotency_key=release_key,
                )
            elif proposal.status in (ProposalStatus.ACTIVATING, ProposalStatus.ACTIVE):
                if (
                    proposal.release_target_id != target_id
                    or proposal.release_owner_id != owner_id
                    or proposal.release_expected_generation is None
                    or proposal.release_idempotency_key
                    != f"psyche-evolution:{proposal.proposal_id}"
                ):
                    raise RuntimeError(
                        "release activation can only resume with its persisted target, owner and idempotency key"
                    )
            else:
                raise RuntimeError(
                    f"proposal must be approved or awaiting release recovery, got {proposal.status.value}"
                )

        # Re-validate immutable candidate bytes and the trusted prepared binding on
        # every attempt, including retries after a process restart.
        stored = self.artifact_store.get(proposal.artifact.sha256)
        if not stored.verify() or stored.content != proposal.artifact.content:
            raise RuntimeError("candidate artifact failed integrity verification")
        prepared_binding = self.artifact_loader.load(proposal.artifact.sha256)
        if prepared_binding.manifest != proposal.replacement.manifest:
            raise RuntimeError("prepared handler manifest does not match the approved candidate")

        assert proposal.release_expected_generation is not None
        assert proposal.release_target_id is not None
        assert proposal.release_owner_id is not None
        assert proposal.release_idempotency_key is not None
        snapshot = release_service.execute(
            proposal.release_target_id,
            proposal.release_owner_id,
            expected_generation=proposal.release_expected_generation,
            version=proposal.replacement.manifest.version,
            artifact=stored,
            idempotency_key=proposal.release_idempotency_key,
            ttl_seconds=ttl_seconds,
        )
        if (
            snapshot.target_id != proposal.release_target_id
            or snapshot.generation != proposal.release_expected_generation + 1
            or snapshot.version != proposal.replacement.manifest.version
            or snapshot.artifact_sha256 != proposal.artifact.sha256
            or snapshot.fencing_token < 1
        ):
            raise RuntimeError("release coordinator returned a snapshot that does not match the proposal")

        # Provider deployment is confirmed. Now reconcile this process's local
        # runtime registry. A different active binding is never overwritten.
        current_binding = self.registry.resolve(proposal.replacement.manifest.action)
        if self._same_active_binding(prepared_binding, current_binding):
            local_generation = self.registry.generation
        elif self._same_active_binding(proposal.previous_binding, current_binding):
            local_generation_before_swap = self.registry.generation
            local_generation = self.registry.replace(
                prepared_binding,
                expected_generation=local_generation_before_swap,
            )
        else:
            raise RuntimeError(
                "external release succeeded but local registry contains an unknown binding; "
                "restore the trusted previous or candidate handler before retrying"
            )

        with self._lock:
            latest = self._proposals[proposal_id]
            if latest.status is ProposalStatus.ACTIVE:
                if (
                    latest.release_generation != snapshot.generation
                    or latest.release_fencing_token != snapshot.fencing_token
                    or latest.activation_generation != local_generation
                ):
                    raise RuntimeError("active proposal release evidence does not match the coordinator")
                return latest
            if latest.status is not ProposalStatus.ACTIVATING:
                raise RuntimeError("proposal state changed during external release execution")
            updated = replace(
                latest,
                activation_generation=local_generation,
                release_generation=snapshot.generation,
                release_fencing_token=snapshot.fencing_token,
            )
            return self._transition(
                updated,
                ProposalStatus.ACTIVE,
                release_target_id=target_id,
                release_generation=snapshot.generation,
                release_fencing_token=snapshot.fencing_token,
                local_registry_generation=local_generation,
            )

    def rollback(self, proposal_id: str) -> EvolutionProposal:
        """Restore the previously active binding using CAS; never overwrite a newer change."""
        with self._lock:
            proposal = self._require(proposal_id, ProposalStatus.ACTIVE)
            if proposal.release_target_id is not None:
                raise RuntimeError(
                    "release-aware proposals cannot use local-only rollback; "
                    "provider-aware rollback requires a separately verified previous artifact"
                )
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
            return self._transition(updated, ProposalStatus.ROLLED_BACK)

    def get(self, proposal_id: str) -> EvolutionProposal:
        with self._lock:
            return self._proposals[proposal_id]

    def list(self) -> tuple[EvolutionProposal, ...]:
        with self._lock:
            return tuple(self._proposals[key] for key in sorted(self._proposals))

    def _proposal_payload(self, proposal: EvolutionProposal) -> dict[str, object]:
        validation = None
        if proposal.validation is not None:
            validation = {
                "passed": proposal.validation.passed,
                "checks": list(proposal.validation.checks),
                "failures": list(proposal.validation.failures),
                "artifact_sha256": proposal.validation.artifact_sha256,
                "validation_id": proposal.validation.validation_id,
            }
        return {
            "proposal_id": proposal.proposal_id,
            "replacement_manifest": manifest_to_dict(proposal.replacement.manifest),
            "previous_manifest": manifest_to_dict(proposal.previous_binding.manifest),
            "artifact_sha256": proposal.artifact.sha256,
            "artifact_size_bytes": proposal.artifact.size_bytes,
            "artifact_media_type": proposal.artifact.media_type,
            "expected_generation": proposal.expected_generation,
            "created_by": proposal.created_by,
            "status": proposal.status.value,
            "validation": validation,
            "approver_id": proposal.approver_id,
            "approval_nonce": proposal.approval_nonce,
            "approval_issued_at": proposal.approval_issued_at,
            "approval_expires_at": proposal.approval_expires_at,
            "approval_signature": proposal.approval_signature,
            "activation_generation": proposal.activation_generation,
            "release_target_id": proposal.release_target_id,
            "release_owner_id": proposal.release_owner_id,
            "release_expected_generation": proposal.release_expected_generation,
            "release_idempotency_key": proposal.release_idempotency_key,
            "release_generation": proposal.release_generation,
            "release_fencing_token": proposal.release_fencing_token,
        }

    def _persist_proposal(
        self,
        proposal: EvolutionProposal,
        *,
        creating: bool = False,
    ) -> None:
        if self.proposal_store is None:
            return
        expected_revision = None if creating else self._revisions.get(proposal.proposal_id)
        if not creating and expected_revision is None:
            raise RuntimeError("proposal revision is missing from durable state")
        revision = self.proposal_store.save(
            proposal.proposal_id,
            self._proposal_payload(proposal),
            expected_revision=expected_revision,
        )
        self._revisions[proposal.proposal_id] = revision

    def _resolve_binding(self, manifest, *, artifact: ArtifactRecord | None = None) -> ToolBinding:
        if artifact is not None:
            try:
                binding = self.artifact_loader.load(artifact.sha256)
            except KeyError:
                if self.binding_resolver is None:
                    raise RuntimeError(
                        "candidate handler is not loaded; configure a trusted binding resolver"
                    )
                binding = self.binding_resolver.resolve(manifest)
                if not isinstance(binding, ToolBinding) or binding.manifest != manifest:
                    raise RuntimeError("trusted resolver returned a mismatched candidate handler")
                self.artifact_loader.stage(artifact, binding)
                binding = self.artifact_loader.load(artifact.sha256)
        else:
            current = self.registry.resolve(manifest.action)
            if current is not None and current.manifest == manifest:
                return current
            if self.binding_resolver is None:
                raise RuntimeError(
                    f"previous handler {manifest.action}@{manifest.version} is not registered; "
                    "configure a trusted binding resolver"
                )
            binding = self.binding_resolver.resolve(manifest)
        if not isinstance(binding, ToolBinding) or binding.manifest != manifest:
            raise RuntimeError("trusted binding resolver returned a mismatched manifest")
        return binding

    def _hydrate_proposal(
        self,
        proposal_id: str,
        payload: dict[str, object],
    ) -> EvolutionProposal:
        if payload.get("proposal_id") != proposal_id:
            raise RuntimeError("persisted proposal ID does not match its storage key")
        try:
            replacement_manifest = manifest_from_dict(payload["replacement_manifest"])
            previous_manifest = manifest_from_dict(payload["previous_manifest"])
            artifact_sha256 = payload["artifact_sha256"]
            artifact_size = payload["artifact_size_bytes"]
            media_type = payload["artifact_media_type"]
            expected_generation = payload["expected_generation"]
            creator_id = payload["created_by"]
            status = ProposalStatus(payload["status"])
            approver_id = payload["approver_id"]
            approval_nonce = payload["approval_nonce"]
            approval_issued_at = payload.get("approval_issued_at")
            approval_expires_at = payload.get("approval_expires_at")
            approval_signature = payload.get("approval_signature")
            activation_generation = payload["activation_generation"]
            release_target_id = payload.get("release_target_id")
            release_owner_id = payload.get("release_owner_id")
            release_expected_generation = payload.get("release_expected_generation")
            release_idempotency_key = payload.get("release_idempotency_key")
            release_generation = payload.get("release_generation")
            release_fencing_token = payload.get("release_fencing_token")
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(f"persisted proposal metadata is invalid: {proposal_id}") from error
        if (
            not isinstance(artifact_sha256, str)
            or not isinstance(artifact_size, int)
            or not isinstance(media_type, str)
            or not media_type.strip()
            or not isinstance(expected_generation, int)
            or expected_generation < 0
            or not isinstance(creator_id, str)
            or not creator_id.strip()
            or (approver_id is not None and not isinstance(approver_id, str))
            or (approval_nonce is not None and not isinstance(approval_nonce, str))
            or (approval_issued_at is not None and not isinstance(approval_issued_at, int))
            or (approval_expires_at is not None and not isinstance(approval_expires_at, int))
            or (approval_signature is not None and not isinstance(approval_signature, str))
            or (activation_generation is not None and (
                not isinstance(activation_generation, int) or isinstance(activation_generation, bool)
            ))
            or (release_target_id is not None and (
                not isinstance(release_target_id, str) or not release_target_id.strip()
            ))
            or (release_owner_id is not None and (
                not isinstance(release_owner_id, str) or not release_owner_id.strip()
            ))
            or (release_expected_generation is not None and (
                not isinstance(release_expected_generation, int)
                or isinstance(release_expected_generation, bool)
                or release_expected_generation < 0
            ))
            or (release_idempotency_key is not None and (
                not isinstance(release_idempotency_key, str) or not release_idempotency_key.strip()
            ))
            or (release_generation is not None and (
                not isinstance(release_generation, int)
                or isinstance(release_generation, bool)
                or release_generation < 1
            ))
            or (release_fencing_token is not None and (
                not isinstance(release_fencing_token, int)
                or isinstance(release_fencing_token, bool)
                or release_fencing_token < 1
            ))
        ):
            raise RuntimeError(f"persisted proposal fields are invalid: {proposal_id}")
        release_intent_fields = (
            release_target_id,
            release_owner_id,
            release_expected_generation,
            release_idempotency_key,
        )
        if any(value is not None for value in release_intent_fields) and not all(
            value is not None for value in release_intent_fields
        ):
            raise RuntimeError("persisted release intent is incomplete")
        if (release_generation is None) != (release_fencing_token is None):
            raise RuntimeError("persisted release receipt metadata is incomplete")
        if release_generation is not None and (
            release_target_id is None or status is not ProposalStatus.ACTIVE
        ):
            raise RuntimeError("persisted release receipt is not attached to an active release proposal")
        if status is ProposalStatus.ACTIVE and release_target_id is not None and release_generation is None:
            raise RuntimeError("active release proposal is missing its provider receipt")
        artifact = self.artifact_store.get(artifact_sha256)
        if (
            not artifact.verify()
            or artifact.size_bytes != artifact_size
            or artifact.media_type != media_type
        ):
            raise RuntimeError(f"persisted proposal artifact does not match its metadata: {proposal_id}")
        replacement = self._resolve_binding(replacement_manifest, artifact=artifact)
        previous = self._resolve_binding(previous_manifest)
        if replacement.manifest.action != previous.manifest.action:
            raise RuntimeError("persisted proposal handlers do not share the same action")
        validation_payload = payload.get("validation")
        validation = None
        if validation_payload is not None:
            if not isinstance(validation_payload, dict):
                raise RuntimeError("persisted validation report must be an object")
            try:
                passed = validation_payload["passed"]
                checks = validation_payload["checks"]
                failures = validation_payload["failures"]
                validation_hash = validation_payload["artifact_sha256"]
                validation_id = validation_payload["validation_id"]
                if (
                    not isinstance(passed, bool)
                    or not isinstance(checks, list)
                    or not all(isinstance(item, str) for item in checks)
                    or not isinstance(failures, list)
                    or not all(isinstance(item, str) for item in failures)
                    or (validation_hash is not None and not isinstance(validation_hash, str))
                    or not isinstance(validation_id, str)
                    or not validation_id.strip()
                ):
                    raise ValueError("validation report fields are invalid")
                validation = ValidationReport(
                    passed=passed,
                    checks=tuple(checks),
                    failures=tuple(failures),
                    artifact_sha256=validation_hash,
                    validation_id=validation_id,
                )
            except (KeyError, TypeError, ValueError) as error:
                raise RuntimeError(f"persisted validation report is invalid: {proposal_id}") from error
        if validation is not None and validation.passed:
            if validation.artifact_sha256 != artifact.sha256:
                raise RuntimeError("persisted passing validation references another artifact")
        approval_required_statuses = {
            ProposalStatus.APPROVED,
            ProposalStatus.ACTIVATING,
            ProposalStatus.ACTIVE,
            ProposalStatus.ROLLING_BACK,
            ProposalStatus.ROLLED_BACK,
        }
        if status in approval_required_statuses and (
            validation is None
            or not validation.passed
            or validation.artifact_sha256 != artifact.sha256
            or not approver_id
            or not approval_nonce
            or approval_issued_at is None
            or approval_expires_at is None
            or not approval_signature
        ):
            raise RuntimeError("persisted approved proposal is missing its signed approval evidence")
        if status is ProposalStatus.VALIDATED and (
            validation is None or not validation.passed
        ):
            raise RuntimeError("persisted validated proposal has no passing validation report")

        proposal = EvolutionProposal(
            proposal_id=proposal_id,
            replacement=replacement,
            previous_binding=previous,
            artifact=artifact,
            expected_generation=expected_generation,
            created_by=creator_id,
            status=status,
            validation=validation,
            approver_id=approver_id,
            approval_nonce=approval_nonce,
            approval_issued_at=approval_issued_at,
            approval_expires_at=approval_expires_at,
            approval_signature=approval_signature,
            activation_generation=activation_generation,
            release_target_id=release_target_id,
            release_owner_id=release_owner_id,
            release_expected_generation=release_expected_generation,
            release_idempotency_key=release_idempotency_key,
            release_generation=release_generation,
            release_fencing_token=release_fencing_token,
        )
        if status in approval_required_statuses:
            verifier = self.approval_verifier
            verify_recorded = getattr(verifier, "verify_recorded", None)
            if not callable(verify_recorded) or not verify_recorded(proposal):
                raise RuntimeError("persisted human approval signature failed verification")
        return proposal

    def _same_active_binding(self, expected: ToolBinding, actual: ToolBinding | None) -> bool:
        return (
            actual is expected
            or (
                actual is not None
                and actual.manifest == expected.manifest
                and actual.handler is expected.handler
            )
        )

    def _restore_persisted_proposals(self) -> None:
        assert self.proposal_store is not None
        for proposal_id, payload, revision in self.proposal_store.load_all():
            proposal = self._hydrate_proposal(proposal_id, payload)
            self._proposals[proposal_id] = proposal
            self._revisions[proposal_id] = revision
            self._recover_interrupted_proposal(proposal)

    def _recover_interrupted_proposal(self, proposal: EvolutionProposal) -> None:
        current = self.registry.resolve(proposal.replacement.manifest.action)
        if proposal.status is ProposalStatus.VALIDATING:
            self._transition(
                proposal,
                ProposalStatus.FAILED,
                recovery="validation_interrupted_by_process_restart",
            )
            return
        if proposal.status is ProposalStatus.ACTIVATING:
            if proposal.release_target_id is not None:
                # Provider state can only be reconciled with its release coordinator.
                # The caller must explicitly resume through activate_with_release().
                return
            if self._same_active_binding(proposal.replacement, current):
                recovered = replace(proposal, activation_generation=self.registry.generation)
                self._transition(
                    recovered,
                    ProposalStatus.ACTIVE,
                    recovery="activation_observed_during_restart",
                )
            elif self._same_active_binding(proposal.previous_binding, current):
                recovered = replace(proposal, expected_generation=self.registry.generation)
                self._transition(
                    recovered,
                    ProposalStatus.APPROVED,
                    recovery="activation_not_committed_before_restart",
                )
            else:
                self._transition(
                    proposal,
                    ProposalStatus.FAILED,
                    recovery="activation_state_could_not_be_reconciled",
                )
            return
        if proposal.status is ProposalStatus.ROLLING_BACK:
            if self._same_active_binding(proposal.previous_binding, current):
                recovered = replace(proposal, activation_generation=self.registry.generation)
                self._transition(
                    recovered,
                    ProposalStatus.ROLLED_BACK,
                    recovery="rollback_observed_during_restart",
                )
            elif self._same_active_binding(proposal.replacement, current):
                recovered = replace(proposal, activation_generation=self.registry.generation)
                self._transition(
                    recovered,
                    ProposalStatus.ACTIVE,
                    recovery="rollback_not_committed_before_restart",
                )
            else:
                self._transition(
                    proposal,
                    ProposalStatus.FAILED,
                    recovery="rollback_state_could_not_be_reconciled",
                )
            return
        if proposal.status in {
            ProposalStatus.PROPOSED,
            ProposalStatus.VALIDATED,
            ProposalStatus.AWAITING_APPROVAL,
            ProposalStatus.APPROVED,
        } and self._same_active_binding(proposal.previous_binding, current):
            if proposal.expected_generation != self.registry.generation:
                recovered = replace(proposal, expected_generation=self.registry.generation)
                self._persist_and_record(
                    recovered,
                    "proposal_rehydrated",
                    registry_generation=self.registry.generation,
                    rebased_expected_generation=True,
                )
                self._proposals[proposal.proposal_id] = recovered
            return
        if proposal.status is ProposalStatus.ACTIVE and self._same_active_binding(
            proposal.replacement, current
        ):
            if proposal.activation_generation != self.registry.generation:
                recovered = replace(proposal, activation_generation=self.registry.generation)
                self._persist_and_record(
                    recovered,
                    "proposal_rehydrated",
                    registry_generation=self.registry.generation,
                )
                self._proposals[proposal.proposal_id] = recovered

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
        updated = replace(proposal, status=target)
        self._persist_and_record(
            updated,
            "evolution_state_transition",
            previous_status=proposal.status.value,
            new_status=target.value,
            **details,
        )
        self._proposals[proposal.proposal_id] = updated
        return updated

    def _persist_and_record(
        self,
        proposal: EvolutionProposal,
        event_type: str,
        *,
        creating: bool = False,
        **details: object,
    ) -> None:
        atomic_writer = getattr(self.proposal_store, "save_with_event", None)
        if (
            self.proposal_store is not None
            and self.proposal_store is self.audit
            and callable(atomic_writer)
        ):
            expected_revision = (
                None if creating else self._revisions.get(proposal.proposal_id)
            )
            if not creating and expected_revision is None:
                raise RuntimeError("proposal revision is missing from durable state")
            next_revision = 1 if expected_revision is None else expected_revision + 1
            event = self._audit_event(
                proposal,
                event_type,
                proposal_revision=next_revision,
                **details,
            )
            revision = atomic_writer(
                proposal.proposal_id,
                self._proposal_payload(proposal),
                expected_revision=expected_revision,
                event=event,
            )
            self._revisions[proposal.proposal_id] = revision
            return

        self._persist_proposal(proposal, creating=creating)
        self._record(proposal, event_type, **details)

    def _audit_event(
        self,
        proposal: EvolutionProposal,
        event_type: str,
        **details: object,
    ) -> AuditEvent:
        return AuditEvent(
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

    def _record(self, proposal: EvolutionProposal, event_type: str, **details: object) -> None:
        self.audit.record(self._audit_event(proposal, event_type, **details))
