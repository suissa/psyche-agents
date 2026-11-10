from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from threading import RLock
from typing import Callable, Protocol

from .models import ValidationReport
from .registry import ToolBinding, ToolRegistry


class ProposalStatus(str, Enum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    APPROVED = "approved"
    ACTIVATED = "activated"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class FailureSignal:
    action: str
    error_code: str
    evidence: tuple[str, ...] = ()
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class EvolutionProposal:
    proposal_id: str
    replacement: ToolBinding
    expected_generation: int
    status: ProposalStatus = ProposalStatus.PROPOSED
    validation: ValidationReport | None = None
    approver_id: str | None = None


class CandidateValidator(Protocol):
    def validate(self, candidate: ToolBinding) -> ValidationReport: ...


class EvolutionaryEngine:
    """Stages improvements; activation requires validation and explicit human approval.

    This engine swaps already-loaded handlers. It deliberately does not execute generated
    source code, install dependencies, create commits, or mutate a remote repository.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry
        self._proposals: dict[str, EvolutionProposal] = {}
        self._lock = RLock()

    def propose(
        self, replacement: ToolBinding, expected_generation: int
    ) -> EvolutionProposal:
        generation, bindings = self.registry.snapshot()
        if generation != expected_generation:
            raise RuntimeError("registry changed before proposal creation")
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
        proposal = EvolutionProposal(
            proposal_id=secrets_token(),
            replacement=replacement,
            expected_generation=expected_generation,
        )
        with self._lock:
            self._proposals[proposal.proposal_id] = proposal
        return proposal

    def propose_from_failure(
        self,
        signal: FailureSignal,
        synthesize: Callable[[FailureSignal], ToolBinding],
        expected_generation: int,
    ) -> EvolutionProposal:
        """Ask an external synthesizer for a candidate; no generated code is run here."""
        candidate = synthesize(signal)
        if not isinstance(candidate, ToolBinding) or candidate.manifest.action != signal.action:
            raise ValueError("synthesizer returned an invalid candidate")
        return self.propose(candidate, expected_generation)

    def validate(
        self, proposal_id: str, validator: CandidateValidator
    ) -> EvolutionProposal:
        with self._lock:
            proposal = self._require(proposal_id, ProposalStatus.PROPOSED)
        report = validator.validate(proposal.replacement)
        status = ProposalStatus.VALIDATED if report.passed else ProposalStatus.REJECTED
        updated = replace(proposal, status=status, validation=report)
        with self._lock:
            self._proposals[proposal_id] = updated
        return updated

    def approve(self, proposal_id: str, approver_id: str) -> EvolutionProposal:
        if not approver_id.strip():
            raise ValueError("an authenticated approver identity is required")
        with self._lock:
            proposal = self._require(proposal_id, ProposalStatus.VALIDATED)
            if proposal.validation is None or not proposal.validation.passed:
                raise RuntimeError("candidate has not passed validation")
            updated = replace(
                proposal, status=ProposalStatus.APPROVED, approver_id=approver_id
            )
            self._proposals[proposal_id] = updated
            return updated

    def activate(self, proposal_id: str) -> EvolutionProposal:
        with self._lock:
            proposal = self._require(proposal_id, ProposalStatus.APPROVED)
        self.registry.replace(
            proposal.replacement,
            expected_generation=proposal.expected_generation,
        )
        updated = replace(proposal, status=ProposalStatus.ACTIVATED)
        with self._lock:
            self._proposals[proposal_id] = updated
        return updated

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


def secrets_token() -> str:
    import secrets

    return secrets.token_urlsafe(18)
