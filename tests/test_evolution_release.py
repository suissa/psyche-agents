from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from psyche_agents.artifacts import ArtifactRecord, SQLiteArtifactStore
from psyche_agents.deployment import (
    DeploymentDivergence,
    DeploymentReceipt,
    ReleaseExecutionService,
)
from psyche_agents.evolution import (
    EvolutionaryEngine,
    HmacEvolutionApprovalVerifier,
    ProposalStatus,
    sign_evolution_approval,
)
from psyche_agents.loader import PreparedArtifactLoader
from psyche_agents.models import SideEffect, ToolManifest, ValidationReport
from psyche_agents.persistence import SQLiteEvolutionJournal, SQLitePreparedArtifactCatalog
from psyche_agents.registry import ToolBinding, ToolRegistry
from psyche_agents.release import IdempotencyConflict, SQLiteReleaseCoordinator
from psyche_agents.provenance import (
    ArtifactProvenanceError,
    HmacArtifactProvenanceVerifier,
    sign_artifact_attestation,
)


SECRET = b"release-aware-evolution-secret-32-bytes"


class Handler:
    def __init__(self, name: str) -> None:
        self.name = name

    def execute(self, intent):
        return {"handler": self.name}


def manifest(version: str) -> ToolManifest:
    return ToolManifest(
        name="catalog",
        action="catalog_lookup",
        version=version,
        archetype="sage",
        side_effects=SideEffect.READ_ONLY,
        description="Trusted catalog lookup",
    )


class TrustedResolver:
    def __init__(self, *bindings: ToolBinding) -> None:
        self.bindings = {binding.manifest: binding for binding in bindings}

    def resolve(self, value: ToolManifest) -> ToolBinding:
        try:
            return self.bindings[value]
        except KeyError as error:
            raise KeyError(f"trusted handler unavailable: {value.action}@{value.version}") from error


class PassingValidator:
    def validate(self, candidate, artifact) -> ValidationReport:
        return ValidationReport(
            passed=True,
            checks=("unit", "contract", "security"),
            artifact_sha256=artifact.sha256,
        )


class FakeDeploymentAdapter:
    def __init__(self) -> None:
        self.current: dict[str, DeploymentReceipt] = {}
        self.operations: dict[tuple[str, str], DeploymentReceipt] = {}
        self.calls = 0

    def inspect(self, target_id: str) -> DeploymentReceipt | None:
        return self.current.get(target_id)

    def deploy(self, request) -> DeploymentReceipt:
        self.calls += 1
        key = (request.target_id, request.idempotency_key)
        previous = self.operations.get(key)
        if previous is not None:
            if (
                previous.owner_id != request.owner_id
                or previous.generation != request.generation
                or previous.version != request.version
                or previous.artifact_sha256 != request.artifact.sha256
            ):
                raise IdempotencyConflict("provider idempotency key payload conflict")
            current = self.current.get(request.target_id)
            if current is not None and current.fencing_token > request.lease.fencing_token:
                raise DeploymentDivergence("provider rejected an obsolete fence")
            receipt = replace(previous, fencing_token=request.lease.fencing_token)
        else:
            current = self.current.get(request.target_id)
            if current is not None and current.fencing_token >= request.lease.fencing_token:
                raise DeploymentDivergence("provider fencing token did not advance")
            receipt = DeploymentReceipt(
                target_id=request.target_id,
                owner_id=request.owner_id,
                generation=request.generation,
                version=request.version,
                artifact_sha256=request.artifact.sha256,
                fencing_token=request.lease.fencing_token,
                idempotency_key=request.idempotency_key,
                deployment_id=f"provider-deployment-{self.calls}",
            )
        self.operations[key] = receipt
        self.current[request.target_id] = receipt
        return receipt


class CommitFailOnceCoordinator:
    def __init__(self, delegate: SQLiteReleaseCoordinator) -> None:
        self.delegate = delegate
        self.fail_next = True

    def get(self, *args, **kwargs):
        return self.delegate.get(*args, **kwargs)

    def acquire(self, *args, **kwargs):
        return self.delegate.acquire(*args, **kwargs)

    def commit(self, *args, **kwargs):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated release coordinator commit failure")
        return self.delegate.commit(*args, **kwargs)

    def release(self, *args, **kwargs):
        return self.delegate.release(*args, **kwargs)


class ReleaseAwareEvolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.base = ToolBinding(manifest("1.0.0"), Handler("base"))
        self.candidate = ToolBinding(manifest("1.1.0"), Handler("candidate"))
        self.resolver = TrustedResolver(self.base, self.candidate)
        content = b"reviewed-and-validated-candidate-artifact"
        self.artifact = ArtifactRecord(
            hashlib.sha256(content).hexdigest(),
            len(content),
            "application/octet-stream",
            content,
        )
        self.adapter = FakeDeploymentAdapter()
        self.coordinator = SQLiteReleaseCoordinator(self.root / "releases.sqlite3")
        self.provenance_secret = b"evolution-provenance-secret-at-least-32-bytes"
        self.attestation = sign_artifact_attestation(
            self.provenance_secret,
            self.artifact,
            target_id="catalog-service",
            version="1.1.0",
            builder_id="trusted-ci",
            build_id="catalog-build-001",
            source_revision="e" * 40,
            issued_at=int(time.time()),
        )
        self.provenance_verifier = HmacArtifactProvenanceVerifier(
            self.provenance_secret,
            trusted_builders={"trusted-ci"},
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def registry(self, *, candidate_active: bool = False) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(self.candidate if candidate_active else self.base)
        return registry

    def new_engine(self, registry: ToolRegistry) -> EvolutionaryEngine:
        artifact_store = SQLiteArtifactStore(self.root / "artifacts.sqlite3")
        prepared_catalog = SQLitePreparedArtifactCatalog(self.root / "prepared.sqlite3")
        loader = PreparedArtifactLoader(artifact_store, catalog=prepared_catalog)
        journal = SQLiteEvolutionJournal(self.root / "evolution-journal.sqlite3")
        return EvolutionaryEngine(
            registry,
            artifact_store=artifact_store,
            artifact_loader=loader,
            approval_verifier=HmacEvolutionApprovalVerifier(SECRET),
            audit=journal,
            proposal_store=journal,
            binding_resolver=self.resolver,
        )

    def approved_proposal(self, engine: EvolutionaryEngine) -> str:
        proposal = engine.propose(
            self.candidate,
            engine.registry.generation,
            artifact=self.artifact.content,
            creator_id="magician-agent",
        )
        validated = engine.validate(proposal.proposal_id, PassingValidator())
        approval = sign_evolution_approval(
            SECRET,
            validated,
            approver_id="release-approver",
            expires_at=int(time.time()) + 300,
            nonce=f"nonce-{proposal.proposal_id}",
        )
        engine.approve(proposal.proposal_id, approval)
        return proposal.proposal_id

    def service(self, coordinator=None) -> ReleaseExecutionService:
        return ReleaseExecutionService(
            coordinator or self.coordinator,
            self.adapter,
            provenance_verifier=self.provenance_verifier,
        )

    def test_approved_proposal_is_deployed_before_local_registry_activation(self) -> None:
        registry = self.registry()
        engine = self.new_engine(registry)
        proposal_id = self.approved_proposal(engine)

        active = engine.activate_with_release(
            proposal_id,
            self.service(),
            target_id="catalog-service",
            owner_id="release-controller",
            attestation=self.attestation,
            ttl_seconds=30,
        )

        self.assertEqual(ProposalStatus.ACTIVE, active.status)
        self.assertEqual(1, active.release_generation)
        self.assertEqual(1, active.release_fencing_token)
        self.assertEqual("catalog-service", active.release_target_id)
        self.assertEqual("release-controller", active.release_owner_id)
        self.assertEqual("psyche-evolution:" + proposal_id, active.release_idempotency_key)
        self.assertEqual(self.candidate.handler, registry.resolve("catalog_lookup").handler)
        receipt = self.adapter.inspect("catalog-service")
        self.assertEqual(active.release_generation, receipt.generation)
        self.assertEqual(active.release_fencing_token, receipt.fencing_token)
        self.assertEqual(1, self.adapter.calls)

    def test_provider_success_and_coordinator_failure_resume_after_restart(self) -> None:
        first_registry = self.registry()
        first_engine = self.new_engine(first_registry)
        proposal_id = self.approved_proposal(first_engine)
        failing_service = self.service(CommitFailOnceCoordinator(self.coordinator))

        with self.assertRaisesRegex(RuntimeError, "simulated release coordinator commit failure"):
            first_engine.activate_with_release(
                proposal_id,
                failing_service,
                target_id="catalog-service",
                owner_id="release-controller",
                attestation=self.attestation,
                ttl_seconds=30,
            )

        interrupted = first_engine.get(proposal_id)
        self.assertEqual(ProposalStatus.ACTIVATING, interrupted.status)
        self.assertEqual(0, self.coordinator.get("catalog-service").generation)
        first_receipt = self.adapter.inspect("catalog-service")
        self.assertIsNotNone(first_receipt)
        self.assertEqual(1, first_receipt.fencing_token)
        self.assertEqual(self.base.handler, first_registry.resolve("catalog_lookup").handler)

        restarted_registry = self.registry()
        restarted_engine = self.new_engine(restarted_registry)
        recovered = restarted_engine.get(proposal_id)
        self.assertEqual(ProposalStatus.ACTIVATING, recovered.status)
        self.assertEqual("catalog-service", recovered.release_target_id)
        self.assertEqual(0, recovered.release_expected_generation)
        self.assertEqual(self.attestation, recovered.release_attestation)

        active = restarted_engine.activate_with_release(
            proposal_id,
            self.service(),
            target_id="catalog-service",
            owner_id="release-controller",
            attestation=self.attestation,
            ttl_seconds=30,
        )

        adopted_receipt = self.adapter.inspect("catalog-service")
        self.assertEqual(ProposalStatus.ACTIVE, active.status)
        self.assertEqual(1, active.release_generation)
        self.assertEqual(2, active.release_fencing_token)
        self.assertEqual(first_receipt.deployment_id, adopted_receipt.deployment_id)
        self.assertEqual(2, self.adapter.calls)
        self.assertEqual(self.candidate.handler, restarted_registry.resolve("catalog_lookup").handler)

    def test_committed_provider_release_is_not_redeployed_after_local_swap_failure(self) -> None:
        registry = self.registry()
        engine = self.new_engine(registry)
        proposal_id = self.approved_proposal(engine)
        original_replace = registry.replace

        def unavailable_registry(*args, **kwargs):
            raise RuntimeError("simulated local registry failure")

        registry.replace = unavailable_registry
        with self.assertRaisesRegex(RuntimeError, "simulated local registry failure"):
            engine.activate_with_release(
                proposal_id,
                self.service(),
                target_id="catalog-service",
                owner_id="release-controller",
                attestation=self.attestation,
                ttl_seconds=30,
            )
        registry.replace = original_replace

        self.assertEqual(ProposalStatus.ACTIVATING, engine.get(proposal_id).status)
        self.assertEqual(1, self.coordinator.get("catalog-service").generation)
        self.assertEqual(1, self.adapter.calls)

        restarted_registry = self.registry()
        restarted_engine = self.new_engine(restarted_registry)
        active = restarted_engine.activate_with_release(
            proposal_id,
            self.service(),
            target_id="catalog-service",
            owner_id="release-controller",
            attestation=self.attestation,
            ttl_seconds=30,
        )
        self.assertEqual(ProposalStatus.ACTIVE, active.status)
        self.assertEqual(1, self.adapter.calls)
        self.assertEqual(self.candidate.handler, restarted_registry.resolve("catalog_lookup").handler)

    def test_invalid_attestation_does_not_start_release_activation(self) -> None:
        registry = self.registry()
        engine = self.new_engine(registry)
        proposal_id = self.approved_proposal(engine)
        invalid = replace(self.attestation, signature="0" * 64)

        with self.assertRaises(ArtifactProvenanceError):
            engine.activate_with_release(
                proposal_id,
                self.service(),
                target_id="catalog-service",
                owner_id="release-controller",
                attestation=invalid,
                ttl_seconds=30,
            )

        self.assertEqual(ProposalStatus.APPROVED, engine.get(proposal_id).status)
        self.assertEqual(0, self.coordinator.get("catalog-service").generation)
        self.assertEqual(0, self.adapter.calls)

    def test_release_aware_proposal_rejects_local_only_rollback(self) -> None:
        registry = self.registry()
        engine = self.new_engine(registry)
        proposal_id = self.approved_proposal(engine)
        active = engine.activate_with_release(
            proposal_id,
            self.service(),
            target_id="catalog-service",
            owner_id="release-controller",
            attestation=self.attestation,
            ttl_seconds=30,
        )
        self.assertEqual(ProposalStatus.ACTIVE, active.status)

        with self.assertRaisesRegex(RuntimeError, "provider-aware rollback"):
            engine.rollback(proposal_id)

        self.assertEqual(ProposalStatus.ACTIVE, engine.get(proposal_id).status)
        self.assertEqual(1, self.coordinator.get("catalog-service").generation)
        self.assertEqual(self.candidate.handler, registry.resolve("catalog_lookup").handler)

    def test_release_retry_cannot_change_persisted_target_or_owner(self) -> None:
        registry = self.registry()
        engine = self.new_engine(registry)
        proposal_id = self.approved_proposal(engine)
        service = self.service(CommitFailOnceCoordinator(self.coordinator))

        with self.assertRaises(RuntimeError):
            engine.activate_with_release(
                proposal_id,
                service,
                target_id="catalog-service",
                owner_id="release-controller",
                attestation=self.attestation,
                ttl_seconds=30,
            )

        with self.assertRaisesRegex(RuntimeError, "persisted target, owner"):
            engine.activate_with_release(
                proposal_id,
                self.service(),
                target_id="other-target",
                owner_id="release-controller",
                attestation=self.attestation,
                ttl_seconds=30,
            )
        self.assertEqual(1, self.adapter.calls)


if __name__ == "__main__":
    unittest.main()
