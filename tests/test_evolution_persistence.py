from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from psyche_agents.artifacts import SQLiteArtifactStore
from psyche_agents.audit import SQLiteAuditLog
from psyche_agents.evolution import (
    EvolutionaryEngine,
    HmacEvolutionApprovalVerifier,
    ProposalStatus,
    sign_evolution_approval,
)
from psyche_agents.loader import PreparedArtifactLoader
from psyche_agents.models import SideEffect, ToolManifest, ValidationReport
from psyche_agents.persistence import (
    SQLiteEvolutionProposalStore,
    SQLitePreparedArtifactCatalog,
)
from psyche_agents.registry import ToolBinding, ToolRegistry


SECRET = b"durable-evolution-approval-secret-32-bytes"


class Handler:
    def __init__(self, label: str) -> None:
        self.label = label

    def execute(self, intent):
        return {"handler": self.label}


class TrustedResolver:
    """Represents the host application's already-loaded, trusted handler set."""

    def __init__(self, *bindings: ToolBinding) -> None:
        self.bindings = {binding.manifest: binding for binding in bindings}

    def resolve(self, manifest: ToolManifest) -> ToolBinding:
        try:
            return self.bindings[manifest]
        except KeyError as error:
            raise KeyError(f"trusted handler is not provisioned: {manifest.action}@{manifest.version}") from error


class PassingValidator:
    def validate(self, candidate, artifact) -> ValidationReport:
        return ValidationReport(
            passed=True,
            checks=("unit", "contract", "security"),
            artifact_sha256=artifact.sha256,
        )


def manifest(version: str) -> ToolManifest:
    return ToolManifest(
        name="lookup",
        action="lookup",
        version=version,
        archetype="sage",
        side_effects=SideEffect.READ_ONLY,
        description="Trusted lookup capability",
    )


class DurableEvolutionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = SQLiteArtifactStore(self.root / "artifacts.sqlite3")
        self.proposals = SQLiteEvolutionProposalStore(self.root / "proposals.sqlite3")
        self.catalog = SQLitePreparedArtifactCatalog(self.root / "prepared.sqlite3")
        self.audit = SQLiteAuditLog(self.root / "audit.sqlite3")
        self.base = ToolBinding(manifest("1.0.0"), Handler("base"))
        self.candidate = ToolBinding(manifest("1.1.0"), Handler("candidate"))
        self.resolver = TrustedResolver(self.base, self.candidate)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def new_engine(self, registry: ToolRegistry) -> EvolutionaryEngine:
        # Reopen every durable adapter to model a new process rather than reusing
        # connection or application state from the previous engine instance.
        artifacts = SQLiteArtifactStore(self.root / "artifacts.sqlite3")
        proposals = SQLiteEvolutionProposalStore(self.root / "proposals.sqlite3")
        catalog = SQLitePreparedArtifactCatalog(self.root / "prepared.sqlite3")
        audit = SQLiteAuditLog(self.root / "audit.sqlite3")
        loader = PreparedArtifactLoader(artifacts, catalog=catalog)
        return EvolutionaryEngine(
            registry,
            artifact_store=artifacts,
            artifact_loader=loader,
            approval_verifier=HmacEvolutionApprovalVerifier(SECRET),
            audit=audit,
            proposal_store=proposals,
            binding_resolver=self.resolver,
        )

    def base_registry(self) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(self.base)
        return registry

    def test_proposal_store_rejects_stale_revision_writes(self) -> None:
        store = SQLiteEvolutionProposalStore(self.root / "cas-proposals.sqlite3")
        payload = {"proposal_id": "cas-proposal", "state": "proposed"}
        first_revision = store.save(
            "cas-proposal", payload, expected_revision=None
        )
        second_revision = store.save(
            "cas-proposal",
            {"proposal_id": "cas-proposal", "state": "validated"},
            expected_revision=first_revision,
        )
        self.assertEqual(2, second_revision)
        with self.assertRaisesRegex(RuntimeError, "revision changed"):
            store.save(
                "cas-proposal",
                {"proposal_id": "cas-proposal", "state": "rejected"},
                expected_revision=first_revision,
            )
        self.assertEqual("validated", store.load_all()[0][1]["state"])

    def test_restart_rebases_registry_generation_only_when_previous_handler_matches(self) -> None:
        original_registry = self.base_registry()
        engine = self.new_engine(original_registry)
        proposal = engine.propose(
            self.candidate,
            original_registry.generation,
            artifact=b"candidate-after-bootstrap-rebase",
        )

        restarted_registry = self.base_registry()
        restarted_registry.register(
            ToolBinding(
                ToolManifest(
                    name="inventory",
                    action="inventory",
                    version="1.0.0",
                    archetype="sage",
                    side_effects=SideEffect.READ_ONLY,
                ),
                Handler("inventory"),
            )
        )
        self.assertNotEqual(proposal.expected_generation, restarted_registry.generation)
        restarted = self.new_engine(restarted_registry)
        recovered = restarted.get(proposal.proposal_id)
        self.assertEqual(restarted_registry.generation, recovered.expected_generation)

    def test_restart_rejects_tampered_approval_signature(self) -> None:
        registry = self.base_registry()
        engine = self.new_engine(registry)
        proposal = engine.propose(
            self.candidate,
            registry.generation,
            artifact=b"candidate-with-tampered-approval",
        )
        validated = engine.validate(proposal.proposal_id, PassingValidator())
        approved = engine.approve(
            proposal.proposal_id,
            sign_evolution_approval(
                SECRET,
                validated,
                approver_id="release-approver",
                expires_at=int(time.time()) + 120,
                nonce="tamper-detection-approval",
            ),
        )
        records = self.proposals.load_all()
        payload = records[0][1]
        payload["approval_signature"] = "0" * 64
        self.proposals.save(
            proposal.proposal_id,
            payload,
            expected_revision=records[0][2],
        )
        with self.assertRaisesRegex(RuntimeError, "approval signature failed verification"):
            self.new_engine(self.base_registry())

    def test_proposal_approval_and_active_binding_rehydrate_after_restart(self) -> None:
        registry = self.base_registry()
        engine = self.new_engine(registry)
        proposal = engine.propose(
            self.candidate,
            registry.generation,
            artifact=b"trusted-prepared-candidate",
            creator_id="magician-agent",
        )
        validated = engine.validate(proposal.proposal_id, PassingValidator())
        approval = sign_evolution_approval(
            SECRET,
            validated,
            approver_id="release-approver",
            expires_at=int(time.time()) + 120,
            nonce="durable-approval-nonce",
        )
        approved = engine.approve(proposal.proposal_id, approval)
        self.assertEqual(ProposalStatus.APPROVED, approved.status)
        self.assertEqual(1, self.proposals.count())
        self.assertEqual(1, self.catalog.count())

        restarted_registry = self.base_registry()
        restarted = self.new_engine(restarted_registry)
        restored = restarted.get(proposal.proposal_id)
        self.assertEqual(ProposalStatus.APPROVED, restored.status)
        self.assertEqual(validated.validation, restored.validation)
        self.assertEqual(approval.nonce, restored.approval_nonce)
        self.assertEqual(approval.issued_at, restored.approval_issued_at)
        self.assertEqual(approval.expires_at, restored.approval_expires_at)
        self.assertEqual(approval.signature, restored.approval_signature)
        self.assertEqual(
            self.artifacts.get(proposal.artifact.sha256),
            restored.artifact,
        )
        restored_loader = PreparedArtifactLoader(self.artifacts, catalog=self.catalog)
        self.assertEqual(
            (proposal.artifact.sha256,),
            restored_loader.restore_catalog(self.resolver),
        )
        self.assertIs(
            self.candidate.handler,
            restored_loader.load(proposal.artifact.sha256).handler,
        )

        active = restarted.activate(proposal.proposal_id)
        self.assertEqual(ProposalStatus.ACTIVE, active.status)
        self.assertIs(self.candidate.handler, restarted_registry.resolve("lookup").handler)

        # A fresh process boots the trusted candidate version. The engine rebases
        # its rollback CAS to this process's registry generation after identity checks.
        active_registry = ToolRegistry()
        active_registry.register(self.candidate)
        after_restart = self.new_engine(active_registry)
        recovered = after_restart.get(proposal.proposal_id)
        self.assertEqual(ProposalStatus.ACTIVE, recovered.status)
        self.assertEqual(active_registry.generation, recovered.activation_generation)

        rolled_back = after_restart.rollback(proposal.proposal_id)
        self.assertEqual(ProposalStatus.ROLLED_BACK, rolled_back.status)
        self.assertIs(self.base.handler, active_registry.resolve("lookup").handler)
        self.assertTrue(self.audit.verify_chain())

    def test_interrupted_validation_is_marked_failed_on_recovery(self) -> None:
        registry = self.base_registry()
        engine = self.new_engine(registry)
        proposal = engine.propose(
            self.candidate,
            registry.generation,
            artifact=b"candidate-with-interrupted-validation",
        )
        with engine._lock:
            engine._transition(engine.get(proposal.proposal_id), ProposalStatus.VALIDATING)

        restarted = self.new_engine(self.base_registry())
        recovered = restarted.get(proposal.proposal_id)
        self.assertEqual(ProposalStatus.FAILED, recovered.status)
        persisted = {
            proposal_id: payload
            for proposal_id, payload, _ in self.proposals.load_all()
        }[proposal.proposal_id]
        self.assertEqual(ProposalStatus.FAILED.value, persisted["status"])

    def test_activation_committed_before_crash_is_reconciled_from_trusted_registry(self) -> None:
        registry = self.base_registry()
        engine = self.new_engine(registry)
        proposal = engine.propose(
            self.candidate,
            registry.generation,
            artifact=b"candidate-activation-crash-window",
        )
        validated = engine.validate(proposal.proposal_id, PassingValidator())
        approved = engine.approve(
            proposal.proposal_id,
            sign_evolution_approval(
                SECRET,
                validated,
                approver_id="release-approver",
                expires_at=int(time.time()) + 120,
                nonce="activation-crash-nonce",
            ),
        )
        with engine._lock:
            engine._transition(approved, ProposalStatus.ACTIVATING)
        registry.replace(
            self.candidate,
            expected_generation=proposal.expected_generation,
        )

        restarted_registry = ToolRegistry()
        restarted_registry.register(self.candidate)
        restarted = self.new_engine(restarted_registry)
        recovered = restarted.get(proposal.proposal_id)
        self.assertEqual(ProposalStatus.ACTIVE, recovered.status)
        self.assertEqual(restarted_registry.generation, recovered.activation_generation)


if __name__ == "__main__":
    unittest.main()
