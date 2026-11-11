from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from psyche_agents.artifacts import ArtifactRecord
from psyche_agents.deployment import (
    DeploymentDivergence,
    DeploymentReceipt,
    ReleaseExecutionService,
)
from psyche_agents.release import (
    IdempotencyConflict,
    ReleaseLease,
    SQLiteReleaseCoordinator,
    StaleGeneration,
)
from psyche_agents.provenance import (
    ArtifactProvenanceError,
    HmacArtifactProvenanceVerifier,
    sign_artifact_attestation,
)


class FakeClock:
    def __init__(self, value: float = 1000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class FakeDeploymentAdapter:
    """Test provider that enforces fencing and idempotent adoption."""

    def __init__(self) -> None:
        self.current: dict[str, DeploymentReceipt] = {}
        self.operations: dict[tuple[str, str], DeploymentReceipt] = {}
        self.deploy_calls = 0
        self.corrupt_inspection = False

    def inspect(self, target_id: str) -> DeploymentReceipt | None:
        receipt = self.current.get(target_id)
        if receipt is not None and self.corrupt_inspection:
            return replace(receipt, deployment_id="different-provider-deployment")
        return receipt

    def deploy(self, request) -> DeploymentReceipt:
        self.deploy_calls += 1
        key = (request.target_id, request.idempotency_key)
        prior = self.operations.get(key)
        if prior is not None:
            if (
                prior.owner_id != request.owner_id
                or prior.generation != request.generation
                or prior.version != request.version
                or prior.artifact_sha256 != request.artifact.sha256
            ):
                raise IdempotencyConflict("provider idempotency key payload conflict")
            current = self.current.get(request.target_id)
            if current is not None and current.fencing_token > request.lease.fencing_token:
                raise DeploymentDivergence("stale deployment fencing token")
            receipt = replace(
                prior,
                fencing_token=request.lease.fencing_token,
            )
        else:
            current = self.current.get(request.target_id)
            if current is not None and current.fencing_token >= request.lease.fencing_token:
                raise DeploymentDivergence("deployment fencing token did not advance")
            receipt = DeploymentReceipt(
                target_id=request.target_id,
                owner_id=request.owner_id,
                generation=request.generation,
                version=request.version,
                artifact_sha256=request.artifact.sha256,
                fencing_token=request.lease.fencing_token,
                idempotency_key=request.idempotency_key,
                deployment_id=f"deployment-{self.deploy_calls}",
            )
        self.operations[key] = receipt
        self.current[request.target_id] = receipt
        return receipt


class CommitFailOnceCoordinator:
    def __init__(self, delegate: SQLiteReleaseCoordinator) -> None:
        self.delegate = delegate
        self.fail_next_commit = True

    def acquire(self, *args, **kwargs):
        return self.delegate.acquire(*args, **kwargs)

    def release(self, *args, **kwargs):
        return self.delegate.release(*args, **kwargs)

    def get(self, *args, **kwargs):
        return self.delegate.get(*args, **kwargs)

    def commit(self, *args, **kwargs):
        if self.fail_next_commit:
            self.fail_next_commit = False
            raise RuntimeError("simulated coordinator commit failure")
        return self.delegate.commit(*args, **kwargs)


class ReleaseExecutionTests(unittest.TestCase):
    PROVENANCE_SECRET = b"release-execution-provenance-secret-32-bytes"
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.clock = FakeClock()
        self.coordinator = SQLiteReleaseCoordinator(
            self.root / "releases.sqlite3",
            clock=self.clock,
        )
        self.adapter = FakeDeploymentAdapter()
        content = b"trusted-prepared-artifact"
        self.artifact = ArtifactRecord(
            hashlib.sha256(content).hexdigest(),
            len(content),
            "application/octet-stream",
            content,
        )
        self.attestation = sign_artifact_attestation(
            self.PROVENANCE_SECRET,
            self.artifact,
            target_id="payments-api",
            version="1.1.0",
            builder_id="trusted-ci",
            build_id="payments-build-001",
            source_revision="c" * 40,
            issued_at=1_000,
        )
        self.provenance_verifier = HmacArtifactProvenanceVerifier(
            self.PROVENANCE_SECRET,
            trusted_builders={"trusted-ci"},
            clock=self.clock,
        )
        self.service = ReleaseExecutionService(
            self.coordinator,
            self.adapter,
            provenance_verifier=self.provenance_verifier,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def execute(self, *, expected_generation: int = 0):
        return self.service.execute(
            "payments-api",
            "release-controller",
            expected_generation=expected_generation,
            version="1.1.0",
            artifact=self.artifact,
            attestation=self.attestation,
            idempotency_key="payments-api-1.1.0",
            ttl_seconds=30,
        )

    def test_deploys_and_commits_only_after_matching_provider_receipt(self) -> None:
        result = self.execute()
        self.assertEqual(1, result.generation)
        self.assertEqual(self.artifact.sha256, result.artifact_sha256)
        self.assertEqual(1, result.fencing_token)
        self.assertEqual(result, self.coordinator.get("payments-api"))
        self.assertEqual(1, self.adapter.deploy_calls)
        self.assertTrue(self.coordinator.verify_event_chain())

    def test_rejects_external_drift_before_changing_coordinator(self) -> None:
        self.adapter.current["payments-api"] = DeploymentReceipt(
            target_id="payments-api",
            owner_id="other-controller",
            generation=1,
            version="9.9.9",
            artifact_sha256=hashlib.sha256(b"unknown").hexdigest(),
            fencing_token=7,
            idempotency_key="foreign-release",
            deployment_id="foreign-deployment",
        )
        with self.assertRaises(DeploymentDivergence):
            self.execute()
        self.assertEqual(0, self.coordinator.get("payments-api").generation)
        self.assertEqual(0, self.adapter.deploy_calls)

    def test_recovers_provider_success_when_coordinator_commit_failed(self) -> None:
        failing = CommitFailOnceCoordinator(self.coordinator)
        service = ReleaseExecutionService(
            failing,
            self.adapter,
            provenance_verifier=self.provenance_verifier,
        )
        with self.assertRaisesRegex(RuntimeError, "simulated coordinator commit failure"):
            service.execute(
                "payments-api",
                "release-controller",
                expected_generation=0,
                version="1.1.0",
                artifact=self.artifact,
                attestation=self.attestation,
                idempotency_key="payments-api-1.1.0",
                ttl_seconds=30,
            )
        self.assertEqual(0, self.coordinator.get("payments-api").generation)
        first_receipt = self.adapter.current["payments-api"]
        self.assertEqual(1, first_receipt.fencing_token)

        recovered = service.execute(
            "payments-api",
            "release-controller",
            expected_generation=0,
            version="1.1.0",
            artifact=self.artifact,
            attestation=self.attestation,
            idempotency_key="payments-api-1.1.0",
            ttl_seconds=30,
        )
        second_receipt = self.adapter.current["payments-api"]
        self.assertEqual(1, recovered.generation)
        self.assertEqual(2, second_receipt.fencing_token)
        self.assertEqual(first_receipt.deployment_id, second_receipt.deployment_id)
        self.assertEqual(2, self.adapter.deploy_calls)
        self.assertTrue(self.coordinator.verify_event_chain())

    def test_completed_retry_is_read_only(self) -> None:
        first = self.execute()
        deployment_id = self.adapter.current["payments-api"].deployment_id
        calls = self.adapter.deploy_calls
        second = self.execute()
        self.assertEqual(first, second)
        self.assertEqual(calls, self.adapter.deploy_calls)
        self.assertEqual(deployment_id, self.adapter.current["payments-api"].deployment_id)

    def test_rejects_corrupted_artifact_before_acquiring_release_lease(self) -> None:
        bad = replace(self.artifact, sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.service.execute(
                "payments-api",
                "release-controller",
                expected_generation=0,
                version="1.1.0",
                artifact=bad,
                idempotency_key="bad-artifact",
            )
        self.assertEqual(0, self.coordinator.get("payments-api").generation)
        self.assertEqual(0, self.adapter.deploy_calls)

    def test_rejects_provider_receipt_mismatch_without_committing_metadata(self) -> None:
        self.adapter.corrupt_inspection = True
        with self.assertRaises(DeploymentDivergence):
            self.execute()
        self.assertEqual(0, self.coordinator.get("payments-api").generation)
        self.assertTrue(self.coordinator.verify_event_chain())

    def test_invalid_attestation_fails_before_provider_or_coordinator_mutation(self) -> None:
        invalid = replace(self.attestation, signature="0" * 64)
        with self.assertRaises(ArtifactProvenanceError):
            self.service.execute(
                "payments-api",
                "release-controller",
                expected_generation=0,
                version="1.1.0",
                artifact=self.artifact,
                attestation=invalid,
                idempotency_key="bad-provenance",
                ttl_seconds=30,
            )
        self.assertEqual(0, self.coordinator.get("payments-api").generation)
        self.assertEqual(0, self.adapter.deploy_calls)

    def test_stale_generation_is_rejected(self) -> None:
        self.execute()
        next_content = b"different-next-release"
        next_artifact = ArtifactRecord(
            hashlib.sha256(next_content).hexdigest(),
            len(next_content),
            "application/octet-stream",
            next_content,
        )
        with self.assertRaises(StaleGeneration):
            self.service.execute(
                "payments-api",
                "release-controller",
                expected_generation=0,
                version="1.2.0",
                artifact=next_artifact,
                attestation=sign_artifact_attestation(
                    self.PROVENANCE_SECRET,
                    next_artifact,
                    target_id="payments-api",
                    version="1.2.0",
                    builder_id="trusted-ci",
                    build_id="payments-build-002",
                    source_revision="d" * 40,
                    issued_at=1_000,
                ),
                idempotency_key="payments-api-1.2.0",
                ttl_seconds=30,
            )
        self.assertEqual(1, self.adapter.deploy_calls)

    def test_provider_rejects_reuse_of_idempotency_key_for_another_payload(self) -> None:
        self.adapter.current["payments-api"] = DeploymentReceipt(
            target_id="payments-api",
            owner_id="release-controller",
            generation=1,
            version="9.9.9",
            artifact_sha256=hashlib.sha256(b"other-payload").hexdigest(),
            fencing_token=1,
            idempotency_key="payments-api-1.1.0",
            deployment_id="existing-deployment",
        )
        with self.assertRaises(IdempotencyConflict):
            self.execute()
        self.assertEqual(0, self.coordinator.get("payments-api").generation)
        self.assertEqual(0, self.adapter.deploy_calls)

    def test_malformed_provider_receipt_fails_closed(self) -> None:
        self.adapter.current["payments-api"] = DeploymentReceipt(
            target_id="payments-api",
            owner_id="release-controller",
            generation=1,
            version="1.1.0",
            artifact_sha256=self.artifact.sha256,
            fencing_token=1,
            idempotency_key="payments-api-1.1.0",
            deployment_id=None,
        )
        with self.assertRaises(DeploymentDivergence):
            self.execute()
        self.assertEqual(0, self.coordinator.get("payments-api").generation)


if __name__ == "__main__":
    unittest.main()
