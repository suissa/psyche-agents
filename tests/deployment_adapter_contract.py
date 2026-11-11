from __future__ import annotations

import hashlib
import time

from psyche_agents.artifacts import ArtifactRecord
from psyche_agents.deployment import (
    DeploymentAdapter,
    DeploymentDivergence,
    DeploymentReceipt,
    DeploymentRequest,
)
from psyche_agents.provenance import sign_artifact_attestation
from psyche_agents.release import IdempotencyConflict, ReleaseLease


class DeploymentAdapterContract:
    """Reusable behavioral contract for concrete DeploymentAdapter implementations.

    Subclasses provide create_adapter() and should use an isolated provider test
    target/project/namespace. The adapter must map provider-specific failures to
    the stable Psyche deployment exceptions asserted here.
    """

    CONTRACT_SECRET = b"psyche-deployment-adapter-contract-secret"

    def create_adapter(self) -> DeploymentAdapter:
        raise NotImplementedError

    def setUp(self) -> None:
        super().setUp()
        self.adapter = self.create_adapter()

    def make_request(
        self,
        *,
        target_id: str = "contract-service",
        owner_id: str = "contract-controller",
        version: str = "1.0.0",
        content: bytes = b"contract-artifact-v1",
        fencing_token: int = 10,
        expected_generation: int = 0,
        idempotency_key: str = "contract-release-1",
    ) -> DeploymentRequest:
        artifact = ArtifactRecord(
            hashlib.sha256(content).hexdigest(),
            len(content),
            "application/octet-stream",
            content,
        )
        attestation = sign_artifact_attestation(
            self.CONTRACT_SECRET,
            artifact,
            target_id=target_id,
            version=version,
            builder_id="contract-builder",
            build_id=f"{target_id}-{version}",
            source_revision="a" * 40,
            issued_at=int(time.time()),
        )
        lease = ReleaseLease(
            target_id=target_id,
            owner_id=owner_id,
            fencing_token=fencing_token,
            expires_at=time.time() + 300,
        )
        return DeploymentRequest(
            lease=lease,
            expected_generation=expected_generation,
            version=version,
            artifact=artifact,
            attestation=attestation,
            idempotency_key=idempotency_key,
        )

    def test_deploy_receipt_is_bound_to_request_and_inspection(self) -> None:
        request = self.make_request()
        receipt = self.adapter.deploy(request)

        self.assertIsInstance(receipt, DeploymentReceipt)
        self.assertEqual(request.target_id, receipt.target_id)
        self.assertEqual(request.owner_id, receipt.owner_id)
        self.assertEqual(request.generation, receipt.generation)
        self.assertEqual(request.version, receipt.version)
        self.assertEqual(request.artifact.sha256, receipt.artifact_sha256)
        self.assertEqual(request.lease.fencing_token, receipt.fencing_token)
        self.assertEqual(request.idempotency_key, receipt.idempotency_key)
        self.assertTrue(receipt.deployment_id.strip())
        self.assertEqual(receipt, self.adapter.inspect(request.target_id))

    def test_exact_retry_is_idempotent(self) -> None:
        request = self.make_request()
        first = self.adapter.deploy(request)
        retry = self.adapter.deploy(request)

        self.assertEqual(first, retry)
        self.assertEqual(first.deployment_id, retry.deployment_id)
        self.assertEqual(retry, self.adapter.inspect(request.target_id))

    def test_idempotency_key_cannot_be_rebound_to_another_payload(self) -> None:
        original = self.make_request()
        first = self.adapter.deploy(original)
        conflicting = self.make_request(
            owner_id="different-controller",
            version="9.9.9",
            content=b"different-artifact",
            fencing_token=11,
            idempotency_key=original.idempotency_key,
        )

        with self.assertRaises(IdempotencyConflict):
            self.adapter.deploy(conflicting)

        self.assertEqual(first, self.adapter.inspect(original.target_id))

    def test_stale_fencing_token_is_rejected_at_provider_boundary(self) -> None:
        current_request = self.make_request(fencing_token=12)
        current_receipt = self.adapter.deploy(current_request)
        stale_request = self.make_request(
            version="1.1.0",
            content=b"contract-artifact-v2",
            fencing_token=11,
            expected_generation=1,
            idempotency_key="contract-release-2",
        )

        with self.assertRaises(DeploymentDivergence):
            self.adapter.deploy(stale_request)

        self.assertEqual(current_receipt, self.adapter.inspect(current_request.target_id))

    def test_higher_fence_adopts_same_pending_deployment(self) -> None:
        original_request = self.make_request(fencing_token=20)
        original_receipt = self.adapter.deploy(original_request)
        adopted_request = self.make_request(fencing_token=21)
        adopted_receipt = self.adapter.deploy(adopted_request)

        self.assertEqual(original_receipt.deployment_id, adopted_receipt.deployment_id)
        self.assertEqual(original_receipt.generation, adopted_receipt.generation)
        self.assertEqual(original_receipt.artifact_sha256, adopted_receipt.artifact_sha256)
        self.assertEqual(21, adopted_receipt.fencing_token)
        self.assertEqual(adopted_receipt, self.adapter.inspect(adopted_request.target_id))

    def test_idempotency_keys_are_scoped_to_target(self) -> None:
        first_request = self.make_request(
            target_id="contract-service-a",
            idempotency_key="shared-key",
            fencing_token=1,
        )
        second_request = self.make_request(
            target_id="contract-service-b",
            idempotency_key="shared-key",
            fencing_token=1,
        )

        first = self.adapter.deploy(first_request)
        second = self.adapter.deploy(second_request)

        self.assertEqual(first_request.target_id, first.target_id)
        self.assertEqual(second_request.target_id, second.target_id)
        self.assertNotEqual(first.deployment_id, second.deployment_id)
        self.assertEqual(first, self.adapter.inspect(first_request.target_id))
        self.assertEqual(second, self.adapter.inspect(second_request.target_id))
