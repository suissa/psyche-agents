from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol

from .artifacts import ArtifactRecord
from .provenance import ArtifactAttestation, ArtifactProvenanceError, ArtifactProvenanceVerifier
from .release import (
    IdempotencyConflict,
    LeaseLost,
    ReleaseCoordinator,
    ReleaseLease,
    ReleaseSnapshot,
    StaleGeneration,
)


class DeploymentError(RuntimeError):
    """Base error for provider-backed deployment execution."""


class DeploymentDivergence(DeploymentError):
    """The deployment provider and release coordinator disagree."""


class DeploymentAdapter(Protocol):
    """Trusted provider integration; implementations own external fencing.

    deploy() must be idempotent for (target_id, idempotency_key), reject the same
    key with different owner/payload, and enforce monotonic fencing tokens at the
    actual deployment target. It must not execute arbitrary candidate source code.
    inspect() returns the provider's currently effective deployment pointer.
    """

    def deploy(self, request: DeploymentRequest) -> DeploymentReceipt: ...

    def inspect(self, target_id: str) -> DeploymentReceipt | None: ...


@dataclass(frozen=True, slots=True)
class DeploymentRequest:
    lease: ReleaseLease
    expected_generation: int
    version: str
    artifact: ArtifactRecord
    attestation: ArtifactAttestation
    idempotency_key: str

    @property
    def target_id(self) -> str:
        return self.lease.target_id

    @property
    def owner_id(self) -> str:
        return self.lease.owner_id

    @property
    def generation(self) -> int:
        return self.expected_generation + 1


@dataclass(frozen=True, slots=True)
class DeploymentReceipt:
    target_id: str
    owner_id: str
    generation: int
    version: str
    artifact_sha256: str
    fencing_token: int
    idempotency_key: str
    deployment_id: str


class ReleaseExecutionService:
    """Coordinates provider deployment with durable release metadata.

    The external side effect happens before coordinator.commit(). If that final
    commit fails, a retry detects the exact pending provider receipt and asks the
    adapter to idempotently adopt it with a newer fencing token before committing.
    """

    def __init__(
        self,
        coordinator: ReleaseCoordinator,
        adapter: DeploymentAdapter,
        *,
        provenance_verifier: ArtifactProvenanceVerifier | None = None,
    ) -> None:
        self.coordinator = coordinator
        self.adapter = adapter
        self.provenance_verifier = provenance_verifier

    def verify_provenance(
        self,
        artifact: ArtifactRecord,
        *,
        target_id: str,
        version: str,
        attestation: ArtifactAttestation,
    ) -> None:
        verifier = self.provenance_verifier
        if verifier is None or not verifier.verify(
            artifact,
            target_id=target_id,
            version=version,
            attestation=attestation,
        ):
            raise ArtifactProvenanceError(
                "artifact provenance is missing, untrusted or does not match this release"
            )

    def execute(
        self,
        target_id: str,
        owner_id: str,
        *,
        expected_generation: int,
        version: str,
        artifact: ArtifactRecord,
        attestation: ArtifactAttestation,
        idempotency_key: str,
        ttl_seconds: float = 60.0,
    ) -> ReleaseSnapshot:
        self._validate_request(
            target_id,
            owner_id,
            expected_generation,
            version,
            artifact,
            idempotency_key,
            ttl_seconds,
        )
        self.verify_provenance(
            artifact,
            target_id=target_id,
            version=version,
            attestation=attestation,
        )
        current = self.coordinator.get(target_id)
        observed = self._inspect(target_id)

        # An immediate retry after a completed release is read-only: do not create
        # a new fencing token or ask the provider to redeploy.
        if current.generation == expected_generation + 1:
            if (
                current.version == version
                and current.artifact_sha256 == artifact.sha256
            ):
                if self._receipt_is_request(observed, target_id, owner_id,
                                            expected_generation + 1, version,
                                            artifact.sha256, idempotency_key,
                                            current.fencing_token):
                    return current
                if observed is not None and observed.idempotency_key == idempotency_key:
                    raise self._idempotency_conflict()
                raise DeploymentDivergence(
                    "coordinator reports this release, but the provider receipt does not match"
                )
            if observed is not None and observed.idempotency_key == idempotency_key:
                raise self._idempotency_conflict()
            raise StaleGeneration(
                f"expected generation {expected_generation}, found {current.generation}"
            )
        if current.generation != expected_generation:
            raise StaleGeneration(
                f"expected generation {expected_generation}, found {current.generation}"
            )

        self._assert_provider_state(current, observed, target_id, owner_id,
                                    expected_generation, version,
                                    artifact.sha256, idempotency_key)

        lease = self.coordinator.acquire(
            target_id, owner_id, ttl_seconds=ttl_seconds
        )
        try:
            # Re-read both sides after acquiring the lease. Another actor may have
            # committed or the provider pointer may have drifted during preflight.
            current_after_lease = self.coordinator.get(target_id)
            if current_after_lease.generation != expected_generation:
                raise StaleGeneration(
                    f"expected generation {expected_generation}, "
                    f"found {current_after_lease.generation}"
                )
            observed_after_lease = self._inspect(target_id)
            pending = self._assert_provider_state(
                current_after_lease,
                observed_after_lease,
                target_id,
                owner_id,
                expected_generation,
                version,
                artifact.sha256,
                idempotency_key,
                new_fencing_token=lease.fencing_token,
            )

            request = DeploymentRequest(
                lease=lease,
                expected_generation=expected_generation,
                version=version,
                artifact=artifact,
                attestation=attestation,
                idempotency_key=idempotency_key,
            )
            receipt = self.adapter.deploy(request)
            self._assert_receipt(receipt, request)
            observed_after_deploy = self._inspect(target_id)
            if observed_after_deploy != receipt:
                raise DeploymentDivergence(
                    "provider inspect result does not match the deployment receipt"
                )

            snapshot = self.coordinator.commit(
                lease,
                expected_generation=expected_generation,
                version=version,
                artifact_sha256=artifact.sha256,
                idempotency_key=idempotency_key,
            )
            expected_snapshot = ReleaseSnapshot(
                target_id=target_id,
                generation=expected_generation + 1,
                version=version,
                artifact_sha256=artifact.sha256,
                fencing_token=lease.fencing_token,
            )
            if snapshot != expected_snapshot:
                raise DeploymentDivergence(
                    "release coordinator committed an unexpected snapshot"
                )
            return snapshot
        finally:
            try:
                self.coordinator.release(lease)
            except LeaseLost:
                # A later fenced owner may already have superseded this lease.
                pass

    @staticmethod
    def _validate_request(
        target_id: str,
        owner_id: str,
        expected_generation: int,
        version: str,
        artifact: ArtifactRecord,
        idempotency_key: str,
        ttl_seconds: float,
    ) -> None:
        for value, label in (
            (target_id, "target ID"),
            (owner_id, "owner ID"),
            (version, "release version"),
            (idempotency_key, "idempotency key"),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} is required")
        if (
            not isinstance(expected_generation, int)
            or isinstance(expected_generation, bool)
            or expected_generation < 0
        ):
            raise ValueError("expected generation must be a non-negative integer")
        if (
            not isinstance(ttl_seconds, (int, float))
            or isinstance(ttl_seconds, bool)
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise ValueError("lease TTL must be a finite positive number")
        if (
            not isinstance(artifact, ArtifactRecord)
            or not isinstance(artifact.content, bytes)
            or not artifact.content
            or not isinstance(artifact.sha256, str)
            or not isinstance(artifact.size_bytes, int)
            or isinstance(artifact.size_bytes, bool)
            or artifact.size_bytes < 1
            or not isinstance(artifact.media_type, str)
            or not artifact.media_type.strip()
        ):
            raise ValueError("deployment requires a valid non-empty ArtifactRecord")
        try:
            valid_artifact = artifact.verify()
        except (TypeError, ValueError):
            valid_artifact = False
        if not valid_artifact:
            raise ValueError("deployment artifact failed integrity verification")

    def _inspect(self, target_id: str) -> DeploymentReceipt | None:
        receipt = self.adapter.inspect(target_id)
        if receipt is None:
            return None
        if not isinstance(receipt, DeploymentReceipt):
            raise DeploymentDivergence("deployment adapter returned an invalid receipt")
        required_strings = (
            receipt.target_id,
            receipt.owner_id,
            receipt.version,
            receipt.artifact_sha256,
            receipt.idempotency_key,
            receipt.deployment_id,
        )
        if (
            not all(isinstance(value, str) and value.strip() for value in required_strings)
            or not isinstance(receipt.generation, int)
            or isinstance(receipt.generation, bool)
            or receipt.generation < 1
            or not isinstance(receipt.fencing_token, int)
            or isinstance(receipt.fencing_token, bool)
            or receipt.fencing_token < 1
            or len(receipt.artifact_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in receipt.artifact_sha256)
        ):
            raise DeploymentDivergence("deployment adapter returned a malformed receipt")
        return receipt

    @staticmethod
    def _idempotency_conflict() -> IdempotencyConflict:
        return IdempotencyConflict(
            "deployment idempotency key is already bound to another owner or payload"
        )

    def _assert_provider_state(
        self,
        current: ReleaseSnapshot,
        observed: DeploymentReceipt | None,
        target_id: str,
        owner_id: str,
        expected_generation: int,
        version: str,
        artifact_sha256: str,
        idempotency_key: str,
        *,
        new_fencing_token: int | None = None,
    ) -> bool:
        """Return True only for a recoverable provider-ahead receipt."""
        if current.generation == 0:
            baseline_matches = (
                observed is None
                and current.version is None
                and current.artifact_sha256 is None
                and current.fencing_token == 0
            )
        else:
            baseline_matches = (
                observed is not None
                and observed.target_id == target_id
                and observed.generation == current.generation
                and observed.version == current.version
                and observed.artifact_sha256 == current.artifact_sha256
                and observed.fencing_token == current.fencing_token
            )
        if baseline_matches:
            return False

        if observed is not None and observed.idempotency_key == idempotency_key:
            if (
                observed.owner_id != owner_id
                or observed.generation != expected_generation + 1
                or observed.version != version
                or observed.artifact_sha256 != artifact_sha256
            ):
                raise self._idempotency_conflict()

        pending_matches = (
            observed is not None
            and observed.target_id == target_id
            and observed.owner_id == owner_id
            and observed.generation == expected_generation + 1
            and observed.version == version
            and observed.artifact_sha256 == artifact_sha256
            and observed.idempotency_key == idempotency_key
            and observed.fencing_token > current.fencing_token
        )
        if pending_matches:
            if (
                new_fencing_token is not None
                and observed.fencing_token >= new_fencing_token
            ):
                raise DeploymentDivergence(
                    "pending provider receipt has a fencing token that is not older than the new lease"
                )
            return True
        raise DeploymentDivergence(
            "deployment provider state diverges from the release coordinator"
        )

    @staticmethod
    def _receipt_is_request(
        receipt: DeploymentReceipt | None,
        target_id: str,
        owner_id: str,
        generation: int,
        version: str,
        artifact_sha256: str,
        idempotency_key: str,
        fencing_token: int,
    ) -> bool:
        return (
            receipt is not None
            and receipt.target_id == target_id
            and receipt.owner_id == owner_id
            and receipt.generation == generation
            and receipt.version == version
            and receipt.artifact_sha256 == artifact_sha256
            and receipt.idempotency_key == idempotency_key
            and receipt.fencing_token == fencing_token
            and isinstance(receipt.deployment_id, str)
            and bool(receipt.deployment_id.strip())
        )

    @classmethod
    def _assert_receipt(
        cls,
        receipt: DeploymentReceipt,
        request: DeploymentRequest,
    ) -> None:
        if not isinstance(receipt, DeploymentReceipt):
            raise DeploymentDivergence("deployment adapter returned an invalid deployment receipt")
        if not cls._receipt_is_request(
            receipt,
            request.target_id,
            request.owner_id,
            request.generation,
            request.version,
            request.artifact.sha256,
            request.idempotency_key,
            request.lease.fencing_token,
        ):
            raise DeploymentDivergence(
                "deployment adapter receipt does not match the fenced release request"
            )
