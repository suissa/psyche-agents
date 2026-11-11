from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from .artifacts import ArtifactRecord

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ArtifactProvenanceError(PermissionError):
    """Raised when an artifact lacks trusted, matching build provenance."""


@dataclass(frozen=True, slots=True)
class ArtifactAttestation:
    artifact_sha256: str
    artifact_size_bytes: int
    artifact_media_type: str
    target_id: str
    version: str
    builder_id: str
    build_id: str
    source_revision: str
    issued_at: int
    signature: str


class ArtifactProvenanceVerifier(Protocol):
    def verify(
        self,
        artifact: ArtifactRecord,
        *,
        target_id: str,
        version: str,
        attestation: ArtifactAttestation,
    ) -> bool: ...


def _payload(attestation: ArtifactAttestation) -> bytes:
    value = {
        "artifact_sha256": attestation.artifact_sha256,
        "artifact_size_bytes": attestation.artifact_size_bytes,
        "artifact_media_type": attestation.artifact_media_type,
        "target_id": attestation.target_id,
        "version": attestation.version,
        "builder_id": attestation.builder_id,
        "build_id": attestation.build_id,
        "source_revision": attestation.source_revision,
        "issued_at": attestation.issued_at,
    }
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _valid_attestation(attestation: ArtifactAttestation) -> bool:
    if not isinstance(attestation, ArtifactAttestation):
        return False
    string_fields = (
        attestation.artifact_sha256,
        attestation.artifact_media_type,
        attestation.target_id,
        attestation.version,
        attestation.builder_id,
        attestation.build_id,
        attestation.source_revision,
        attestation.signature,
    )
    return (
        all(isinstance(value, str) and value.strip() for value in string_fields)
        and bool(_HEX_SHA256.fullmatch(attestation.artifact_sha256))
        and bool(_HEX_SHA256.fullmatch(attestation.signature))
        and isinstance(attestation.artifact_size_bytes, int)
        and not isinstance(attestation.artifact_size_bytes, bool)
        and attestation.artifact_size_bytes > 0
        and isinstance(attestation.issued_at, int)
        and not isinstance(attestation.issued_at, bool)
        and attestation.issued_at >= 0
    )


def sign_artifact_attestation(
    secret: bytes,
    artifact: ArtifactRecord,
    *,
    target_id: str,
    version: str,
    builder_id: str,
    build_id: str,
    source_revision: str,
    issued_at: int | None = None,
) -> ArtifactAttestation:
    """Create a signed attestation inside an authenticated trusted build service."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("artifact attestation secret must contain at least 32 bytes")
    if not isinstance(artifact, ArtifactRecord) or not artifact.verify():
        raise ValueError("cannot attest an invalid artifact")
    for value, label in (
        (target_id, "target ID"),
        (version, "artifact version"),
        (builder_id, "builder ID"),
        (build_id, "build ID"),
        (source_revision, "source revision"),
        (artifact.media_type, "artifact media type"),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} is required")
    timestamp = int(time.time()) if issued_at is None else issued_at
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise ValueError("attestation issue time must be a non-negative integer")
    unsigned = ArtifactAttestation(
        artifact_sha256=artifact.sha256,
        artifact_size_bytes=artifact.size_bytes,
        artifact_media_type=artifact.media_type,
        target_id=target_id,
        version=version,
        builder_id=builder_id,
        build_id=build_id,
        source_revision=source_revision,
        issued_at=timestamp,
        signature="0" * 64,
    )
    signature = hmac.new(secret, _payload(unsigned), hashlib.sha256).hexdigest()
    return ArtifactAttestation(
        artifact_sha256=unsigned.artifact_sha256,
        artifact_size_bytes=unsigned.artifact_size_bytes,
        artifact_media_type=unsigned.artifact_media_type,
        target_id=unsigned.target_id,
        version=unsigned.version,
        builder_id=unsigned.builder_id,
        build_id=unsigned.build_id,
        source_revision=unsigned.source_revision,
        issued_at=unsigned.issued_at,
        signature=signature,
    )


class HmacArtifactProvenanceVerifier:
    """HMAC verifier with an explicit allowlist of trusted builder identities.

    Attestations are immutable. Key rotation and builder revocation are controlled by
    the application that provisions this verifier.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        trusted_builders: set[str] | frozenset[str],
        clock: Callable[[], float] = time.time,
        max_future_skew_seconds: int = 60,
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("artifact attestation secret must contain at least 32 bytes")
        if not trusted_builders or not all(
            isinstance(value, str) and value.strip() for value in trusted_builders
        ):
            raise ValueError("at least one trusted builder ID is required")
        if (
            not isinstance(max_future_skew_seconds, int)
            or isinstance(max_future_skew_seconds, bool)
            or max_future_skew_seconds < 0
        ):
            raise ValueError("maximum future clock skew must be a non-negative integer")
        self._secret = secret
        self._trusted_builders = frozenset(trusted_builders)
        self._clock = clock
        self._max_future_skew = max_future_skew_seconds

    def verify(
        self,
        artifact: ArtifactRecord,
        *,
        target_id: str,
        version: str,
        attestation: ArtifactAttestation,
    ) -> bool:
        if not _valid_attestation(attestation):
            return False
        try:
            if not isinstance(artifact, ArtifactRecord) or not artifact.verify():
                return False
            if (
                not isinstance(target_id, str)
                or not isinstance(version, str)
                or attestation.builder_id not in self._trusted_builders
                or attestation.artifact_sha256 != artifact.sha256
                or attestation.artifact_size_bytes != artifact.size_bytes
                or attestation.artifact_media_type != artifact.media_type
                or attestation.target_id != target_id
                or attestation.version != version
            ):
                return False
            now = float(self._clock())
            if not math.isfinite(now) or attestation.issued_at > now + self._max_future_skew:
                return False
            expected = hmac.new(self._secret, _payload(attestation), hashlib.sha256).hexdigest()
        except (TypeError, ValueError, OverflowError):
            return False
        return hmac.compare_digest(expected, attestation.signature)


def attestation_to_dict(attestation: ArtifactAttestation) -> dict[str, object]:
    return {
        "artifact_sha256": attestation.artifact_sha256,
        "artifact_size_bytes": attestation.artifact_size_bytes,
        "artifact_media_type": attestation.artifact_media_type,
        "target_id": attestation.target_id,
        "version": attestation.version,
        "builder_id": attestation.builder_id,
        "build_id": attestation.build_id,
        "source_revision": attestation.source_revision,
        "issued_at": attestation.issued_at,
        "signature": attestation.signature,
    }


def attestation_from_dict(value: dict[str, object]) -> ArtifactAttestation:
    try:
        attestation = ArtifactAttestation(
            artifact_sha256=value["artifact_sha256"],
            artifact_size_bytes=value["artifact_size_bytes"],
            artifact_media_type=value["artifact_media_type"],
            target_id=value["target_id"],
            version=value["version"],
            builder_id=value["builder_id"],
            build_id=value["build_id"],
            source_revision=value["source_revision"],
            issued_at=value["issued_at"],
            signature=value["signature"],
        )
    except (KeyError, TypeError) as error:
        raise ValueError("stored artifact attestation is malformed") from error
    if not _valid_attestation(attestation):
        raise ValueError("stored artifact attestation contains invalid fields")
    return attestation
