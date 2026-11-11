from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace

from psyche_agents.artifacts import ArtifactRecord
from psyche_agents.deployment import ReleaseExecutionService
from psyche_agents.provenance import (
    ArtifactProvenanceError,
    HmacArtifactProvenanceVerifier,
    sign_artifact_attestation,
)
from psyche_agents.release import SQLiteReleaseCoordinator


SECRET = b"artifact-provenance-secret-at-least-32-bytes"


class ArtifactProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        content = b"built-and-reviewed-artifact"
        self.artifact = ArtifactRecord(
            hashlib.sha256(content).hexdigest(),
            len(content),
            "application/octet-stream",
            content,
        )
        self.attestation = sign_artifact_attestation(
            SECRET,
            self.artifact,
            target_id="catalog-service",
            version="2.1.0",
            builder_id="trusted-ci",
            build_id="build-2026-11-11-001",
            source_revision="a" * 40,
            issued_at=1_000,
        )
        self.verifier = HmacArtifactProvenanceVerifier(
            SECRET,
            trusted_builders={"trusted-ci"},
            clock=lambda: 1_010,
        )

    def test_valid_attestation_binds_artifact_target_version_and_builder(self) -> None:
        self.assertTrue(
            self.verifier.verify(
                self.artifact,
                target_id="catalog-service",
                version="2.1.0",
                attestation=self.attestation,
            )
        )

    def test_rejects_untrusted_builder(self) -> None:
        verifier = HmacArtifactProvenanceVerifier(
            SECRET,
            trusted_builders={"other-builder"},
            clock=lambda: 1_010,
        )
        self.assertFalse(
            verifier.verify(
                self.artifact,
                target_id="catalog-service",
                version="2.1.0",
                attestation=self.attestation,
            )
        )

    def test_rejects_wrong_target_or_version(self) -> None:
        self.assertFalse(
            self.verifier.verify(
                self.artifact,
                target_id="payments-api",
                version="2.1.0",
                attestation=self.attestation,
            )
        )
        self.assertFalse(
            self.verifier.verify(
                self.artifact,
                target_id="catalog-service",
                version="2.2.0",
                attestation=self.attestation,
            )
        )

    def test_rejects_tampered_signature_and_digest(self) -> None:
        invalid_signature = replace(self.attestation, signature="0" * 64)
        self.assertFalse(
            self.verifier.verify(
                self.artifact,
                target_id="catalog-service",
                version="2.1.0",
                attestation=invalid_signature,
            )
        )
        invalid_artifact = replace(self.artifact, sha256="0" * 64)
        self.assertFalse(
            self.verifier.verify(
                invalid_artifact,
                target_id="catalog-service",
                version="2.1.0",
                attestation=self.attestation,
            )
        )

    def test_rejects_future_dated_attestation(self) -> None:
        future = sign_artifact_attestation(
            SECRET,
            self.artifact,
            target_id="catalog-service",
            version="2.1.0",
            builder_id="trusted-ci",
            build_id="future-build",
            source_revision="b" * 40,
            issued_at=2_000,
        )
        self.assertFalse(
            self.verifier.verify(
                self.artifact,
                target_id="catalog-service",
                version="2.1.0",
                attestation=future,
            )
        )

    def test_missing_verifier_fails_closed(self) -> None:
        class Adapter:
            def deploy(self, request):
                raise AssertionError("provider must not be called")

            def inspect(self, target_id):
                return None

        with tempfile.TemporaryDirectory() as directory:
            service = ReleaseExecutionService(
                SQLiteReleaseCoordinator(f"{directory}/releases.sqlite3"),
                Adapter(),
            )
            with self.assertRaises(ArtifactProvenanceError):
                service.verify_provenance(
                    self.artifact,
                    target_id="catalog-service",
                    version="2.1.0",
                    attestation=self.attestation,
                )


if __name__ == "__main__":
    unittest.main()
