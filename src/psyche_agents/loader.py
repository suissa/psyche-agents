from __future__ import annotations

from threading import RLock
from typing import Protocol

from .artifacts import ArtifactRecord, ArtifactStore
from .models import ToolManifest
from .registry import ToolBinding
from .persistence import PreparedArtifactCatalog


class ArtifactLoader(Protocol):
    """Resolves a validated artifact digest to a prepared, trusted runtime handler."""

    def stage(self, artifact: ArtifactRecord, binding: ToolBinding) -> None: ...

    def load(self, artifact_sha256: str) -> ToolBinding: ...


class TrustedBindingResolver(Protocol):
    """Resolves metadata to an already-prepared handler from trusted application code."""

    def resolve(self, manifest: ToolManifest) -> ToolBinding: ...


class PreparedArtifactLoader:
    """Digest-to-handler adapter with an optional durable metadata catalog.

    Only the digest and ToolManifest are persisted. Python handler instances are never
    serialized or imported from candidate bytes. After restart, restore_catalog() asks
    the trusted application resolver for each already-prepared handler and checks that
    its manifest exactly matches the persisted metadata.
    """

    def __init__(
        self,
        artifact_store: ArtifactStore,
        *,
        catalog: PreparedArtifactCatalog | None = None,
    ) -> None:
        self.artifact_store = artifact_store
        self.catalog = catalog
        self._bindings: dict[str, ToolBinding] = {}
        self._lock = RLock()

    def stage(self, artifact: ArtifactRecord, binding: ToolBinding) -> None:
        stored = self.artifact_store.get(artifact.sha256)
        if (
            not artifact.verify()
            or not stored.verify()
            or stored.content != artifact.content
            or stored.sha256 != artifact.sha256
        ):
            raise RuntimeError("cannot stage a handler for an unverified artifact")
        manifest = binding.manifest
        if not manifest.name or not manifest.action or not manifest.version:
            raise ValueError("prepared handler requires a complete manifest")
        if self.catalog is not None:
            self.catalog.put(artifact.sha256, manifest)
        with self._lock:
            current = self._bindings.get(artifact.sha256)
            if current is not None and current is not binding:
                raise RuntimeError("artifact digest is already bound to another handler")
            self._bindings[artifact.sha256] = binding

    def restore_catalog(self, resolver: TrustedBindingResolver) -> tuple[str, ...]:
        """Rehydrate only handlers returned by the trusted bootstrap resolver."""
        if self.catalog is None:
            raise RuntimeError("no persistent prepared-artifact catalog is configured")
        restored: list[str] = []
        for digest, expected_manifest in self.catalog.snapshot():
            artifact = self.artifact_store.get(digest)
            if not artifact.verify() or artifact.sha256 != digest:
                raise RuntimeError("catalog references a missing or invalid candidate artifact")
            binding = resolver.resolve(expected_manifest)
            if not isinstance(binding, ToolBinding) or binding.manifest != expected_manifest:
                raise RuntimeError("trusted resolver returned a handler with a different manifest")
            with self._lock:
                current = self._bindings.get(digest)
                if current is not None and current is not binding:
                    raise RuntimeError("restored digest conflicts with an already-loaded handler")
                self._bindings[digest] = binding
            restored.append(digest)
        return tuple(restored)

    def load(self, artifact_sha256: str) -> ToolBinding:
        artifact = self.artifact_store.get(artifact_sha256)
        if not artifact.verify() or artifact.sha256 != artifact_sha256:
            raise RuntimeError("artifact failed integrity verification during load")
        with self._lock:
            binding = self._bindings.get(artifact_sha256)
        if binding is None:
            raise KeyError(f"no trusted prepared handler for artifact: {artifact_sha256}")
        return binding
