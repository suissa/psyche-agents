from __future__ import annotations

from threading import RLock
from typing import Protocol

from .artifacts import ArtifactRecord, ArtifactStore
from .registry import ToolBinding


class ArtifactLoader(Protocol):
    """Resolves a validated artifact digest to a prepared, trusted runtime handler."""

    def stage(self, artifact: ArtifactRecord, binding: ToolBinding) -> None: ...

    def load(self, artifact_sha256: str) -> ToolBinding: ...


class PreparedArtifactLoader:
    """In-memory catalog for handlers prepared by a trusted build/release adapter.

    This class never imports, evaluates or executes artifact bytes. It only associates
    a digest with a handler that has already been loaded by trusted application code.
    A production artifact builder must verify its build provenance before calling stage.
    """

    def __init__(self, artifact_store: ArtifactStore) -> None:
        self.artifact_store = artifact_store
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
        with self._lock:
            current = self._bindings.get(artifact.sha256)
            if current is not None and current is not binding:
                raise RuntimeError("artifact digest is already bound to another handler")
            self._bindings[artifact.sha256] = binding

    def load(self, artifact_sha256: str) -> ToolBinding:
        artifact = self.artifact_store.get(artifact_sha256)
        if not artifact.verify() or artifact.sha256 != artifact_sha256:
            raise RuntimeError("artifact failed integrity verification during load")
        with self._lock:
            binding = self._bindings.get(artifact_sha256)
        if binding is None:
            raise KeyError(f"no trusted prepared handler for artifact: {artifact_sha256}")
        return binding
