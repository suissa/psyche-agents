from __future__ import annotations

import hashlib
from dataclasses import dataclass
from threading import RLock
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """Content-addressed immutable candidate artifact."""

    sha256: str
    size_bytes: int
    media_type: str
    content: bytes

    def verify(self) -> bool:
        return (
            self.size_bytes == len(self.content)
            and hashlib.sha256(self.content).hexdigest() == self.sha256
        )


class ArtifactStore(Protocol):
    def put(self, content: bytes, media_type: str = "application/octet-stream") -> ArtifactRecord: ...

    def get(self, sha256: str) -> ArtifactRecord: ...


class InMemoryArtifactStore:
    """Thread-safe content-addressed store for development and tests.

    Production deployments should implement ArtifactStore using durable immutable
    object storage with retention, access control and independent integrity checks.
    """

    def __init__(self) -> None:
        self._records: dict[str, ArtifactRecord] = {}
        self._lock = RLock()

    def put(
        self,
        content: bytes,
        media_type: str = "application/octet-stream",
    ) -> ArtifactRecord:
        if not isinstance(content, bytes) or not content:
            raise ValueError("candidate artifact must be non-empty immutable bytes")
        if not media_type.strip():
            raise ValueError("artifact media type is required")
        digest = hashlib.sha256(content).hexdigest()
        record = ArtifactRecord(
            sha256=digest,
            size_bytes=len(content),
            media_type=media_type,
            content=content,
        )
        with self._lock:
            existing = self._records.get(digest)
            if existing is not None and existing.content != content:
                raise RuntimeError("content-address collision detected")
            self._records.setdefault(digest, record)
            return self._records[digest]

    def get(self, sha256: str) -> ArtifactRecord:
        with self._lock:
            record = self._records[sha256]
        if not record.verify():
            raise RuntimeError("stored artifact integrity check failed")
        return record

    def contains(self, sha256: str) -> bool:
        with self._lock:
            return sha256 in self._records

    def snapshot(self) -> tuple[ArtifactRecord, ...]:
        with self._lock:
            return tuple(self._records.values())
