from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
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
    """Thread-safe content-addressed store for development and tests."""

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
        record = ArtifactRecord(digest, len(content), media_type, content)
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


class SQLiteArtifactStore:
    """Durable, content-addressed artifact store backed by SQLite.

    SQLite uses WAL, FULL synchronous durability and a write transaction for inserts.
    The database file should live on a local durable filesystem, not an unreliable
    network filesystem. Backups and retention remain deployment responsibilities.
    """

    def __init__(self, database_path: str | Path, *, busy_timeout_ms: int = 5_000) -> None:
        self.database_path = Path(database_path)
        if str(database_path) == ":memory:":
            raise ValueError("SQLiteArtifactStore requires a durable database path")
        if busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be positive")
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.busy_timeout_ms = busy_timeout_ms
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    sha256 TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    content BLOB NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        self.database_path.chmod(0o600)


    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level="IMMEDIATE",
        )
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def put(
        self,
        content: bytes,
        media_type: str = "application/octet-stream",
    ) -> ArtifactRecord:
        if not isinstance(content, bytes) or not content:
            raise ValueError("candidate artifact must be non-empty immutable bytes")
        if not isinstance(media_type, str) or not media_type.strip():
            raise ValueError("artifact media type is required")
        digest = hashlib.sha256(content).hexdigest()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO artifacts (sha256, size_bytes, media_type, content)
                VALUES (?, ?, ?, ?)
                """,
                (digest, len(content), media_type, sqlite3.Binary(content)),
            )
            row = connection.execute(
                "SELECT size_bytes, media_type, content FROM artifacts WHERE sha256 = ?",
                (digest,),
            ).fetchone()
        if row is None:
            raise RuntimeError("artifact insert did not produce a durable record")
        record = ArtifactRecord(digest, int(row[0]), str(row[1]), bytes(row[2]))
        if record.content != content or not record.verify():
            raise RuntimeError("stored artifact integrity check failed")
        return record

    def get(self, sha256: str) -> ArtifactRecord:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT size_bytes, media_type, content FROM artifacts WHERE sha256 = ?",
                (sha256,),
            ).fetchone()
        if row is None:
            raise KeyError(sha256)
        record = ArtifactRecord(sha256, int(row[0]), str(row[1]), bytes(row[2]))
        if not record.verify():
            raise RuntimeError("stored artifact integrity check failed")
        return record

    def contains(self, sha256: str) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM artifacts WHERE sha256 = ?", (sha256,)
            ).fetchone()
        return row is not None

    def count(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()
        return int(row[0])
