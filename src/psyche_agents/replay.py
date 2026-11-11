from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from threading import RLock
from typing import Protocol


class NonceStore(Protocol):
    def consume(self, nonce: str, expires_at: int, now: int) -> bool: ...


class InMemoryNonceStore:
    def __init__(self) -> None:
        self._nonces: set[str] = set()
        self._lock = RLock()

    def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        if not nonce or expires_at <= now:
            return False
        with self._lock:
            if nonce in self._nonces:
                return False
            self._nonces.add(nonce)
            return True


class SQLiteNonceStore:
    """Durable one-time nonce store with atomic consume semantics.

    Multiple processes can share the same local SQLite database. Use a transactional
    shared database adapter for multi-host deployments; do not place this file on an
    unreliable network filesystem.
    """

    def __init__(self, database_path: str | Path, *, busy_timeout_ms: int = 5_000) -> None:
        self.database_path = Path(database_path)
        if str(database_path) == ":memory:":
            raise ValueError("SQLiteNonceStore requires a durable database path")
        if busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be positive")
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.busy_timeout_ms = busy_timeout_ms
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_nonces (
                    nonce TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER NOT NULL
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

    def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        if not nonce or expires_at <= now:
            return False
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM consumed_nonces WHERE expires_at <= ?", (now,)
            )
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO consumed_nonces (nonce, expires_at, consumed_at)
                VALUES (?, ?, ?)
                """,
                (nonce, expires_at, now),
            )
            return cursor.rowcount == 1

    def count(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()
        return int(row[0])
