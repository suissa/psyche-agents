from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from .audit import ZERO_HASH, _chain_hash, _canonical_json


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseCoordinatorError(RuntimeError):
    """Base error for release coordination failures."""


class LeaseBusy(ReleaseCoordinatorError):
    """Another owner currently holds an unexpired lease."""


class LeaseLost(ReleaseCoordinatorError):
    """The lease expired or was replaced by a higher fencing token."""


class StaleGeneration(ReleaseCoordinatorError):
    """The target generation changed since the caller read it."""


class IdempotencyConflict(ReleaseCoordinatorError):
    """An idempotency key was reused for a different release request."""


@dataclass(frozen=True, slots=True)
class ReleaseLease:
    target_id: str
    owner_id: str
    fencing_token: int
    expires_at: float


@dataclass(frozen=True, slots=True)
class ReleaseSnapshot:
    target_id: str
    generation: int
    version: str | None
    artifact_sha256: str | None
    fencing_token: int


class ReleaseCoordinator(Protocol):
    def acquire(
        self, target_id: str, owner_id: str, *, ttl_seconds: float
    ) -> ReleaseLease: ...

    def renew(self, lease: ReleaseLease, *, ttl_seconds: float) -> ReleaseLease: ...

    def release(self, lease: ReleaseLease) -> None: ...

    def commit(
        self,
        lease: ReleaseLease,
        *,
        expected_generation: int,
        version: str,
        artifact_sha256: str,
        idempotency_key: str,
    ) -> ReleaseSnapshot: ...

    def get(self, target_id: str) -> ReleaseSnapshot: ...


class SQLiteReleaseCoordinator:
    """Transactional single-host release coordinator.

    Multiple processes may coordinate through the same durable local SQLite database.
    SQLite on a local filesystem is not a multi-host coordination service; use a
    server-backed implementation of ReleaseCoordinator for multi-host deployments.
    Fencing tokens are monotonic per target and prevent an expired owner from committing
    after a successor has acquired the lease.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        clock: Callable[[], float] = time.time,
        timeout: float = 30.0,
    ) -> None:
        self.path = Path(path)
        if str(path) == ":memory:":
            raise ValueError("SQLiteReleaseCoordinator requires a durable filesystem path")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("SQLite timeout must be a finite positive number")
        self.clock = clock
        self.timeout = timeout
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS release_targets (
                    target_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    version TEXT,
                    artifact_sha256 TEXT,
                    fencing_token INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS release_fences (
                    target_id TEXT PRIMARY KEY,
                    token INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS release_leases (
                    target_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS release_operations (
                    target_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    PRIMARY KEY (target_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS release_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def _required(value: str, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required")
        return value

    @staticmethod
    def _validate_ttl(ttl_seconds: float) -> None:
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("lease TTL must be positive")

    @staticmethod
    def _snapshot_from_row(row: tuple[object, ...]) -> ReleaseSnapshot:
        return ReleaseSnapshot(
            target_id=str(row[0]),
            generation=int(row[1]),
            version=str(row[2]) if row[2] is not None else None,
            artifact_sha256=str(row[3]) if row[3] is not None else None,
            fencing_token=int(row[4]),
        )

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        event_type: str,
        target_id: str,
        owner_id: str,
        fencing_token: int,
        timestamp: float,
        details: dict[str, object],
    ) -> None:
        payload_json = _canonical_json(
            {
                "event_type": event_type,
                "target_id": target_id,
                "owner_id": owner_id,
                "fencing_token": fencing_token,
                "timestamp": timestamp,
                "details": details,
            }
        )
        row = connection.execute(
            "SELECT event_hash FROM release_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = row[0] if row else ZERO_HASH
        event_hash = _chain_hash(previous_hash, payload_json)
        connection.execute(
            """
            INSERT INTO release_events (payload_json, previous_hash, event_hash)
            VALUES (?, ?, ?)
            """,
            (payload_json, previous_hash, event_hash),
        )

    def acquire(
        self,
        target_id: str,
        owner_id: str,
        *,
        ttl_seconds: float,
    ) -> ReleaseLease:
        self._required(target_id, "target ID")
        self._required(owner_id, "owner ID")
        self._validate_ttl(ttl_seconds)
        now = float(self.clock())
        if not math.isfinite(now):
            raise ValueError("release coordinator clock must return a finite timestamp")
        expires_at = now + ttl_seconds
        if not math.isfinite(expires_at):
            raise ValueError("lease expiry must be a finite timestamp")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    "SELECT owner_id, fencing_token, expires_at FROM release_leases WHERE target_id=?",
                    (target_id,),
                ).fetchone()
                if current and float(current[2]) > now:
                    raise LeaseBusy(f"release target is leased by {current[0]}")

                fence = connection.execute(
                    "SELECT token FROM release_fences WHERE target_id=?",
                    (target_id,),
                ).fetchone()
                next_token = int(fence[0]) + 1 if fence else 1
                connection.execute(
                    """
                    INSERT INTO release_fences (target_id, token) VALUES (?, ?)
                    ON CONFLICT(target_id) DO UPDATE SET token=excluded.token
                    """,
                    (target_id, next_token),
                )
                connection.execute(
                    """
                    INSERT INTO release_leases (target_id, owner_id, fencing_token, expires_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(target_id) DO UPDATE SET
                        owner_id=excluded.owner_id,
                        fencing_token=excluded.fencing_token,
                        expires_at=excluded.expires_at
                    """,
                    (target_id, owner_id, next_token, expires_at),
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO release_targets
                        (target_id, generation, version, artifact_sha256, fencing_token)
                    VALUES (?, 0, NULL, NULL, 0)
                    """,
                    (target_id,),
                )
                self._append_event(
                    connection,
                    event_type="lease_acquired",
                    target_id=target_id,
                    owner_id=owner_id,
                    fencing_token=next_token,
                    timestamp=now,
                    details={"expires_at": expires_at},
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return ReleaseLease(target_id, owner_id, next_token, expires_at)

    def renew(self, lease: ReleaseLease, *, ttl_seconds: float) -> ReleaseLease:
        self._validate_ttl(ttl_seconds)
        now = float(self.clock())
        if not math.isfinite(now):
            raise ValueError("release coordinator clock must return a finite timestamp")
        expires_at = now + ttl_seconds
        if not math.isfinite(expires_at):
            raise ValueError("lease expiry must be a finite timestamp")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    UPDATE release_leases SET expires_at=?
                    WHERE target_id=? AND owner_id=? AND fencing_token=? AND expires_at>?
                    """,
                    (
                        expires_at,
                        lease.target_id,
                        lease.owner_id,
                        lease.fencing_token,
                        now,
                    ),
                )
                if cursor.rowcount != 1:
                    raise LeaseLost("cannot renew an expired or superseded release lease")
                self._append_event(
                    connection,
                    event_type="lease_renewed",
                    target_id=lease.target_id,
                    owner_id=lease.owner_id,
                    fencing_token=lease.fencing_token,
                    timestamp=now,
                    details={"expires_at": expires_at},
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return ReleaseLease(
            lease.target_id, lease.owner_id, lease.fencing_token, expires_at
        )

    def release(self, lease: ReleaseLease) -> None:
        now = float(self.clock())
        if not math.isfinite(now):
            raise ValueError("release coordinator clock must return a finite timestamp")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    DELETE FROM release_leases
                    WHERE target_id=? AND owner_id=? AND fencing_token=?
                    """,
                    (lease.target_id, lease.owner_id, lease.fencing_token),
                )
                if cursor.rowcount != 1:
                    raise LeaseLost("cannot release a superseded release lease")
                self._append_event(
                    connection,
                    event_type="lease_released",
                    target_id=lease.target_id,
                    owner_id=lease.owner_id,
                    fencing_token=lease.fencing_token,
                    timestamp=now,
                    details={},
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def commit(
        self,
        lease: ReleaseLease,
        *,
        expected_generation: int,
        version: str,
        artifact_sha256: str,
        idempotency_key: str,
    ) -> ReleaseSnapshot:
        self._required(version, "release version")
        self._required(idempotency_key, "idempotency key")
        if expected_generation < 0:
            raise ValueError("expected generation cannot be negative")
        if not _SHA256.fullmatch(artifact_sha256):
            raise ValueError("artifact SHA-256 must be 64 lowercase hexadecimal characters")

        request_json = _canonical_json(
            {
                "target_id": lease.target_id,
                "owner_id": lease.owner_id,
                "expected_generation": expected_generation,
                "version": version,
                "artifact_sha256": artifact_sha256,
            }
        )
        request_digest = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        now = float(self.clock())
        if not math.isfinite(now):
            raise ValueError("release coordinator clock must return a finite timestamp")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                prior = connection.execute(
                    """
                    SELECT owner_id, request_digest, snapshot_json
                    FROM release_operations
                    WHERE target_id=? AND idempotency_key=?
                    """,
                    (lease.target_id, idempotency_key),
                ).fetchone()
                if prior:
                    if prior[0] != lease.owner_id or prior[1] != request_digest:
                        raise IdempotencyConflict(
                            "idempotency key already belongs to a different release request"
                        )
                    saved = json.loads(prior[2])
                    connection.commit()
                    return ReleaseSnapshot(**saved)

                active_lease = connection.execute(
                    """
                    SELECT owner_id, fencing_token, expires_at
                    FROM release_leases WHERE target_id=?
                    """,
                    (lease.target_id,),
                ).fetchone()
                if (
                    active_lease is None
                    or active_lease[0] != lease.owner_id
                    or int(active_lease[1]) != lease.fencing_token
                    or float(active_lease[2]) <= now
                ):
                    raise LeaseLost("release lease expired or was superseded")

                current_row = connection.execute(
                    """
                    SELECT target_id, generation, version, artifact_sha256, fencing_token
                    FROM release_targets WHERE target_id=?
                    """,
                    (lease.target_id,),
                ).fetchone()
                if current_row is None:
                    raise RuntimeError("release target was not initialized")
                current = self._snapshot_from_row(current_row)
                if current.fencing_token > lease.fencing_token:
                    raise LeaseLost("release fencing token is older than target state")
                if current.generation != expected_generation:
                    raise StaleGeneration(
                        f"expected generation {expected_generation}, found {current.generation}"
                    )

                result = ReleaseSnapshot(
                    target_id=lease.target_id,
                    generation=current.generation + 1,
                    version=version,
                    artifact_sha256=artifact_sha256,
                    fencing_token=lease.fencing_token,
                )
                snapshot_json = _canonical_json(
                    {
                        "target_id": result.target_id,
                        "generation": result.generation,
                        "version": result.version,
                        "artifact_sha256": result.artifact_sha256,
                        "fencing_token": result.fencing_token,
                    }
                )
                connection.execute(
                    """
                    UPDATE release_targets
                    SET generation=?, version=?, artifact_sha256=?, fencing_token=?
                    WHERE target_id=? AND generation=?
                    """,
                    (
                        result.generation,
                        result.version,
                        result.artifact_sha256,
                        result.fencing_token,
                        lease.target_id,
                        expected_generation,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO release_operations
                        (target_id, idempotency_key, owner_id, request_digest, snapshot_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        lease.target_id,
                        idempotency_key,
                        lease.owner_id,
                        request_digest,
                        snapshot_json,
                    ),
                )
                self._append_event(
                    connection,
                    event_type="release_committed",
                    target_id=lease.target_id,
                    owner_id=lease.owner_id,
                    fencing_token=lease.fencing_token,
                    timestamp=now,
                    details={
                        "generation": result.generation,
                        "version": version,
                        "artifact_sha256": artifact_sha256,
                        "idempotency_key": idempotency_key,
                    },
                )
                connection.commit()
                return result
            except Exception:
                connection.rollback()
                raise

    def get(self, target_id: str) -> ReleaseSnapshot:
        self._required(target_id, "target ID")
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT target_id, generation, version, artifact_sha256, fencing_token
                FROM release_targets WHERE target_id=?
                """,
                (target_id,),
            ).fetchone()
        if row is None:
            return ReleaseSnapshot(target_id, 0, None, None, 0)
        return self._snapshot_from_row(row)

    def verify_event_chain(self) -> bool:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT sequence, payload_json, previous_hash, event_hash
                FROM release_events ORDER BY sequence
                """
            ).fetchall()
        previous_hash = ZERO_HASH
        expected_sequence = 1
        for sequence, payload_json, stored_previous, stored_hash in rows:
            if sequence != expected_sequence or stored_previous != previous_hash:
                return False
            expected_hash = _chain_hash(previous_hash, payload_json)
            if expected_hash != stored_hash:
                return False
            previous_hash = stored_hash
            expected_sequence += 1
        return True

    def event_checkpoint(self) -> tuple[int, str]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT sequence, event_hash FROM release_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        return (int(row[0]), str(row[1])) if row else (0, ZERO_HASH)
