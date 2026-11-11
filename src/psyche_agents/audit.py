from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from threading import RLock
from typing import Mapping, Protocol

from .models import AuditEvent


ZERO_HASH = "0" * 64


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...


class InMemoryAuditLog:
    """Thread-safe audit sink for tests and single-process deployments."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = RLock()

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class AuditIntegrityError(RuntimeError):
    """Raised when an audit record cannot be decoded or verified."""


def _canonical_json(value: Mapping[str, object]) -> str:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("audit data must contain finite JSON-compatible values") from error


def _event_payload(event: AuditEvent) -> dict[str, object]:
    if not event.event_type.strip() or not event.intent_id.strip() or not event.actor_id.strip():
        raise ValueError("audit event type, subject ID and actor ID are required")
    if not math.isfinite(event.timestamp):
        raise ValueError("audit event timestamp must be finite")
    return {
        "event_type": event.event_type,
        "intent_id": event.intent_id,
        "actor_id": event.actor_id,
        "timestamp": event.timestamp,
        "details": dict(event.details),
    }


def _chain_hash(previous_hash: str, payload_json: str) -> str:
    return hashlib.sha256(
        previous_hash.encode("ascii") + b"\n" + payload_json.encode("utf-8")
    ).hexdigest()


def _event_from_json(payload_json: str) -> AuditEvent:
    try:
        payload = json.loads(payload_json)
        if not isinstance(payload, dict):
            raise TypeError("event payload must be an object")
        event_type = payload["event_type"]
        intent_id = payload["intent_id"]
        actor_id = payload["actor_id"]
        timestamp = float(payload["timestamp"])
        details = payload["details"]
        if (
            not isinstance(event_type, str)
            or not event_type.strip()
            or not isinstance(intent_id, str)
            or not intent_id.strip()
            or not isinstance(actor_id, str)
            or not actor_id.strip()
            or not math.isfinite(timestamp)
            or not isinstance(details, dict)
        ):
            raise ValueError("event fields have invalid types or values")
        return AuditEvent(
            event_type=event_type,
            intent_id=intent_id,
            actor_id=actor_id,
            timestamp=timestamp,
            details=details,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise AuditIntegrityError("stored audit event is malformed") from error


class SQLiteAuditLog:
    """Durable append-only audit sink with a SHA-256 hash chain.

    Keep checkpoints outside this database when deletion or full-database rewriting
    must be detectable. The local hash chain detects altered, reordered or partially
    removed rows, but a database administrator able to rewrite every row can also
    recompute the chain unless its head is externally anchored.
    """

    def __init__(self, path: str | os.PathLike[str], *, timeout: float = 30.0) -> None:
        self.path = Path(path)
        if str(path) == ":memory:":
            raise ValueError("SQLiteAuditLog requires a durable filesystem path")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("SQLite timeout must be a finite positive number")
        self.timeout = timeout
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )
        self._secure_file_permissions()

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

    def _secure_file_permissions(self) -> None:
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            # Some filesystems do not support POSIX permission bits.
            pass

    def record(self, event: AuditEvent) -> None:
        payload_json = _canonical_json(_event_payload(event))
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous_hash = row[0] if row else ZERO_HASH
                event_hash = _chain_hash(previous_hash, payload_json)
                connection.execute(
                    """
                    INSERT INTO audit_events (payload_json, previous_hash, event_hash)
                    VALUES (?, ?, ?)
                    """,
                    (payload_json, previous_hash, event_hash),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    @staticmethod
    def _rows_form_valid_chain(rows: list[tuple[object, ...]]) -> bool:
        previous_hash = ZERO_HASH
        expected_sequence = 1
        for sequence, payload_json, stored_previous, stored_hash in rows:
            if sequence != expected_sequence or stored_previous != previous_hash:
                return False
            try:
                expected_hash = _chain_hash(previous_hash, payload_json)
                if not isinstance(stored_hash, str):
                    return False
            except (UnicodeEncodeError, AttributeError, TypeError):
                return False
            if not hmac.compare_digest(expected_hash, stored_hash):
                return False
            previous_hash = stored_hash
            expected_sequence += 1
        return True

    def snapshot(self) -> tuple[AuditEvent, ...]:
        # Verify the events in the same read snapshot used to deserialize them.
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                """
                SELECT sequence, payload_json, previous_hash, event_hash
                FROM audit_events ORDER BY sequence
                """
            ).fetchall()
            if not self._rows_form_valid_chain(rows):
                raise AuditIntegrityError("audit hash chain verification failed")
            events = tuple(_event_from_json(row[1]) for row in rows)
            connection.commit()
            return events

    def verify_chain(self) -> bool:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT sequence, payload_json, previous_hash, event_hash
                FROM audit_events ORDER BY sequence
                """
            ).fetchall()
        return self._rows_form_valid_chain(rows)

    def checkpoint(self) -> tuple[int, str]:
        """Return the current sequence and chain head for external anchoring."""
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        return (int(row[0]), str(row[1])) if row else (0, ZERO_HASH)
