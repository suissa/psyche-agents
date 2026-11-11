from __future__ import annotations

import json
import math
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Mapping, Protocol

from .audit import (
    AuditIntegrityError,
    SQLiteAuditLog,
    ZERO_HASH,
    _canonical_json as _canonical_audit_json,
    _chain_hash,
    _event_from_json,
    _event_payload,
)
from .models import AuditEvent, SideEffect, ToolManifest


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProposalConflict(RuntimeError):
    """A proposal changed in another process since it was read."""


class EvolutionProposalStore(Protocol):
    def save(
        self,
        proposal_id: str,
        payload: Mapping[str, object],
        *,
        expected_revision: int | None,
    ) -> int: ...

    def load_all(self) -> tuple[tuple[str, dict[str, object], int], ...]: ...


def manifest_to_dict(manifest: ToolManifest) -> dict[str, object]:
    return {
        "name": manifest.name,
        "action": manifest.action,
        "version": manifest.version,
        "archetype": manifest.archetype,
        "side_effects": manifest.side_effects.value,
        "requires_approval": manifest.requires_approval,
        "description": manifest.description,
    }


def manifest_from_dict(value: Mapping[str, object]) -> ToolManifest:
    try:
        name = value["name"]
        action = value["action"]
        version = value["version"]
        archetype = value["archetype"]
        side_effects = value["side_effects"]
        requires_approval = value["requires_approval"]
        description = value["description"]
        if not all(isinstance(item, str) and item.strip() for item in (name, action, version, archetype)):
            raise ValueError("manifest identity fields must be non-empty strings")
        if not isinstance(requires_approval, bool) or not isinstance(description, str):
            raise ValueError("manifest flags or description have invalid types")
        return ToolManifest(
            name=name,
            action=action,
            version=version,
            archetype=archetype,
            side_effects=SideEffect(side_effects),
            requires_approval=requires_approval,
            description=description,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("stored tool manifest is invalid") from error


class SQLiteEvolutionProposalStore:
    """Durable proposal metadata with optimistic revision checks.

    Handler objects and artifact bytes are deliberately excluded. Artifact bytes belong
    in ArtifactStore; executable handlers must be rehydrated by trusted application code.
    SQLite supports multiple processes on one host and a durable local filesystem.
    """

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        timeout: float = 30.0,
    ) -> None:
        if str(database_path) == ":memory:":
            raise ValueError("SQLiteEvolutionProposalStore requires a durable filesystem path")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("SQLite timeout must be a finite positive number")
        self.database_path = Path(database_path)
        self.timeout = timeout
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evolution_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        self._secure_permissions()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _secure_permissions(self) -> None:
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _encode(proposal_id: str, payload: Mapping[str, object]) -> str:
        if not isinstance(proposal_id, str) or not proposal_id.strip():
            raise ValueError("proposal ID is required")
        value = dict(payload)
        if value.get("proposal_id") != proposal_id:
            raise ValueError("payload proposal ID must match its storage key")
        try:
            return json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError) as error:
            raise ValueError("proposal metadata must be finite JSON-compatible data") from error

    @staticmethod
    def _decode(proposal_id: str, payload_json: str) -> dict[str, object]:
        try:
            payload = json.loads(payload_json)
            if not isinstance(payload, dict) or payload.get("proposal_id") != proposal_id:
                raise ValueError("proposal storage key mismatch")
            return payload
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"persisted proposal is malformed: {proposal_id}") from error

    def save(
        self,
        proposal_id: str,
        payload: Mapping[str, object],
        *,
        expected_revision: int | None,
    ) -> int:
        encoded = self._encode(proposal_id, payload)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    "SELECT revision FROM evolution_proposals WHERE proposal_id=?",
                    (proposal_id,),
                ).fetchone()
                if expected_revision is None:
                    if current is not None:
                        raise ProposalConflict("proposal already exists")
                    revision = 1
                    connection.execute(
                        """
                        INSERT INTO evolution_proposals (proposal_id, revision, payload_json)
                        VALUES (?, ?, ?)
                        """,
                        (proposal_id, revision, encoded),
                    )
                else:
                    if current is None or int(current[0]) != expected_revision:
                        raise ProposalConflict("proposal revision changed; refusing stale update")
                    revision = expected_revision + 1
                    cursor = connection.execute(
                        """
                        UPDATE evolution_proposals
                        SET revision=?, payload_json=?, updated_at=CURRENT_TIMESTAMP
                        WHERE proposal_id=? AND revision=?
                        """,
                        (revision, encoded, proposal_id, expected_revision),
                    )
                    if cursor.rowcount != 1:
                        raise ProposalConflict("proposal revision changed during update")
                connection.commit()
                return revision
            except Exception:
                connection.rollback()
                raise

    def load_all(self) -> tuple[tuple[str, dict[str, object], int], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT proposal_id, payload_json, revision
                FROM evolution_proposals ORDER BY proposal_id
                """
            ).fetchall()
        return tuple(
            (str(row[0]), self._decode(str(row[0]), str(row[1])), int(row[2]))
            for row in rows
        )

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT COUNT(*) FROM evolution_proposals").fetchone()
        return int(row[0])




class SQLiteEvolutionJournal:
    """One SQLite transaction boundary for proposal revisions and audit events.

    Pass the same instance as both EvolutionaryEngine(proposal_store=..., audit=...).
    A proposal CAS write and its hash-chained audit event then commit or roll back
    together. Artifact storage and the process-local ToolRegistry remain separate.
    """

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        timeout: float = 30.0,
    ) -> None:
        if str(database_path) == ":memory:":
            raise ValueError("SQLiteEvolutionJournal requires a durable filesystem path")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("SQLite timeout must be a finite positive number")
        self.database_path = Path(database_path)
        self.timeout = timeout
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evolution_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def _save_on_connection(
        connection: sqlite3.Connection,
        proposal_id: str,
        encoded: str,
        expected_revision: int | None,
    ) -> int:
        current = connection.execute(
            "SELECT revision FROM evolution_proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if expected_revision is None:
            if current is not None:
                raise ProposalConflict("proposal already exists")
            revision = 1
            connection.execute(
                """
                INSERT INTO evolution_proposals (proposal_id, revision, payload_json)
                VALUES (?, ?, ?)
                """,
                (proposal_id, revision, encoded),
            )
            return revision

        if current is None or int(current[0]) != expected_revision:
            raise ProposalConflict("proposal revision changed; refusing stale update")
        revision = expected_revision + 1
        cursor = connection.execute(
            """
            UPDATE evolution_proposals
            SET revision=?, payload_json=?, updated_at=CURRENT_TIMESTAMP
            WHERE proposal_id=? AND revision=?
            """,
            (revision, encoded, proposal_id, expected_revision),
        )
        if cursor.rowcount != 1:
            raise ProposalConflict("proposal revision changed during update")
        return revision

    @staticmethod
    def _append_audit_payload(
        connection: sqlite3.Connection,
        payload_json: str,
    ) -> None:
        row = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(row[0]) if row else ZERO_HASH
        event_hash = _chain_hash(previous_hash, payload_json)
        connection.execute(
            """
            INSERT INTO audit_events (payload_json, previous_hash, event_hash)
            VALUES (?, ?, ?)
            """,
            (payload_json, previous_hash, event_hash),
        )

    def save(
        self,
        proposal_id: str,
        payload: Mapping[str, object],
        *,
        expected_revision: int | None,
    ) -> int:
        encoded = SQLiteEvolutionProposalStore._encode(proposal_id, payload)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                revision = self._save_on_connection(
                    connection, proposal_id, encoded, expected_revision
                )
                connection.commit()
                return revision
            except Exception:
                connection.rollback()
                raise

    def save_with_event(
        self,
        proposal_id: str,
        payload: Mapping[str, object],
        *,
        expected_revision: int | None,
        event: AuditEvent,
    ) -> int:
        """CAS-save proposal metadata and append its audit event atomically."""
        if not isinstance(event, AuditEvent):
            raise TypeError("atomic journal events must be AuditEvent instances")
        if event.intent_id != proposal_id:
            raise ValueError("audit event subject must match the proposal ID")
        encoded = SQLiteEvolutionProposalStore._encode(proposal_id, payload)
        event_json = _canonical_audit_json(_event_payload(event))
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                revision = self._save_on_connection(
                    connection, proposal_id, encoded, expected_revision
                )
                self._append_audit_payload(connection, event_json)
                connection.commit()
                return revision
            except Exception:
                connection.rollback()
                raise

    def load_all(self) -> tuple[tuple[str, dict[str, object], int], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT proposal_id, payload_json, revision
                FROM evolution_proposals ORDER BY proposal_id
                """
            ).fetchall()
        return tuple(
            (
                str(row[0]),
                SQLiteEvolutionProposalStore._decode(str(row[0]), str(row[1])),
                int(row[2]),
            )
            for row in rows
        )

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM evolution_proposals"
            ).fetchone()
        return int(row[0])

    def record(self, event: AuditEvent) -> None:
        event_json = _canonical_audit_json(_event_payload(event))
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._append_audit_payload(connection, event_json)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def snapshot(self) -> tuple[AuditEvent, ...]:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                """
                SELECT sequence, payload_json, previous_hash, event_hash
                FROM audit_events ORDER BY sequence
                """
            ).fetchall()
            if not SQLiteAuditLog._rows_form_valid_chain(rows):
                connection.rollback()
                raise AuditIntegrityError("audit hash chain verification failed")
            events = tuple(_event_from_json(str(row[1])) for row in rows)
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
        return SQLiteAuditLog._rows_form_valid_chain(rows)

    def checkpoint(self) -> tuple[int, str]:
        """Return the current sequence and chain head for external anchoring."""
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        return (int(row[0]), str(row[1])) if row else (0, ZERO_HASH)

class PreparedArtifactCatalog(Protocol):
    def put(self, artifact_sha256: str, manifest: ToolManifest) -> None: ...

    def snapshot(self) -> tuple[tuple[str, ToolManifest], ...]: ...


class SQLitePreparedArtifactCatalog:
    """Persists digest-to-manifest metadata, never executable handler objects."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        timeout: float = 30.0,
    ) -> None:
        if str(database_path) == ":memory:":
            raise ValueError("SQLitePreparedArtifactCatalog requires a durable filesystem path")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("SQLite timeout must be a finite positive number")
        self.database_path = Path(database_path)
        self.timeout = timeout
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS prepared_artifacts (
                    artifact_sha256 TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def put(self, artifact_sha256: str, manifest: ToolManifest) -> None:
        if not _SHA256.fullmatch(artifact_sha256):
            raise ValueError("prepared artifact key must be a SHA-256 digest")
        encoded = json.dumps(
            manifest_to_dict(manifest),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT manifest_json FROM prepared_artifacts WHERE artifact_sha256=?",
                    (artifact_sha256,),
                ).fetchone()
                if row is not None and str(row[0]) != encoded:
                    raise ProposalConflict("artifact digest is already assigned to another manifest")
                connection.execute(
                    """
                    INSERT OR IGNORE INTO prepared_artifacts (artifact_sha256, manifest_json)
                    VALUES (?, ?)
                    """,
                    (artifact_sha256, encoded),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def snapshot(self) -> tuple[tuple[str, ToolManifest], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT artifact_sha256, manifest_json FROM prepared_artifacts ORDER BY artifact_sha256"
            ).fetchall()
        result: list[tuple[str, ToolManifest]] = []
        for digest, encoded in rows:
            try:
                raw = json.loads(encoded)
                if not isinstance(raw, dict):
                    raise ValueError("manifest metadata must be an object")
                result.append((str(digest), manifest_from_dict(raw)))
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise RuntimeError(f"prepared artifact catalog entry is malformed: {digest}") from error
        return tuple(result)

    def count(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT COUNT(*) FROM prepared_artifacts").fetchone()
        return int(row[0])
