from __future__ import annotations

import json
import math
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Mapping, Protocol

from .models import SideEffect, ToolManifest


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
