from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from psyche_agents.audit import AuditIntegrityError, SQLiteAuditLog
from psyche_agents.models import AuditEvent
from psyche_agents.release import (
    IdempotencyConflict,
    LeaseBusy,
    LeaseLost,
    SQLiteReleaseCoordinator,
    StaleGeneration,
)


class FakeClock:
    def __init__(self, value: float = 1000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class SQLiteAuditLogTests(unittest.TestCase):
    def test_persists_events_and_verifies_hash_chain_after_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            log = SQLiteAuditLog(path)
            log.record(AuditEvent("proposal_created", "proposal-1", "creator", 1.0, {"sha": "a"}))
            log.record(AuditEvent("approved", "proposal-1", "reviewer", 2.0, {"approved": True}))

            reopened = SQLiteAuditLog(path)
            self.assertEqual([event.event_type for event in reopened.snapshot()], [
                "proposal_created", "approved"
            ])
            self.assertTrue(reopened.verify_chain())
            sequence, head = reopened.checkpoint()
            self.assertEqual(sequence, 2)
            self.assertEqual(len(head), 64)

    def test_detects_modified_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            log = SQLiteAuditLog(path)
            log.record(AuditEvent("proposal_created", "proposal-1", "creator", 1.0, {"state": "proposed"}))
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "UPDATE audit_events SET payload_json=? WHERE sequence=1",
                    ('{"actor_id":"attacker"}',),
                )
            self.assertFalse(log.verify_chain())
            with self.assertRaises(AuditIntegrityError):
                log.snapshot()

    def test_concurrent_appends_keep_a_valid_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            log = SQLiteAuditLog(path)
            errors: list[Exception] = []

            def append(index: int) -> None:
                try:
                    log.record(AuditEvent("transition", f"proposal-{index}", "actor", float(index), {}))
                except Exception as error:  # pragma: no cover - assertion reports worker error.
                    errors.append(error)

            workers = [threading.Thread(target=append, args=(index,)) for index in range(12)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()

            self.assertEqual(errors, [])
            self.assertEqual(len(log.snapshot()), 12)
            self.assertTrue(log.verify_chain())


class SQLiteReleaseCoordinatorTests(unittest.TestCase):
    def test_lease_fencing_cas_and_idempotent_commit_survive_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releases.sqlite3"
            clock = FakeClock()
            coordinator = SQLiteReleaseCoordinator(path, clock=clock)
            lease = coordinator.acquire("production", "controller-a", ttl_seconds=30)
            self.assertEqual(lease.fencing_token, 1)
            with self.assertRaises(LeaseBusy):
                coordinator.acquire("production", "controller-b", ttl_seconds=30)

            digest = hashlib.sha256(b"trusted artifact").hexdigest()
            result = coordinator.commit(
                lease,
                expected_generation=0,
                version="1.2.0",
                artifact_sha256=digest,
                idempotency_key="release-001",
            )
            self.assertEqual(result.generation, 1)
            self.assertEqual(
                coordinator.commit(
                    lease,
                    expected_generation=0,
                    version="1.2.0",
                    artifact_sha256=digest,
                    idempotency_key="release-001",
                ),
                result,
            )

            reopened = SQLiteReleaseCoordinator(path, clock=clock)
            self.assertEqual(reopened.get("production"), result)
            self.assertTrue(reopened.verify_event_chain())
            self.assertEqual(reopened.event_checkpoint()[0], 2)

    def test_rejects_idempotency_key_reuse_with_different_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            coordinator = SQLiteReleaseCoordinator(Path(directory) / "releases.sqlite3")
            lease = coordinator.acquire("staging", "controller-a", ttl_seconds=30)
            coordinator.commit(
                lease,
                expected_generation=0,
                version="1.0.0",
                artifact_sha256=hashlib.sha256(b"one").hexdigest(),
                idempotency_key="same-key",
            )
            with self.assertRaises(IdempotencyConflict):
                coordinator.commit(
                    lease,
                    expected_generation=0,
                    version="1.0.1",
                    artifact_sha256=hashlib.sha256(b"two").hexdigest(),
                    idempotency_key="same-key",
                )

    def test_expired_owner_cannot_commit_after_successor_gets_new_fence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock()
            coordinator = SQLiteReleaseCoordinator(
                Path(directory) / "releases.sqlite3", clock=clock
            )
            old_lease = coordinator.acquire("production", "old-node", ttl_seconds=5)
            clock.advance(6)
            new_lease = coordinator.acquire("production", "new-node", ttl_seconds=30)
            self.assertEqual(new_lease.fencing_token, old_lease.fencing_token + 1)

            with self.assertRaises(LeaseLost):
                coordinator.commit(
                    old_lease,
                    expected_generation=0,
                    version="1.0.0",
                    artifact_sha256=hashlib.sha256(b"old").hexdigest(),
                    idempotency_key="old-release",
                )

            with self.assertRaises(LeaseLost):
                coordinator.renew(old_lease, ttl_seconds=30)

            result = coordinator.commit(
                new_lease,
                expected_generation=0,
                version="2.0.0",
                artifact_sha256=hashlib.sha256(b"new").hexdigest(),
                idempotency_key="new-release",
            )
            self.assertEqual(result.fencing_token, new_lease.fencing_token)
            self.assertEqual(result.generation, 1)
            self.assertTrue(coordinator.verify_event_chain())

    def test_generation_cas_rejects_stale_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            coordinator = SQLiteReleaseCoordinator(Path(directory) / "releases.sqlite3")
            lease = coordinator.acquire("production", "controller-a", ttl_seconds=30)
            coordinator.commit(
                lease,
                expected_generation=0,
                version="1.0.0",
                artifact_sha256=hashlib.sha256(b"first").hexdigest(),
                idempotency_key="one",
            )
            with self.assertRaises(StaleGeneration):
                coordinator.commit(
                    lease,
                    expected_generation=0,
                    version="1.0.1",
                    artifact_sha256=hashlib.sha256(b"second").hexdigest(),
                    idempotency_key="two",
                )

    def test_release_and_expired_lease_cannot_be_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock()
            coordinator = SQLiteReleaseCoordinator(
                Path(directory) / "releases.sqlite3", clock=clock
            )
            lease = coordinator.acquire("production", "controller-a", ttl_seconds=5)
            renewed = coordinator.renew(lease, ttl_seconds=10)
            self.assertGreater(renewed.expires_at, lease.expires_at)
            coordinator.release(renewed)
            with self.assertRaises(LeaseLost):
                coordinator.release(renewed)


if __name__ == "__main__":
    unittest.main()
