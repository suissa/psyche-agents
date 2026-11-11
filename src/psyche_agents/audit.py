from __future__ import annotations

from threading import RLock
from typing import Protocol

from .models import AuditEvent


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
