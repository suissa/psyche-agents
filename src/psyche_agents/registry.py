from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Mapping, Protocol

from .models import Intent, ToolManifest


class ToolHandler(Protocol):
    def execute(self, intent: Intent) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ToolBinding:
    manifest: ToolManifest
    handler: ToolHandler


class ToolRegistry:
    """Versioned registry with compare-and-swap replacement semantics."""

    def __init__(self) -> None:
        self._bindings: dict[str, ToolBinding] = {}
        self._generation = 0
        self._lock = RLock()

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def register(self, binding: ToolBinding) -> int:
        if not binding.manifest.action or not binding.manifest.version:
            raise ValueError("tool action and version are required")
        with self._lock:
            if binding.manifest.action in self._bindings:
                raise ValueError(f"action already registered: {binding.manifest.action}")
            self._bindings[binding.manifest.action] = binding
            self._generation += 1
            return self._generation

    def resolve(self, action: str) -> ToolBinding | None:
        with self._lock:
            return self._bindings.get(action)

    def snapshot(self) -> tuple[int, tuple[ToolBinding, ...]]:
        with self._lock:
            return self._generation, tuple(self._bindings.values())

    def replace(self, binding: ToolBinding, expected_generation: int) -> int:
        action = binding.manifest.action
        with self._lock:
            if self._generation != expected_generation:
                raise RuntimeError("registry generation changed; refusing stale hot-swap")
            current = self._bindings.get(action)
            if current is None:
                raise KeyError(f"cannot replace unregistered action: {action}")
            if current.manifest.name != binding.manifest.name:
                raise ValueError("replacement must preserve the tool identity")
            if current.manifest.version == binding.manifest.version:
                raise ValueError("replacement must use a new immutable version")
            self._bindings[action] = binding
            self._generation += 1
            return self._generation
