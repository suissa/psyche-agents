from __future__ import annotations

import json
import time
from typing import Any, Mapping, Protocol

from .audit import AuditSink, InMemoryAuditLog
from .models import (
    ApprovalToken,
    AuditEvent,
    DecisionStatus,
    DispatchResult,
    Intent,
    PolicyDecision,
)
from .policy import ApprovalVerifier, SecurityPolicy, SuperegoAgent
from .registry import ToolRegistry
from .zig_guard import ZigGuard


class IntentExtractor(Protocol):
    def extract(
        self, raw_input: str, actor_id: str, idempotency_key: str | None
    ) -> Intent: ...


class JsonIntentExtractor:
    """Deterministic structured-input adapter; local-model adapters use the same protocol."""

    def extract(
        self, raw_input: str, actor_id: str, idempotency_key: str | None
    ) -> Intent:
        try:
            value = json.loads(raw_input)
        except json.JSONDecodeError as exc:
            raise ValueError("ID input must be a JSON object with action and payload") from exc
        if not isinstance(value, dict):
            raise ValueError("ID input must be a JSON object")
        action = value.get("action")
        payload = value.get("payload", {})
        if not isinstance(action, str) or not isinstance(payload, dict):
            raise ValueError("ID requires a string action and object payload")
        return Intent(
            action=action.strip().lower(),
            payload=payload,
            raw_input=raw_input,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
        )


class IdAgent:
    """Captures the user's stated goal without granting it execution authority."""

    def __init__(self, extractor: IntentExtractor | None = None) -> None:
        self.extractor = extractor or JsonIntentExtractor()

    def capture(
        self, raw_input: str, actor_id: str, idempotency_key: str | None = None
    ) -> Intent:
        return self.extractor.extract(raw_input, actor_id, idempotency_key)


class EgoAgent:
    """Mediates intent, deterministic policy, registered capabilities and execution."""

    def __init__(
        self,
        registry: ToolRegistry,
        superego: SuperegoAgent,
        audit: AuditSink | None = None,
    ) -> None:
        self.registry = registry
        self.superego = superego
        self.audit = audit or InMemoryAuditLog()

    def _record(self, event_type: str, intent: Intent, **details: Any) -> None:
        self.audit.record(
            AuditEvent(
                event_type=event_type,
                intent_id=intent.intent_id,
                actor_id=intent.actor_id,
                timestamp=time.time(),
                details=details,
            )
        )

    def dispatch(
        self, intent: Intent, approval: ApprovalToken | None = None
    ) -> DispatchResult:
        binding = self.registry.resolve(intent.action)
        if binding is None:
            decision = PolicyDecision(
                DecisionStatus.DENY,
                "tool_not_registered",
                "No registered capability matches the requested action.",
            )
            self._record("intent_denied", intent, code=decision.code)
            return DispatchResult(intent.intent_id, decision)

        decision = self.superego.evaluate(intent, binding.manifest, approval)
        if not decision.executable:
            self._record(
                "intent_blocked",
                intent,
                code=decision.code,
                status=decision.status.value,
                tool=binding.manifest.name,
            )
            return DispatchResult(intent.intent_id, decision)

        self._record(
            "execution_started",
            intent,
            tool=binding.manifest.name,
            version=binding.manifest.version,
        )
        try:
            output = binding.handler.execute(intent)
            if not isinstance(output, Mapping):
                raise TypeError("tool handler must return a mapping")
        except Exception as exc:
            self._record("execution_failed", intent, error_type=type(exc).__name__)
            failed = PolicyDecision(
                DecisionStatus.DENY,
                "tool_execution_failed",
                "The capability failed; no automatic replay was attempted.",
            )
            return DispatchResult(intent.intent_id, failed, error_code=type(exc).__name__)

        self._record("execution_completed", intent, tool=binding.manifest.name)
        return DispatchResult(intent.intent_id, decision, dict(output))


class PsycheRuntime:
    """Facade for raw input and already-structured intents.

    Use prepare() followed by dispatch() for an approval workflow so the exact same
    intent identifier is retained across the human approval round-trip.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        policy: SecurityPolicy,
        approval_verifier: ApprovalVerifier | None = None,
        audit: AuditSink | None = None,
        extractor: IntentExtractor | None = None,
        guard: ZigGuard | None = None,
    ) -> None:
        self.audit = audit or InMemoryAuditLog()
        self.id_agent = IdAgent(extractor)
        self.superego = SuperegoAgent(policy, approval_verifier, guard)
        self.ego = EgoAgent(registry, self.superego, self.audit)

    def prepare(
        self,
        raw_input: str,
        actor_id: str = "anonymous",
        idempotency_key: str | None = None,
    ) -> Intent:
        return self.id_agent.capture(raw_input, actor_id, idempotency_key)

    def handle(
        self,
        raw_input: str,
        actor_id: str = "anonymous",
        idempotency_key: str | None = None,
        approval: ApprovalToken | None = None,
    ) -> DispatchResult:
        intent = self.prepare(raw_input, actor_id, idempotency_key)
        return self.ego.dispatch(intent, approval)

    def dispatch(
        self, intent: Intent, approval: ApprovalToken | None = None
    ) -> DispatchResult:
        return self.ego.dispatch(intent, approval)
