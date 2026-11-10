from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


class SideEffect(str, Enum):
    READ_ONLY = "read_only"
    WRITE = "write"
    FINANCIAL = "financial"


@dataclass(frozen=True, slots=True)
class Intent:
    action: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    raw_input: str = ""
    actor_id: str = "anonymous"
    intent_id: str = field(default_factory=lambda: uuid4().hex)
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovalToken:
    intent_id: str
    approver_id: str
    expires_at: int
    nonce: str
    signature: str


@dataclass(frozen=True, slots=True)
class ToolManifest:
    name: str
    action: str
    version: str
    archetype: str = "sage"
    side_effects: SideEffect = SideEffect.READ_ONLY
    requires_approval: bool = False
    description: str = ""


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    status: DecisionStatus
    code: str
    reason: str

    @property
    def executable(self) -> bool:
        return self.status is DecisionStatus.ALLOW


@dataclass(frozen=True, slots=True)
class DispatchResult:
    intent_id: str
    decision: PolicyDecision
    output: Mapping[str, Any] | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    intent_id: str
    actor_id: str
    timestamp: float
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ValidationReport:
    passed: bool
    checks: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()
