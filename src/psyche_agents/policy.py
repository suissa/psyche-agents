from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from threading import RLock
from typing import Protocol

from .models import (
    ApprovalToken,
    DecisionStatus,
    Intent,
    PolicyDecision,
    SideEffect,
    ToolManifest,
)
from .zig_guard import FLAG_CONTROL_BYTES, FLAG_PROMPT_INJECTION, ZigGuard


class ApprovalVerifier(Protocol):
    def verify(self, intent: Intent, token: ApprovalToken | None) -> bool: ...


def _approval_payload(token: ApprovalToken) -> bytes:
    canonical = [
        token.intent_id,
        token.approver_id,
        token.expires_at,
        token.nonce,
    ]
    return json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_approval_token(
    secret: bytes,
    intent_id: str,
    approver_id: str,
    expires_at: int,
    nonce: str | None = None,
) -> ApprovalToken:
    """Call only after a trusted approval service has authenticated the human approver."""
    if len(secret) < 32:
        raise ValueError("approval secret must contain at least 32 bytes")
    unsigned = ApprovalToken(
        intent_id=intent_id,
        approver_id=approver_id,
        expires_at=expires_at,
        nonce=nonce or secrets.token_urlsafe(18),
        signature="",
    )
    signature = hmac.new(secret, _approval_payload(unsigned), hashlib.sha256).hexdigest()
    return ApprovalToken(
        intent_id=unsigned.intent_id,
        approver_id=unsigned.approver_id,
        expires_at=unsigned.expires_at,
        nonce=unsigned.nonce,
        signature=signature,
    )


class HmacApprovalVerifier:
    """Verifies signed approvals and prevents nonce reuse within this process."""

    def __init__(self, secret: bytes, clock=time.time) -> None:
        if len(secret) < 32:
            raise ValueError("approval secret must contain at least 32 bytes")
        self._secret = secret
        self._clock = clock
        self._used_nonces: set[str] = set()
        self._lock = RLock()

    def verify(self, intent: Intent, token: ApprovalToken | None) -> bool:
        if token is None or token.intent_id != intent.intent_id or not token.nonce:
            return False
        if not token.approver_id or token.approver_id == intent.actor_id:
            return False
        if token.expires_at <= int(self._clock()):
            return False
        expected = hmac.new(
            self._secret, _approval_payload(token), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, token.signature):
            return False
        with self._lock:
            if token.nonce in self._used_nonces:
                return False
            self._used_nonces.add(token.nonce)
        return True


@dataclass(frozen=True, slots=True)
class SecurityPolicy:
    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    approval_required_actions: frozenset[str] = field(default_factory=frozenset)
    financial_actions: frozenset[str] = field(default_factory=lambda: frozenset({"transfer"}))
    max_transaction_amount: Decimal = Decimal("1000")
    max_input_bytes: int = 16_384


class SuperegoAgent:
    """Deterministic policy gate. A model may advise it but cannot override its result."""

    def __init__(
        self,
        policy: SecurityPolicy,
        approval_verifier: ApprovalVerifier | None = None,
        guard: ZigGuard | None = None,
    ) -> None:
        self.policy = policy
        self.approval_verifier = approval_verifier
        self.guard = guard or ZigGuard()

    @staticmethod
    def _deny(code: str, reason: str) -> PolicyDecision:
        return PolicyDecision(DecisionStatus.DENY, code, reason)

    @staticmethod
    def _canonical_payload(intent: Intent) -> str:
        def encode_extra(value: object) -> str:
            if isinstance(value, Decimal):
                return str(value)
            raise TypeError(f"unsupported payload value: {type(value).__name__}")

        return json.dumps(
            {"action": intent.action, "payload": dict(intent.payload)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=encode_extra,
        )

    def evaluate(
        self,
        intent: Intent,
        manifest: ToolManifest,
        approval: ApprovalToken | None = None,
    ) -> PolicyDecision:
        if not isinstance(intent.action, str) or not re.fullmatch(
            r"[a-z][a-z0-9_.-]{0,63}", intent.action
        ):
            return self._deny("invalid_action", "Action identifier is malformed.")
        if intent.action != manifest.action:
            return self._deny(
                "manifest_action_mismatch",
                "Tool manifest does not match the requested action.",
            )
        if not isinstance(intent.payload, dict) and not hasattr(intent.payload, "items"):
            return self._deny("invalid_payload", "Intent payload must be an object.")
        if not isinstance(intent.raw_input, str):
            return self._deny("invalid_input", "Raw input must be text.")

        try:
            canonical = self._canonical_payload(intent)
        except (TypeError, ValueError):
            return self._deny("invalid_payload", "Payload contains unsupported values.")
        scan_target = intent.raw_input + "\n" + canonical
        if len(scan_target.encode("utf-8", errors="replace")) > self.policy.max_input_bytes:
            return self._deny("input_too_large", "Input exceeds the configured byte limit.")

        flags = self.guard.scan(scan_target)
        if flags & FLAG_PROMPT_INJECTION:
            return self._deny(
                "prompt_injection_signal",
                "Input or structured payload matched a blocked instruction-override pattern.",
            )
        if flags & FLAG_CONTROL_BYTES:
            return self._deny("control_bytes", "Input contains disallowed control bytes.")

        if intent.action not in self.policy.allowed_actions:
            return self._deny("action_not_allowlisted", "Action is not explicitly allowlisted.")

        is_financial_action = intent.action in self.policy.financial_actions
        if is_financial_action != (manifest.side_effects is SideEffect.FINANCIAL):
            return self._deny(
                "financial_manifest_mismatch",
                "Financial action classification must match the tool manifest.",
            )

        if is_financial_action:
            try:
                amount = Decimal(str(intent.payload.get("amount", "")))
            except (InvalidOperation, ValueError):
                return self._deny("invalid_amount", "A valid decimal transaction amount is required.")
            if not amount.is_finite() or amount <= 0:
                return self._deny(
                    "invalid_amount",
                    "Transaction amount must be finite and greater than zero.",
                )
            if amount > self.policy.max_transaction_amount:
                return self._deny(
                    "amount_limit_exceeded",
                    "Transaction amount exceeds the configured limit.",
                )
            currency = str(intent.payload.get("currency", "")).upper()
            destination = str(intent.payload.get("destination", "")).strip()
            if (
                not re.fullmatch(r"[A-Z]{3}", currency)
                or not destination
                or len(destination) > 256
            ):
                return self._deny(
                    "invalid_transfer_fields",
                    "Transfer requires a three-letter currency and a bounded destination.",
                )

        approval_required = (
            manifest.requires_approval
            or is_financial_action
            or intent.action in self.policy.approval_required_actions
        )
        if approval_required:
            if self.approval_verifier is None or not self.approval_verifier.verify(intent, approval):
                return PolicyDecision(
                    DecisionStatus.REQUIRES_APPROVAL,
                    "human_approval_required",
                    "A valid, unused approval from a different authenticated actor is required.",
                )

        return PolicyDecision(
            DecisionStatus.ALLOW,
            "policy_allow",
            "All deterministic policy checks passed.",
        )
