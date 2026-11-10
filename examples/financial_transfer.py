"""Illustrative dry-run wiring; this example does not connect to a bank or move money."""

from decimal import Decimal

from psyche_agents import (
    PsycheRuntime,
    SecurityPolicy,
    SideEffect,
    ToolManifest,
    ToolRegistry,
)
from psyche_agents.registry import ToolBinding


class TransferReviewTool:
    def execute(self, intent):
        return {
            "status": "review_only",
            "amount": str(Decimal(str(intent.payload["amount"]))),
            "currency": intent.payload["currency"],
            "destination": intent.payload["destination"],
        }


registry = ToolRegistry()
registry.register(
    ToolBinding(
        ToolManifest(
            name="transfer-review",
            action="transfer",
            version="1.0.0",
            archetype="hero",
            side_effects=SideEffect.FINANCIAL,
            requires_approval=True,
            description="Dry-run transfer review; no payment is initiated.",
        ),
        TransferReviewTool(),
    )
)

runtime = PsycheRuntime(
    registry,
    SecurityPolicy(
        allowed_actions=frozenset({"transfer"}),
        max_transaction_amount=Decimal("250"),
    ),
)

result = runtime.handle(
    '{"action":"transfer","payload":{"amount":"25.00","currency":"BRL","destination":"demo-account"}}',
    actor_id="requester-1",
)
print(result.decision.status.value, result.decision.code)
print("Expected first response: requires_approval; the tool is not executed.")
