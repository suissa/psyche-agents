from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Sequence, TypeVar


class Archetype(str, Enum):
    SAGE = "sage"
    MAGICIAN = "magician"
    HERO = "hero"
    SHADOW = "shadow"


@dataclass(frozen=True, slots=True)
class ArchetypeProfile:
    archetype: Archetype
    responsibility: str
    permitted_side_effects: tuple[str, ...]
    execution_authority: str


ARCHETYPE_CATALOG = {
    Archetype.SAGE: ArchetypeProfile(
        Archetype.SAGE,
        "Ground claims in evidence, verify provenance and report uncertainty.",
        ("read_only",),
        "May advise; cannot grant policy approval.",
    ),
    Archetype.MAGICIAN: ArchetypeProfile(
        Archetype.MAGICIAN,
        "Prepare candidate capabilities and transformations for validation.",
        (),
        "May propose; cannot activate code or tools.",
    ),
    Archetype.HERO: ArchetypeProfile(
        Archetype.HERO,
        "Coordinate bounded, observable progress toward an approved goal.",
        ("read_only", "idempotent_write"),
        "Retries only explicitly idempotent operations within a fixed budget.",
    ),
    Archetype.SHADOW: ArchetypeProfile(
        Archetype.SHADOW,
        "Probe the system with adversarial and malformed inputs in isolation.",
        (),
        "May test policy gates; never invokes production tools.",
    ),
}


@dataclass(frozen=True, slots=True)
class Evidence:
    claim: str
    source: str
    verified: bool


@dataclass(frozen=True, slots=True)
class EvidenceReport:
    accepted: bool
    rejected_claims: tuple[str, ...]


class SageAgent:
    def validate(self, evidence: Sequence[Evidence]) -> EvidenceReport:
        rejected = tuple(
            item.claim for item in evidence if not item.verified or not item.source.strip()
        )
        return EvidenceReport(bool(evidence) and not rejected, rejected)


T = TypeVar("T")


class RetryableOperationError(Exception):
    pass


class HeroAgent:
    """Retries only operations declared idempotent, with a hard maximum of three attempts."""

    def run(
        self,
        operation: Callable[[], T],
        *,
        idempotent: bool,
        max_attempts: int = 1,
    ) -> T:
        attempts = max(1, min(max_attempts, 3))
        if attempts > 1 and not idempotent:
            raise ValueError("non-idempotent operations cannot be automatically retried")
        for attempt in range(attempts):
            try:
                return operation()
            except RetryableOperationError:
                if attempt + 1 == attempts:
                    raise
        raise RuntimeError("unreachable retry state")


class MagicianAgent:
    """Produces a candidate value for the evolution pipeline; it cannot activate it."""

    def prepare(self, candidate_factory: Callable[[], T]) -> T:
        return candidate_factory()
