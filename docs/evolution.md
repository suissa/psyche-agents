# Evolutionary engine

## State machine

A capability replacement follows a monotonic lifecycle:

    PROPOSED -> VALIDATED -> APPROVED -> ACTIVATED

A failed validation transitions to REJECTED. A candidate cannot skip a state or move backward through the public API.

## Validation and approval

Candidate validation is supplied through the CandidateValidator protocol. Production validators should run unit, integration, contract, security, dependency, policy and performance checks in an isolated environment. A successful boolean alone is not an adequate production validator.

Approval is a separate human action. The approver identity is stored on the proposal. The current implementation requires a non-empty authenticated identity from the caller; the surrounding application must enforce role-based access, separation of duties and an auditable approval workflow.

## Atomic activation

ToolRegistry uses a generation counter. Activation succeeds only when the generation still matches the one captured during proposal creation. If another update has happened, compare-and-swap rejects the stale activation. The new handler must preserve tool identity and action while using a new immutable version.

## Deliberate boundary

The engine does not execute source emitted by an LLM, run arbitrary shell commands, mutate the repository, push commits or deploy services. A safe extension pipeline should produce a signed, reproducible artifact in an isolated CI environment, evaluate it against the same contracts and policy suite, and activate it through a separately authorized release controller. The running process should retain a known-good version and support rollback.
