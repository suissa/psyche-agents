# Security model and limitations

## Fail-closed defaults

The action allowlist is empty by default. The runtime denies unknown actions, unregistered tools, malformed action identifiers, invalid financial fields, out-of-policy amounts, blocked lexical patterns, control bytes and missing or invalid required approvals.

A manifest marks each capability as read-only, write or financial. Financial handlers require approval even if their manifest is misconfigured to omit the explicit approval flag.

The HMAC approval token is bound to the intent identifier and includes an approver identifier, expiry, nonce and signature. The verifier rejects expired tokens, rejects an approver who is the same identity as the initiating actor and rejects nonce reuse within the current process. The approval secret must be at least 256 bits and must remain in a trusted service boundary. The included nonce cache is in-memory; production deployments must replace it with a durable, shared, atomic one-time nonce store.

The actor identity supplied to the runtime must come from an authenticated server-side session, never from an untrusted prompt or client field.

## Zig lexical scanner

The Zig module exposes psyche_scan_input through a C ABI and reports two signal classes: a small set of instruction-override phrases and disallowed control bytes. The Python fallback mirrors these checks.

The scanner evaluates both raw input and a canonical representation of the structured intent payload. This is a pre-filter, not a parser, semantic classifier or proof of safety. It can produce false positives and false negatives. It cannot reliably detect encoded, multilingual, contextual, indirect or novel prompt injection. Do not treat a zero result as authorization. All actions still require deterministic policy evaluation.

## Side effects and replay

The Ego performs no automatic replay after a handler exception. A tool that supports retries must define idempotency and reconciliation at its own boundary. The Hero profile limits retries to declared idempotent operations and caps attempts at three.

A production financial adapter must implement idempotency keys, transaction-state reconciliation, destination ownership checks, limits at the payment provider, fraud controls, dual control and immutable accounting records. The sample package does not move money.

## Shadow testing

The Shadow agent operates on the Superego gate only. Add isolated integration tests for every adapter and tool handler. Never point destructive red-team tests at production accounts or customer data.

## Production requirements not supplied by this repository

- authenticated identity and authorization service;
- durable, tamper-evident audit storage and retention controls;
- durable, shared anti-replay nonce storage;
- schema validation and domain invariants for every tool;
- process/container isolation for model inference and candidate testing;
- secrets management, rotation and least-privilege credentials;
- rate limits, quotas, timeouts and resource ceilings;
- idempotency, reconciliation and rollback for external side effects;
- independent threat modeling, penetration testing and compliance review.

This project is a technical foundation and must not be represented as certified or independently audited financial software.
