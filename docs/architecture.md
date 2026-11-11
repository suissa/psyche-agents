# Architecture: Psyche as a multi-agent control plane

## Purpose

Psyche Agents maps selected psychoanalytic concepts to software boundaries. The mapping is useful because it separates intent, constraints, arbitration, adversarial testing, shared capabilities and controlled adaptation. It is not a psychological model of an LLM and does not make claims about consciousness.

## Request lifecycle

1. The Id adapter captures raw input and emits a typed Intent. It does not authorize an action.
2. The Ego resolves the requested action in the versioned ToolRegistry. A missing capability is denied.
3. The Superego evaluates the intent, tool manifest and optional signed approval. The policy is deterministic and independent of model output.
4. The Ego executes the handler only when the decision status is ALLOW.
5. Audit events record blocked, started, completed and failed execution transitions.

There is no path from a model response directly to a side effect. A local model can extract, classify, explain or propose, but it does not hold the policy authority.

## Freud: Id, Superego and Ego

### Id — intent capture

The Id represents the requested outcome in a typed structure. It preserves the raw input for inspection and produces an action plus a payload. The default JSON extractor is intentionally deterministic. A local-model-backed extractor can be added behind the IntentExtractor protocol, but its result is always untrusted.

### Superego — policy gate

The Superego owns allowlists, schema and domain constraints, amount limits, lexical risk signals, side-effect classes and human approval requirements. It does not infer permission from the apparent intent or from a model's confidence.

The initial policy defaults to an empty allowlist. Financial tools are classified explicitly and require a signed approval from an actor other than the initiating actor. Tool registration alone never grants permission.

### Ego — arbitration and dispatch

The Ego resolves a capability, asks the Superego for a decision, emits audit events and dispatches only an ALLOW result. Exceptions are not automatically replayed. Retry behavior belongs to a separately bounded policy and must not repeat non-idempotent side effects.

## Jung: Shadow and archetypes

### Shadow

The Shadow is a test harness, not an autonomous production attacker. It sends adversarial examples to the policy gate and verifies that the gate does not return ALLOW. It never invokes registered production handlers. Extend the cases with domain-specific abuse patterns, parser confusion, replay, authorization bypass and concurrency races.

### Archetype catalog

- **Sage:** grounds claims in evidence and records uncertainty. It cannot authorize actions.
- **Magician:** prepares candidate capabilities. It cannot activate them.
- **Hero:** coordinates bounded progress and retries only explicitly idempotent operations within a fixed attempt budget.
- **Shadow:** probes policy behavior in isolation and cannot invoke production tools.

Archetypes are capability profiles, not unrestricted autonomous agents. Tool manifests identify the archetype associated with a capability.

## Individuation: controlled system evolution

The evolutionary engine stages a replacement as a proposal. A candidate must preserve tool identity and action, use a new immutable version, pass an externally supplied validator and receive explicit human approval. Activation uses registry-generation compare-and-swap so a stale candidate cannot overwrite a newer registry state.

The current engine swaps an already-loaded handler. It does not execute generated source code, install dependencies, perform a hot compile, create remote commits or deploy a binary. Those operations require a separate isolated build-and-release pipeline with signed artifacts, policy checks, rollback and human authorization.

## Trust boundaries

- User prompts, model output, tool output, retrieved documents and candidate code are untrusted.
- The policy gate and its configuration are trusted computing-base components and require independent review.
- Tool handlers execute with only the credentials and capabilities they need.
- Approval tokens are signed by an authenticated approval service and are bound to an intent, expiry, nonce and distinct approver.
- The audit sink must be replaced with durable, tamper-evident storage before production use.
