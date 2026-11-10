# psyche-agents

A policy-governed multi-agent substrate inspired by Freud and Jung, with a Python orchestration layer and an optional high-performance Zig guard.

The psychoanalytic model is an architectural metaphor, not a claim that software agents have human psychology.

## Architecture

- **Id — intent capture:** preserves the user's request as a typed intent. The default adapter accepts structured JSON; local-model extractors can implement the same protocol.
- **Superego — deterministic policy gate:** validates action allowlists, payload constraints, lexical risk signals, transaction limits and signed human approvals. A model cannot override this gate.
- **Ego — mediator and dispatcher:** resolves only registered capabilities, requests a policy decision, emits audit events and executes only an explicit ALLOW decision.
- **Shadow — adversarial testing:** probes the policy gate with injection attempts, malformed values and boundary cases. It does not call production tools.
- **Collective unconscious — archetype/tool catalog:** Sage, Magician, Hero and Shadow profiles define bounded roles and capability expectations.
- **Individuation — controlled evolution:** candidates move through proposal, isolated validation, explicit approval and compare-and-swap activation. The engine never executes generated source or commits to GitHub.

The Zig scanner is an optional C-ABI lexical pre-filter. Python fallback behavior is available for development. Neither scanner is a complete prompt-injection detector.

## Quick start

Requires Python 3.11 or newer. The core package has no third-party runtime dependencies.

Install the project in editable mode:

    python -m pip install -e .

Create a ToolRegistry, register a ToolBinding, and build a PsycheRuntime with an explicit SecurityPolicy. Each tool implements execute(intent) and declares a ToolManifest with its action, version, archetype and side-effect level.

The default JSON intent adapter accepts an object with an action string and payload object. It does not call an LLM. A production local-model adapter should implement IntentExtractor and must be treated as an untrusted parser: its output still passes through Superego.

For financial actions, configure an HmacApprovalVerifier using a secret of at least 32 bytes. A trusted approval service should issue a signed token only after authenticating a human approver. The approver must differ from the actor who originated the intent. Keep the secret outside source control and rotate it through your secret-management system.

## Optional Zig guard

From the repository root:

    zig test zig/src/guard.zig
    mkdir -p zig-out
    zig build-lib zig/src/guard.zig -dynamic -O ReleaseFast -femit-bin=zig-out/libpsyche_guard.so

Set PSYCHE_GUARD_LIB to the resulting shared-library path to use the native scanner through ctypes. If that variable is set but the library cannot be loaded, startup fails rather than silently using the fallback.

The native scanner only identifies a small set of lexical patterns and control bytes. It must be combined with structured parsing, authorization, least-privilege tool contracts, isolation, monitoring and human review.

## Validation

Run the Python test suite:

    python -m unittest discover -s tests -v

The GitHub Actions workflow runs the Python tests and compiles/tests the Zig scanner. Its native integration job loads the compiled Zig library through the Python FFI.

## Security posture

Default policy allows no actions. Registering a tool does not authorize it. Financial actions require a policy allowlist, bounded positive amount, valid destination and currency, and a verifiable approval from a different actor. Unknown actions, unregistered tools, invalid approval and tool exceptions fail closed.

This repository is an implementation foundation, not a certified financial control system. Before production use, connect durable audit storage, an authenticated approval service, idempotency and reconciliation, isolated candidate testing, secrets management, threat modeling and independent security review.
