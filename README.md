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


## Governed Evolution Engine

The implementation now binds each proposal to immutable candidate bytes stored by SHA-256. A validation report must attest to the exact artifact hash. Human approval is represented by a signed token bound to the proposal ID, artifact hash and validation ID; the engine rejects self-approval, expired tokens, replayed nonces and mismatched artifacts.

Activation uses the registry generation captured when the proposal was created. A stale generation fails closed. The previous ToolBinding is retained and can be restored through a second compare-and-swap operation.

The project now includes SQLiteArtifactStore for durable, content-addressed artifacts and SQLiteNonceStore for atomic one-time approval nonces across processes sharing a local database. The in-memory adapters remain useful for tests. Multi-host deployments should inject object storage and a shared transactional nonce store.

SandboxCandidateValidator connects EvolutionaryEngine.validate() to SandboxOrchestrator. ContainerSandboxRunner supports digest-pinned Docker/Podman images, no network, read-only filesystem and candidate mount, dropped capabilities, no-new-privileges, non-root execution, bounded CPU/memory/PIDs/time/output and a noexec temporary filesystem. Rootless Podman is recommended.

PreparedArtifactLoader resolves the approved digest to an already-prepared ToolBinding without importing or executing artifact bytes. The trusted builder must prove that the prepared handler corresponds to the candidate digest. RuntimeHealthMonitor evaluates supplied error-rate, p95-latency and contract-failure samples; RecoveryController can roll back the active binding through CAS.

The container engine, validation image, candidate builder, approver identity service and application telemetry adapter remain trusted integration boundaries. Proposal state, prepared-handler catalog and the default audit sink are still in memory. The current rollback updates the in-process registry and is not a distributed release rollback.


## Sandboxed validation, persistent artifacts and recovery

The next evolution layer is implemented in these modules:

- `sandbox.py`: digest-pinned Docker/Podman runner with no network, read-only root filesystem and candidate mount, dropped capabilities, no-new-privileges, non-root UID/GID, CPU/memory/PID/time/output/artifact limits and a noexec temporary filesystem.
- `validation.py`: `SandboxOrchestrator` and `SandboxCandidateValidator` connect a named validation matrix to `EvolutionaryEngine.validate()`.
- `artifacts.py`: `SQLiteArtifactStore` provides durable content-addressed artifacts with SHA-256 verification and WAL/FULL durability.
- `replay.py`: `SQLiteNonceStore` atomically consumes one-time approval nonces across processes sharing a local database.
- `loader.py`: `PreparedArtifactLoader` resolves an approved digest to an already-prepared trusted handler; it never evaluates artifact bytes.
- `health.py`: `RuntimeHealthMonitor` evaluates supplied error-rate, p95-latency and contract-failure samples and can call `RecoveryController` for CAS rollback.

A production runner needs a locally available, reviewed validation image pinned by digest. `SandboxCheck` commands are trusted deployment configuration and are passed as an argument vector, never through a shell. The container engine and its daemon remain part of the trusted computing base; rootless Podman is recommended.

Example configuration:

    runner = ContainerSandboxRunner(
        image="registry.example/psyche-validator@sha256:<64-hex-digest>",
        engine="podman",
    )
    checks = (
        SandboxCheck("unit", ("/opt/validator/unit-check",)),
        SandboxCheck("contract", ("/opt/validator/contract-check",)),
        SandboxCheck("security", ("/opt/validator/security-check",)),
    )
    validator = SandboxCandidateValidator(
        SandboxOrchestrator(runner),
        checks,
    )

The GitHub Actions workflow builds a small local validator fixture and runs an actual container integration test that verifies candidate readability, read-only root filesystem, zero Linux capabilities, no-new-privileges and disabled networking.

SQLite stores are intended for a local durable filesystem. Multi-host production should inject object storage and a shared transactional nonce store. Evolution proposal state, the prepared-handler catalog and the default audit sink remain in memory; distributed activation and durable audit are not implemented yet.


## Durable evolution history and release coordination

`SQLiteAuditLog` is a durable audit sink for proposal lifecycle events. It stores canonical records in a SHA-256 hash chain and supports integrity verification plus externally anchorable checkpoints. Supply it as `EvolutionaryEngine(..., audit=SQLiteAuditLog(path))`.

`ReleaseCoordinator` defines the release boundary. Its `SQLiteReleaseCoordinator` implementation provides per-target leases, monotonic fencing tokens, generation CAS, idempotent retries and a transactionally written release event chain. This implementation coordinates multiple processes on one host using a durable local filesystem. A multi-host deployment needs a server-backed adapter implementing the same protocol; SQLite on a shared network filesystem is not a distributed lock service.

The release coordinator records deployment metadata only. It does not build, sign, upload or deploy executable artifacts, and it does not turn the engine's in-process registry swap into a distributed rollout. Those steps remain explicit trusted integration boundaries.
