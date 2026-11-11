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

The container engine, validation image, candidate builder, approver identity service and application telemetry adapter remain trusted integration boundaries. Proposal state and the prepared-handler catalog are still in memory. The default audit sink remains `InMemoryAuditLog`, while `SQLiteAuditLog` is available as an opt-in durable sink. The current rollback updates the in-process registry and is not a distributed release rollback.


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

SQLite stores are intended for a local durable filesystem. Multi-host production should inject object storage, a shared transactional nonce store and a server-backed release coordinator. Evolution proposal metadata can be persisted with `SQLiteEvolutionProposalStore`, and prepared digest-to-manifest metadata with `SQLitePreparedArtifactCatalog`; runtime handler objects are still rehydrated from a trusted application resolver. The default audit sink remains in-memory unless `SQLiteAuditLog` is supplied. Multi-host distributed activation is not implemented yet.


## Durable evolution history and release coordination

`SQLiteAuditLog` is a durable audit sink for proposal lifecycle events. It stores canonical records in a SHA-256 hash chain and supports integrity verification plus externally anchorable checkpoints. Supply it as `EvolutionaryEngine(..., audit=SQLiteAuditLog(path))`.

`ReleaseCoordinator` defines the release boundary. Its `SQLiteReleaseCoordinator` implementation provides per-target leases, monotonic fencing tokens, generation CAS, idempotent retries and a transactionally written release event chain. This implementation coordinates multiple processes on one host using a durable local filesystem. A multi-host deployment needs a server-backed adapter implementing the same protocol; SQLite on a shared network filesystem is not a distributed lock service.

The release coordinator records deployment metadata only. It does not build, sign, upload or deploy executable artifacts, and it does not turn the engine's in-process registry swap into a distributed rollout. Those steps remain explicit trusted integration boundaries.


## Durable proposal recovery

`SQLiteEvolutionProposalStore` saves proposal status, validation evidence, signed-approval metadata and activation generation with optimistic revision checks. `SQLitePreparedArtifactCatalog` stores only candidate digest-to-manifest metadata. At restart, the host supplies a `TrustedBindingResolver` that maps each persisted manifest to an already-prepared handler. Recovery rejects missing or mismatched handlers and reconciles interrupted lifecycle transitions against the current trusted registry.

The database does not serialize executable handlers and does not decide which binary is deployed. The host bootstrap/release layer must register the active trusted version before constructing `EvolutionaryEngine`, provide a `TrustedBindingResolver`, and configure the same approval verifier so persisted approval signatures can be checked after restart. The SQLite stores are scoped to a durable local filesystem and multiple local processes; multi-host deployments need server-backed implementations.


## Atomic proposal state and audit journal

For a local deployment that requires proposal revisions and their audit evidence to commit together, use one `SQLiteEvolutionJournal` instance for both engine interfaces:

```python
journal = SQLiteEvolutionJournal("./var/evolution-journal.sqlite3")
engine = EvolutionaryEngine(
    registry,
    proposal_store=journal,
    audit=journal,
    # Keep the trusted artifact store, loader, resolver and approval verifier configured.
)
```

The journal writes the proposal revision with compare-and-swap and appends the corresponding SHA-256 chained audit event under one SQLite `BEGIN IMMEDIATE` transaction. If either write fails, both are rolled back. It also implements the ordinary proposal-store and audit-sink read APIs, so the existing recovery and checkpoint flows continue to work.

This guarantee applies to proposal creation, lifecycle transitions and restart reconciliation only when the exact same journal instance is supplied for both interfaces. Separate adapters remain supported but are not atomic. Artifact bytes, prepared-handler metadata, approval nonce consumption, the process-local registry swap and external deployment remain separate boundaries. SQLite remains a single-host durable-filesystem adapter, not a multi-host consensus service.


## Provider-backed release execution

`ReleaseExecutionService` composes the fenced `ReleaseCoordinator` with a trusted `DeploymentAdapter`. The adapter is responsible for the actual provider operation and must enforce fencing tokens at the deployment target, idempotency by target/key, payload binding and safe inspection of the effective deployment pointer.

The service verifies the immutable artifact digest, compares provider state with the coordinator before and after acquiring a lease, deploys through the adapter, verifies the returned receipt against an independent inspection, and only then commits release metadata. A retry can reconcile a provider deployment that succeeded before the coordinator commit failed: the exact pending receipt is adopted idempotently with a newer fencing token before the coordinator is advanced.

No cloud, Kubernetes or VM provider is bundled. The repository supplies the contract and orchestration boundary, not a claim that a specific production environment has been deployed. Provider adapters must not execute arbitrary LLM-generated source; they should accept only reviewed, built and prepared artifacts. The coordinator and provider do not share a distributed transaction, so recovery depends on adapter-enforced idempotency, fencing and accurate inspection.


## Release-aware evolution activation

An approved proposal can now be activated through the external release path instead of only replacing the local registry:

```python
active = engine.activate_with_release(
    proposal_id,
    release_execution_service,
    target_id="catalog-service",
    owner_id="release-controller",
)
```

Before the provider side effect, the engine persists the target, owner, coordinator generation and deterministic idempotency key on the proposal and moves it to `ACTIVATING`. It marks the proposal `ACTIVE` only after the provider receipt is verified, the release coordinator confirms the expected generation, and the local registry has been reconciled to the trusted candidate binding.

An interrupted release-aware proposal remains `ACTIVATING` during engine hydration. The host must resume it through `activate_with_release()` with the same target and owner. This recovers both the provider-success/coordinator-failure window and the coordinator-success/local-registry-failure window without deploying twice. The engine never silently changes the persisted release target, owner, generation or idempotency key.


Release-aware proposals intentionally reject the existing local-only `rollback()` method. Reverting only the in-process registry would leave the external provider on the candidate version. Provider-aware rollback remains unavailable until the previous immutable deployment artifact and its verified digest are available to the release adapter; do not treat a local handler swap as an external rollback.
