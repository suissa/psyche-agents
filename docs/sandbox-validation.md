# Sandboxed candidate validation

## Purpose

 CandidateValidator is connected to the EvolutionaryEngine through SandboxCandidateValidator and SandboxOrchestrator. The configured runner receives the immutable ArtifactRecord and a static check definition. It never evaluates candidate bytes in the host Python process.

## Container runner

ContainerSandboxRunner supports Docker and Podman and requires an image reference pinned by digest:

    registry.example/psyche-validator@sha256:<64-hex-digest>

The validation image must already be present locally. The runner uses `--pull=never` to avoid an unreviewed image pull during validation.

Each check launches a fresh container with:

- network disabled (`--network=none`);
- read-only root filesystem;
- all Linux capabilities dropped;
- no-new-privileges security option;
- explicit numeric unprivileged UID/GID;
- bounded memory, CPU and PID count;
- read-only bind mount containing only `/candidate/artifact.bin`;
- bounded `/tmp` tmpfs mounted `noexec,nosuid,nodev`;
- a hard timeout and bounded captured stdout/stderr;
- no inherited host environment secrets and no shell interpolation.

Use rootless Podman where possible. The container engine and its host daemon remain part of the trusted computing base. A rootful Docker daemon is a powerful host boundary and must not be exposed to agents or candidate containers.

## Validation plan

SandboxCheck contains a unique name, an argument-vector command and a very small environment allowlist (`LANG`, `LC_ALL`, `TZ`, `PYTHONHASHSEED`). The command is trusted deployment configuration, not model output. The artifact path is appended as the final argument. Commands are passed directly to the process API; no shell is used.

The image should contain all validation tools and pinned dependencies. Since the sandbox has no network, any dependency installation or package fetch must happen while constructing and reviewing the validator image, not while evaluating a candidate.

SandboxOrchestrator executes all checks and produces a ValidationReport whose artifact_sha256 is the exact artifact digest. A non-zero exit, timeout or runner error prevents the proposal from reaching VALIDATED. The engine independently verifies that the report digest equals the stored artifact digest.

## Current boundary

The runner implementation and command construction are included. CI tests the security arguments and uses a fake runner to exercise the validation-to-activation path. The standard CI job does not start a container or run a customer-supplied validation image. A deployment must supply a reviewed, digest-pinned image and run the container integration suite in an environment with the configured rootless engine.

The current runner mounts the artifact as opaque bytes. The validator image owns format parsing, archive extraction, compilation and test execution. It must perform those operations inside the container with safe path handling and must not mount the host workspace or secrets.

## Example

    runner = ContainerSandboxRunner(
        image="registry.example/psyche-validator@sha256:" + "<64-hex-digest>",
        engine="podman",
        limits=SandboxLimits(
            timeout_seconds=180,
            memory_limit="1g",
            cpu_limit=2,
            pids_limit=96,
        ),
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

Pass this validator to `EvolutionaryEngine.validate(proposal_id, validator)`. Approval is still required after validation; sandbox success never grants production activation authority.
