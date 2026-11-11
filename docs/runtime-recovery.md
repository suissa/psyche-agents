# Runtime health and recovery

## Health observations

RuntimeHealthMonitor consumes samples from the application monitoring layer. HealthSample currently supports:

- error rate in the interval [0, 1];
- p95 latency in milliseconds;
- contract failure count.

HealthThresholds defines the allowed maxima. Metrics equal to their configured maximum remain healthy; a value above a maximum is degraded.

This module does not poll services or collect telemetry itself. An application adapter must aggregate real runtime metrics and call `RuntimeHealthMonitor.observe(proposal_id, sample)` for the active evolution.

## Automatic rollback

Automatic recovery is enabled by default when a RuntimeHealthMonitor is constructed. When a sample breaches any threshold, the monitor asks RecoveryController to roll back the active proposal.

RecoveryController calls `EvolutionaryEngine.rollback()`, which restores the retained previous ToolBinding with compare-and-swap against the registry generation created by the candidate activation.

If another registry change has happened since activation, the CAS check fails and the recovery controller reports RECOVERY_FAILED. It does not overwrite a newer deployment. Operator reconciliation is then required.

Set `auto_recover=False` to report DEGRADED without performing rollback automatically. This is useful for staged observation or environments where automatic recovery requires a separate approval policy.

## Recovery evidence

The controller records a recovery-completed or recovery-failed audit event with proposal ID, reason and restored version. The EvolutionaryEngine also records state transitions. The default audit sinks are in-memory reference implementations; production requires durable, tamper-evident audit storage.

## Current boundary

The health monitor evaluates supplied samples. It does not include an OpenTelemetry collector/exporter, baseline learning, statistical anomaly detection, canary traffic routing or multi-process rollout controller. Those are separate integrations. Rollback operates on the in-process ToolRegistry and is not a distributed deployment rollback.
