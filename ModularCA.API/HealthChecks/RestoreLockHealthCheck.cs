using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Database;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// Reports, under <c>restoreLock</c> in <c>/health/ready</c>, where this node stands with the
/// lock that keeps a restore and a running node apart (<see cref="ServingDatabaseLock"/>).
/// <para>
/// <c>status</c> is <c>held</c> in ordinary running; <c>not_taken</c> in setup mode or before the
/// database first answered; <c>reconnecting</c> while the lock's connection is down, which an
/// ordinary database restart causes and which the main check already reports; <c>restoring</c>
/// while a restore started from this node's console runs. All four are healthy. Two are not, so
/// <c>/health/live</c> and <c>/health/ready</c> answer 503: <c>restore_running</c>, a restore is
/// replacing the database under this running process, and <c>restart_needed</c>, one has done so
/// and the process still runs on what it read before. A restart cures both: the start waits for
/// a restore that is still running.
/// </para>
/// </summary>
public sealed class RestoreLockHealthCheck(ServingDatabaseLock servingLock) : IHealthCheck
{
    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var state = servingLock.State;
        var status = state switch
        {
            ServingLockState.RestartNeeded => "restart_needed",
            ServingLockState.RestoreRunning => "restore_running",
            ServingLockState.Reconnecting => "reconnecting",
            ServingLockState.NotTaken => "not_taken",
            _ => servingLock.RestoringHere ? "restoring" : "held",
        };
        var detail = servingLock.HoldReason;
        var data = new Dictionary<string, object>
        {
            ["restoreLock"] = new { status, since = servingLock.Since, scheduledJobsHeld = detail != null, detail },
        };
        return Task.FromResult(state is ServingLockState.RestartNeeded or ServingLockState.RestoreRunning
            ? HealthCheckResult.Unhealthy(detail, data: data)
            : HealthCheckResult.Healthy("Restore lock", data));
    }
}
