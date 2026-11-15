using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Shared.Modes;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// Puts the instance's mode in <c>/health/ready</c>, under <c>checks.instanceMode</c>: the mode,
/// who set it, the reason and when. It never fails: restricted and DR mode are states somebody
/// chose, not faults, so they do not turn readiness to 503.
/// </summary>
public sealed class InstanceModeHealthCheck(IInstanceModeGate gate) : IHealthCheck
{
    /// <summary>The key of the entry under <c>checks</c>.</summary>
    public const string DataKey = "instanceMode";

    /// <inheritdoc/>
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var record = gate.Current;
        var data = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [DataKey] = new
            {
                mode = InstanceModeGate.NameOf(record.Mode),
                source = InstanceModeStore.SourceName(record.Source),
                setBy = record.SetBy,
                reason = record.Reason,
                setAtUtc = record.SetAtUtc,
            },
        };
        return Task.FromResult(HealthCheckResult.Healthy(InstanceModeGate.DisplayName(record.Mode), data));
    }
}
