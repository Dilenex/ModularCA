using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.API.Ingress;
using ModularCA.Core.Services.Ingress;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Model;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// The ingress role's entry on <c>/health/ready</c>: how many configured routes there are, and
/// per upstream what the active probe last found. The entry is always healthy; a node that is
/// down is reported, not made the whole ingress's failure, since the other hosts are still
/// served.
/// </summary>
public sealed class IngressHealthCheck : IHealthCheck
{
    private readonly IngressRouteTableService _table;
    private readonly IProxyStateLookup _proxy;

    /// <summary>Creates the check over the route table and YARP's runtime state.</summary>
    public IngressHealthCheck(IngressRouteTableService table, IProxyStateLookup proxy)
    {
        _table = table;
        _proxy = proxy;
    }

    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var routes = _table.Routes;
        var upstreams = new List<object>();
        var down = new List<string>();
        foreach (var cluster in _proxy.GetClusters().OrderBy(c => c.ClusterId, StringComparer.Ordinal))
        {
            var host = cluster.Model.Config.Metadata != null && cluster.Model.Config.Metadata.TryGetValue(IngressProxyConfigProvider.HostMetadata, out var h) ? h : cluster.ClusterId;
            foreach (var destination in cluster.DestinationsState.AllDestinations)
            {
                var health = destination.Health.Active;
                var state = health switch
                {
                    DestinationHealth.Healthy => "healthy",
                    DestinationHealth.Unhealthy => "unhealthy",
                    _ => "unknown",
                };
                if (health == DestinationHealth.Unhealthy)
                    down.Add($"{host} ({destination.DestinationId})");
                upstreams.Add(new { host, destination = destination.DestinationId, address = destination.Model.Config.Address, health = state });
            }
        }

        var report = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["routeCount"] = routes.Count,
            ["upstreams"] = upstreams,
            ["down"] = down,
        };
        var data = new Dictionary<string, object>(StringComparer.Ordinal) { ["ingress"] = report };

        var summary = routes.Count == 0
            ? "The ingress routes nothing; every name is served here"
            : down.Count == 0
                ? $"{routes.Count} route(s), every upstream answering"
                : $"{routes.Count} route(s), {down.Count} upstream(s) down: {string.Join(", ", down)}";
        return Task.FromResult(HealthCheckResult.Healthy(summary, data));
    }
}
