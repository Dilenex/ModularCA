using Microsoft.Extensions.Primitives;
using ModularCA.Core.Services.Ingress;
using ModularCA.Shared.Models.Config;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Health;

namespace ModularCA.API.Ingress;

/// <summary>
/// Hands the route table to YARP: one route and one cluster per host that has an upstream,
/// rebuilt whenever <see cref="IngressRouteTableService"/> reports a change. A host with no
/// upstream has no route here, so a request for it is never proxied and falls through to the
/// local roles. The translation is a pure function (<see cref="Build"/>) so the shape can be
/// asserted without a host.
/// </summary>
public sealed class IngressProxyConfigProvider : IProxyConfigProvider, IDisposable
{
    /// <summary>The destination requests from the HTTPS listener go to: the route's <c>Upstream</c>.</summary>
    public const string HttpsDestination = "https";

    /// <summary>The destination requests from the plain-HTTP listener go to, when the route names a <c>PlainHttpUpstream</c>.</summary>
    public const string PlainDestination = "plain";

    /// <summary>Cluster metadata: the host the cluster serves.</summary>
    public const string HostMetadata = "modularca.host";

    /// <summary>Cluster metadata: the route's SPKI pin in canonical form, when it has one.</summary>
    public const string PinMetadata = "modularca.pinnedSpki";

    /// <summary>Cluster metadata: <c>true</c> when every <c>https://</c> destination of the cluster is loopback.</summary>
    public const string LoopbackMetadata = "modularca.httpsLoopback";

    /// <summary>Cluster metadata: where the route came from, <c>Configuration</c> or <c>Database</c>.</summary>
    public const string SourceMetadata = "modularca.source";

    private const string IdPrefix = "ingress:";

    private readonly IngressRouteTableService _table;
    private readonly IngressConfig _config;
    private readonly object _gate = new();
    private volatile Snapshot _current;

    /// <summary>Creates the provider over the route table and subscribes to its changes.</summary>
    public IngressProxyConfigProvider(IngressRouteTableService table, IngressConfig config)
    {
        _table = table ?? throw new ArgumentNullException(nameof(table));
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _current = Snapshot.From(Build(table.Routes, config));
        _table.Changed += OnChanged;
    }

    /// <inheritdoc />
    public IProxyConfig GetConfig() => _current;

    /// <summary>The route id and cluster id for a host.</summary>
    public static string IdFor(string host) => IdPrefix + host;

    /// <summary>
    /// One route and one cluster per table entry. The route matches the host and every path;
    /// the cluster holds the HTTPS destination and, when the entry names one, the plain-HTTP
    /// destination, each probed actively at the configured path so a node that stops
    /// answering is marked down and the request for its host is refused rather than sent.
    /// </summary>
    public static (IReadOnlyList<RouteConfig> Routes, IReadOnlyList<ClusterConfig> Clusters) Build(IReadOnlyList<IngressRoute> routes, IngressConfig config)
    {
        ArgumentNullException.ThrowIfNull(routes);
        ArgumentNullException.ThrowIfNull(config);
        var routeConfigs = new List<RouteConfig>(routes.Count);
        var clusterConfigs = new List<ClusterConfig>(routes.Count);
        foreach (var route in routes)
        {
            var id = IdFor(route.Host);
            routeConfigs.Add(new RouteConfig
            {
                RouteId = id,
                ClusterId = id,
                Match = new RouteMatch { Hosts = new[] { route.Host } },
            });

            var destinations = new Dictionary<string, DestinationConfig>(StringComparer.Ordinal)
            {
                [HttpsDestination] = new DestinationConfig { Address = route.Upstream.ToString() },
            };
            if (route.PlainHttpUpstream != null)
                destinations[PlainDestination] = new DestinationConfig { Address = route.PlainHttpUpstream.ToString() };

            var httpsLoopback = destinations.Values
                .Select(d => new Uri(d.Address, UriKind.Absolute))
                .Where(IngressConfig.IsHttps)
                .All(u => u.IsLoopback);

            var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [HostMetadata] = route.Host,
                [LoopbackMetadata] = httpsLoopback ? "true" : "false",
                [SourceMetadata] = route.Source.ToString(),
            };
            if (route.PinnedSpki != null)
                metadata[PinMetadata] = route.PinnedSpki;

            clusterConfigs.Add(new ClusterConfig
            {
                ClusterId = id,
                Destinations = destinations,
                Metadata = metadata,
                HealthCheck = new HealthCheckConfig
                {
                    // Unhealthy destinations are withheld; with none left the request is refused
                    // with a clear body rather than sent to a node known to be down.
                    AvailableDestinationsPolicy = HealthCheckConstants.AvailableDestinations.HealthyAndUnknown,
                    Active = new ActiveHealthCheckConfig
                    {
                        Enabled = true,
                        Interval = TimeSpan.FromSeconds(Math.Max(IngressConfig.MinimumHealthCheckIntervalSeconds, config.HealthCheckIntervalSeconds)),
                        Timeout = TimeSpan.FromSeconds(Math.Max(1, config.HealthCheckTimeoutSeconds)),
                        Policy = HealthCheckConstants.ActivePolicy.ConsecutiveFailures,
                        Path = config.HealthCheckPath,
                    },
                },
                HttpClient = new HttpClientConfig
                {
                    // The trust decision is the client factory's (pin, shared CA, loopback under
                    // the dangerous flag, else the system store); this flag alone would accept
                    // anything, so it is never set here.
                    DangerousAcceptAnyServerCertificate = false,
                },
            });
        }
        return (routeConfigs, clusterConfigs);
    }

    private void OnChanged()
    {
        lock (_gate)
        {
            var previous = _current;
            _current = Snapshot.From(Build(_table.Routes, _config));
            previous.SignalChange();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _table.Changed -= OnChanged;
    }

    /// <summary>One immutable configuration with the token YARP watches for the next one.</summary>
    private sealed class Snapshot : IProxyConfig
    {
        private readonly CancellationTokenSource _cts = new();

        private Snapshot(IReadOnlyList<RouteConfig> routes, IReadOnlyList<ClusterConfig> clusters)
        {
            Routes = routes;
            Clusters = clusters;
            ChangeToken = new CancellationChangeToken(_cts.Token);
        }

        public static Snapshot From((IReadOnlyList<RouteConfig> Routes, IReadOnlyList<ClusterConfig> Clusters) built)
            => new(built.Routes, built.Clusters);

        public IReadOnlyList<RouteConfig> Routes { get; }
        public IReadOnlyList<ClusterConfig> Clusters { get; }
        public IChangeToken ChangeToken { get; }

        public void SignalChange()
        {
            _cts.Cancel();
            _cts.Dispose();
        }
    }
}
