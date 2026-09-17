using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Ingress;

/// <summary>Where a route came from, for the health report and the log.</summary>
public enum IngressRouteSource
{
    /// <summary>The <c>Ingress.Routes</c> list in configuration.</summary>
    Configuration,

    /// <summary>A tenant hostname row with <c>NodeUpstream</c> set.</summary>
    Database,
}

/// <summary>
/// One entry of the ingress route table: requests for <see cref="Host"/> are forwarded to
/// <see cref="Upstream"/>, and requests that arrived on the plain-HTTP listener to
/// <see cref="PlainHttpUpstream"/> when there is one. A host absent from the table is served
/// locally; the table never holds a host without an upstream.
/// </summary>
/// <param name="Host">The name, lower-case, without trailing dot.</param>
/// <param name="Upstream">The node's address.</param>
/// <param name="PlainHttpUpstream">The node's plain-HTTP listener, or null to use <paramref name="Upstream"/> for plain-HTTP arrivals too.</param>
/// <param name="PinnedSpki">The node's TLS SPKI pin in canonical form, or null.</param>
/// <param name="Source">Which source named the route.</param>
public sealed record IngressRoute(string Host, Uri Upstream, Uri? PlainHttpUpstream, string? PinnedSpki, IngressRouteSource Source)
{
    /// <summary>Whether either upstream is reached over TLS.</summary>
    public bool AnyHttps => IngressConfig.IsHttps(Upstream) || (PlainHttpUpstream != null && IngressConfig.IsHttps(PlainHttpUpstream));
}

/// <summary>A tenant hostname row as the route table reads it: the name and the node it is served by, if any.</summary>
/// <param name="Hostname">The tenant hostname, as stored.</param>
/// <param name="NodeUpstream">The <c>NodeUpstream</c> column; null or blank means the name is served locally.</param>
public sealed record TenantHostnameUpstream(string Hostname, string? NodeUpstream);

/// <summary>
/// The rules that turn the two route sources into one table. Pure, so the precedence and the
/// refusals are testable without a database or a host.
/// </summary>
public static class IngressRouteTable
{
    /// <summary>
    /// Merges the configured routes with the database rows. A configured route wins over the
    /// row for the same host; a row with no <c>NodeUpstream</c> is not a route, so the host
    /// falls through to the local roles; a row whose upstream does not parse is dropped and
    /// reported through <paramref name="onProblem"/> rather than routed somewhere odd.
    /// Configured routes are assumed validated by <see cref="IngressConfig.Validate"/>; one
    /// that still fails to parse is dropped and reported the same way. The result is ordered
    /// by host.
    /// </summary>
    public static IReadOnlyList<IngressRoute> Merge(
        IEnumerable<IngressRouteConfig> configured,
        IEnumerable<TenantHostnameUpstream> database,
        Action<string>? onProblem = null)
    {
        ArgumentNullException.ThrowIfNull(configured);
        ArgumentNullException.ThrowIfNull(database);
        var table = new Dictionary<string, IngressRoute>(StringComparer.OrdinalIgnoreCase);

        foreach (var route in configured)
        {
            if (route == null) continue;
            var host = IngressRouteConfig.NormalizeHost(route.Host);
            if (host == null)
            {
                onProblem?.Invoke($"Ingress.Routes: '{route.Host}' is not a bare hostname; the route is ignored.");
                continue;
            }
            if (!IngressRouteConfig.TryParseUpstream(route.Upstream, out var upstream))
            {
                onProblem?.Invoke($"Ingress.Routes: '{host}' has no usable Upstream ('{route.Upstream}'); the route is ignored.");
                continue;
            }
            Uri? plain = null;
            if (!string.IsNullOrWhiteSpace(route.PlainHttpUpstream) && !IngressRouteConfig.TryParseUpstream(route.PlainHttpUpstream, out plain))
            {
                onProblem?.Invoke($"Ingress.Routes: '{host}' has no usable PlainHttpUpstream ('{route.PlainHttpUpstream}'); plain-HTTP requests use Upstream.");
                plain = null;
            }
            var pin = IngressRouteConfig.NormalizePin(route.PinnedSpki);
            if (!string.IsNullOrWhiteSpace(route.PinnedSpki) && pin == null)
            {
                onProblem?.Invoke($"Ingress.Routes: '{host}' has a PinnedSpki that is not a SHA-256 pin; the route is ignored.");
                continue;
            }
            if (table.ContainsKey(host))
            {
                onProblem?.Invoke($"Ingress.Routes: '{host}' is listed more than once; the first entry is kept.");
                continue;
            }
            table[host] = new IngressRoute(host, upstream, plain, pin, IngressRouteSource.Configuration);
        }

        foreach (var row in database)
        {
            if (row == null || string.IsNullOrWhiteSpace(row.NodeUpstream)) continue;
            var host = IngressRouteConfig.NormalizeHost(row.Hostname);
            if (host == null) continue;
            if (table.TryGetValue(host, out var existing) && existing.Source == IngressRouteSource.Configuration)
                continue; // configuration wins
            if (!IngressRouteConfig.TryParseUpstream(row.NodeUpstream, out var upstream))
            {
                onProblem?.Invoke($"Tenant hostname '{host}' has a NodeUpstream that is not an absolute http:// or https:// address ('{row.NodeUpstream}'); the name is served locally.");
                continue;
            }
            table[host] = new IngressRoute(host, upstream, null, null, IngressRouteSource.Database);
        }

        return table.Values.OrderBy(r => r.Host, StringComparer.Ordinal).ToList();
    }
}

/// <summary>
/// The route table the ingress serves from, rebuilt from configuration and the tenant
/// hostnames table on a short interval and after a change made in this process. The lookup
/// on the request path is a dictionary read; the rebuild happens off it, as the tenant
/// hostname certificate cache does it. A failed database read keeps the previous database
/// rows: a route that was there a minute ago is more likely right than no route.
/// </summary>
public sealed class IngressRouteTableService
{
    private readonly IngressConfig _config;
    private readonly Func<IReadOnlyList<TenantHostnameUpstream>> _loadDatabase;
    private readonly TimeSpan _refreshInterval;
    private readonly Action<string>? _onProblem;
    private readonly object _gate = new();

    private volatile Snapshot _current;
    private IReadOnlyList<TenantHostnameUpstream> _lastDatabaseRows = Array.Empty<TenantHostnameUpstream>();
    private long _nextRefreshTicks;
    private int _refreshInFlight;

    /// <summary>Shortest honoured refresh interval, so a misconfigured value cannot hammer the database.</summary>
    public static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Creates the service. Nothing is loaded until <see cref="LoadNow"/> or the first lookup.
    /// </summary>
    /// <param name="config">The ingress section; its routes are the first source.</param>
    /// <param name="loadDatabase">Reads every tenant hostname with its <c>NodeUpstream</c>; may throw when the database is unreachable.</param>
    /// <param name="refreshInterval">Age after which a lookup triggers a background rebuild.</param>
    /// <param name="onProblem">Receives one message per dropped route and per failed database read.</param>
    public IngressRouteTableService(
        IngressConfig config,
        Func<IReadOnlyList<TenantHostnameUpstream>> loadDatabase,
        TimeSpan refreshInterval,
        Action<string>? onProblem = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _loadDatabase = loadDatabase ?? throw new ArgumentNullException(nameof(loadDatabase));
        _refreshInterval = refreshInterval < MinimumRefreshInterval ? MinimumRefreshInterval : refreshInterval;
        _onProblem = onProblem;
        _current = new Snapshot(Array.Empty<IngressRoute>(), loaded: false, databaseReachable: false);
    }

    /// <summary>Raised after a rebuild whose result differs from the table served before it, on the rebuilding thread.</summary>
    public event Action? Changed;

    /// <summary>The routes being served, ordered by host.</summary>
    public IReadOnlyList<IngressRoute> Routes => _current.Routes;

    /// <summary>Whether the table has been built at least once, from configuration at least.</summary>
    public bool Loaded => _current.Loaded;

    /// <summary>Whether the last rebuild read the tenant hostnames table; false when the database was unreachable.</summary>
    public bool DatabaseReachable => _current.DatabaseReachable;

    /// <summary>
    /// The route for a request host, by exact case-insensitive match; null when the host is
    /// served locally. Never blocks and never throws; a stale table triggers a background
    /// rebuild.
    /// </summary>
    public IngressRoute? Find(string? host)
    {
        var snapshot = _current;
        if (DateTime.UtcNow.Ticks >= Interlocked.Read(ref _nextRefreshTicks))
            TriggerRefresh();
        if (string.IsNullOrEmpty(host)) return null;
        return snapshot.ByHost.TryGetValue(host.TrimEnd('.'), out var route) ? route : null;
    }

    /// <summary>Whether <paramref name="host"/> has an upstream, so whether a request for it is proxied rather than served here.</summary>
    public bool HasUpstream(string? host) => Find(host) != null;

    /// <summary>Rebuilds the table synchronously and returns the number of routes.</summary>
    public int LoadNow()
    {
        Interlocked.Exchange(ref _nextRefreshTicks, (DateTime.UtcNow + _refreshInterval).Ticks);
        Rebuild();
        return _current.Routes.Count;
    }

    /// <summary>Rebuilds the table after a change made in this process.</summary>
    public void Reload() => LoadNow();

    private void TriggerRefresh()
    {
        if (Interlocked.CompareExchange(ref _refreshInFlight, 1, 0) != 0) return;
        Interlocked.Exchange(ref _nextRefreshTicks, (DateTime.UtcNow + _refreshInterval).Ticks);
        _ = Task.Run(() =>
        {
            try
            {
                Rebuild();
            }
            finally
            {
                Interlocked.Exchange(ref _refreshInFlight, 0);
            }
        });
    }

    private void Rebuild()
    {
        lock (_gate)
        {
            IReadOnlyList<TenantHostnameUpstream> rows;
            var reachable = true;
            try
            {
                rows = _loadDatabase() ?? Array.Empty<TenantHostnameUpstream>();
                _lastDatabaseRows = rows;
            }
            catch (Exception ex)
            {
                reachable = false;
                rows = _lastDatabaseRows;
                _onProblem?.Invoke($"The tenant hostnames table could not be read ({ex.GetType().Name}: {ex.Message}); the previous {rows.Count} row(s) are kept.");
            }

            var routes = IngressRouteTable.Merge(_config.Routes, rows, _onProblem);
            var previous = _current;
            _current = new Snapshot(routes, loaded: true, databaseReachable: reachable);
            if (!previous.Loaded || !SameRoutes(previous.Routes, routes))
                Changed?.Invoke();
        }
    }

    private static bool SameRoutes(IReadOnlyList<IngressRoute> a, IReadOnlyList<IngressRoute> b)
    {
        if (a.Count != b.Count) return false;
        for (var i = 0; i < a.Count; i++)
        {
            if (!a[i].Equals(b[i])) return false;
        }
        return true;
    }

    private sealed class Snapshot
    {
        public Snapshot(IReadOnlyList<IngressRoute> routes, bool loaded, bool databaseReachable)
        {
            Routes = routes;
            Loaded = loaded;
            DatabaseReachable = databaseReachable;
            ByHost = routes.ToDictionary(r => r.Host, r => r, StringComparer.OrdinalIgnoreCase);
        }

        public IReadOnlyList<IngressRoute> Routes { get; }
        public bool Loaded { get; }
        public bool DatabaseReachable { get; }
        public IReadOnlyDictionary<string, IngressRoute> ByHost { get; }
    }
}
