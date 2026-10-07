using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Ingress;

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
public sealed record IngressRoute(string Host, Uri Upstream, Uri? PlainHttpUpstream, string? PinnedSpki)
{
    /// <summary>Whether either upstream is reached over TLS.</summary>
    public bool AnyHttps => IngressConfig.IsHttps(Upstream) || (PlainHttpUpstream != null && IngressConfig.IsHttps(PlainHttpUpstream));
}

/// <summary>
/// The rules that turn <c>Ingress.Routes</c> into the route table. Pure, so the refusals are
/// testable without a host.
/// </summary>
public static class IngressRouteTable
{
    /// <summary>
    /// Builds the table from the configured routes. Routes are assumed validated by
    /// <see cref="IngressConfig.Validate"/>; one that still fails to parse, or repeats a host,
    /// is dropped and reported through <paramref name="onProblem"/> rather than routed
    /// somewhere odd. Hosts are keyed without regard to case or a trailing dot. The result is
    /// ordered by host.
    /// </summary>
    public static IReadOnlyList<IngressRoute> Build(IEnumerable<IngressRouteConfig> configured, Action<string>? onProblem = null)
    {
        ArgumentNullException.ThrowIfNull(configured);
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
            table[host] = new IngressRoute(host, upstream, plain, pin);
        }

        return table.Values.OrderBy(r => r.Host, StringComparer.Ordinal).ToList();
    }
}

/// <summary>
/// The route table the ingress serves from, built once from <c>Ingress.Routes</c> when the
/// process starts. The lookup on the request path is a dictionary read.
/// </summary>
public sealed class IngressRouteTableService
{
    private readonly IReadOnlyDictionary<string, IngressRoute> _byHost;

    /// <summary>Builds the table from the configured routes.</summary>
    /// <param name="config">The ingress section.</param>
    /// <param name="onProblem">Receives one message per dropped route.</param>
    public IngressRouteTableService(IngressConfig config, Action<string>? onProblem = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        Routes = IngressRouteTable.Build(config.Routes, onProblem);
        _byHost = Routes.ToDictionary(r => r.Host, r => r, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The routes being served, ordered by host.</summary>
    public IReadOnlyList<IngressRoute> Routes { get; }

    /// <summary>
    /// The route for a request host, by exact case-insensitive match ignoring a trailing dot;
    /// null when the host is served locally.
    /// </summary>
    public IngressRoute? Find(string? host)
    {
        if (string.IsNullOrEmpty(host)) return null;
        return _byHost.TryGetValue(host.TrimEnd('.'), out var route) ? route : null;
    }

    /// <summary>Whether <paramref name="host"/> has an upstream, so whether a request for it is proxied rather than served here.</summary>
    public bool HasUpstream(string? host) => Find(host) != null;
}
