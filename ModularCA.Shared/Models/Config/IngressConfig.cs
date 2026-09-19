namespace ModularCA.Shared.Models.Config;

/// <summary>
/// The ingress role: TLS termination for every name the system knows, and routing by name to
/// the node that serves it. The route table has two sources, merged: <see cref="Routes"/> here
/// (for a spike, and for nodes on other hosts), and the tenant hostnames table, where a row
/// with <c>NodeUpstream</c> set is routed to that node. A configured route wins over the
/// database row for the same host. A name with no upstream anywhere is served by this
/// process's own roles, which is how the default single process (ingress and node together)
/// routes nothing and serves everything, exactly as before the role existed.
/// </summary>
/// <remarks>
/// Upstream TLS trust, when an upstream is <c>https://</c>: a route may pin the node's SPKI
/// (<see cref="IngressRouteConfig.PinnedSpki"/>), or every upstream may be validated against
/// one CA (<see cref="UpstreamCaCertificatePath"/>, a PEM file), or the system trust store
/// applies. <see cref="DangerousAcceptAnyUpstreamCertificate"/> skips validation for loopback
/// upstreams only; a non-loopback <c>https://</c> upstream under that flag is refused at
/// startup, since a node on another host with an unverified certificate is a node anyone on
/// the path can impersonate.
/// </remarks>
public class IngressConfig
{
    /// <summary>The routes named in configuration; each host once.</summary>
    public List<IngressRouteConfig> Routes { get; set; } = new();

    /// <summary>Seconds between active health probes of each upstream. A node that fails its probes is marked down and answered 503 for its hosts.</summary>
    public int HealthCheckIntervalSeconds { get; set; } = 10;

    /// <summary>Seconds a health probe may take before it counts as failed.</summary>
    public int HealthCheckTimeoutSeconds { get; set; } = 5;

    /// <summary>The path probed on each upstream; the node answers it anonymously on both listeners.</summary>
    public string HealthCheckPath { get; set; } = "/health/live";

    /// <summary>Seconds between re-reads of the tenant hostnames table for routes added or changed elsewhere.</summary>
    public int RouteRefreshSeconds { get; set; } = 30;

    /// <summary>
    /// PEM file of the CA that issued the upstreams' TLS certificates, resolved against the
    /// application base directory when relative. Empty means the system trust store, unless a
    /// route pins a key or the dangerous flag applies.
    /// </summary>
    public string UpstreamCaCertificatePath { get; set; } = string.Empty;

    /// <summary>
    /// Accept any certificate from an upstream on loopback. Refused at startup when any
    /// <c>https://</c> route in <see cref="Routes"/> is not loopback; a database route that
    /// is not loopback never gets this treatment, whatever the flag says.
    /// </summary>
    public bool DangerousAcceptAnyUpstreamCertificate { get; set; }

    /// <summary>The shortest health probe interval honoured.</summary>
    public const int MinimumHealthCheckIntervalSeconds = 1;

    /// <summary>
    /// The problems with this section, each a sentence naming the value; empty when the
    /// section is usable. <paramref name="baseDirectory"/>, when given, is where a relative
    /// <see cref="UpstreamCaCertificatePath"/> must exist.
    /// </summary>
    public IReadOnlyList<string> Validate(string? baseDirectory = null)
    {
        var problems = new List<string>();
        if (HealthCheckIntervalSeconds < MinimumHealthCheckIntervalSeconds)
            problems.Add($"Ingress.HealthCheckIntervalSeconds must be at least {MinimumHealthCheckIntervalSeconds}.");
        if (HealthCheckTimeoutSeconds < 1)
            problems.Add("Ingress.HealthCheckTimeoutSeconds must be at least 1.");
        if (RouteRefreshSeconds < 1)
            problems.Add("Ingress.RouteRefreshSeconds must be at least 1.");
        if (string.IsNullOrWhiteSpace(HealthCheckPath) || !HealthCheckPath.StartsWith('/'))
            problems.Add("Ingress.HealthCheckPath must be an absolute path such as /health/live.");
        if (!string.IsNullOrWhiteSpace(UpstreamCaCertificatePath) && baseDirectory != null)
        {
            var path = Path.IsPathRooted(UpstreamCaCertificatePath) ? UpstreamCaCertificatePath : Path.Combine(baseDirectory, UpstreamCaCertificatePath);
            if (!File.Exists(path))
                problems.Add($"Ingress.UpstreamCaCertificatePath '{UpstreamCaCertificatePath}' does not exist.");
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < Routes.Count; i++)
        {
            var route = Routes[i] ?? new IngressRouteConfig();
            var where = $"Ingress.Routes[{i}]";
            var host = IngressRouteConfig.NormalizeHost(route.Host);
            if (host == null)
                problems.Add($"{where}.Host '{route.Host}' is not a bare hostname.");
            else if (!seen.Add(host))
                problems.Add($"{where}.Host '{host}' is listed more than once.");

            if (!IngressRouteConfig.TryParseUpstream(route.Upstream, out var upstream))
                problems.Add($"{where}.Upstream '{route.Upstream}' is not an absolute http:// or https:// address.");
            else if (DangerousAcceptAnyUpstreamCertificate && IsHttps(upstream) && !upstream.IsLoopback)
                problems.Add($"{where}.Upstream '{route.Upstream}' is not loopback; Ingress.DangerousAcceptAnyUpstreamCertificate is refused for it. Pin the node's key or set Ingress.UpstreamCaCertificatePath.");

            if (!string.IsNullOrWhiteSpace(route.PlainHttpUpstream))
            {
                if (!IngressRouteConfig.TryParseUpstream(route.PlainHttpUpstream, out var plain))
                    problems.Add($"{where}.PlainHttpUpstream '{route.PlainHttpUpstream}' is not an absolute http:// or https:// address.");
                else if (DangerousAcceptAnyUpstreamCertificate && IsHttps(plain) && !plain.IsLoopback)
                    problems.Add($"{where}.PlainHttpUpstream '{route.PlainHttpUpstream}' is not loopback; Ingress.DangerousAcceptAnyUpstreamCertificate is refused for it.");
            }

            if (!string.IsNullOrWhiteSpace(route.PinnedSpki) && IngressRouteConfig.NormalizePin(route.PinnedSpki) == null)
                problems.Add($"{where}.PinnedSpki is not a SHA-256 SPKI pin (64 hex characters).");
        }
        return problems;
    }

    /// <summary>Whether <paramref name="upstream"/> is reached over TLS.</summary>
    public static bool IsHttps(Uri upstream)
        => string.Equals(upstream.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// One configured route: requests for <see cref="Host"/> go to <see cref="Upstream"/>, and
/// requests that arrived on the plain-HTTP listener go to <see cref="PlainHttpUpstream"/>
/// when it is set (the node's own plain-HTTP listener, so revocation URLs on the tenant's
/// name reach that node's CRL and OCSP without a redirect), else to <see cref="Upstream"/>.
/// </summary>
public class IngressRouteConfig
{
    /// <summary>The DNS name requests arrive for; the public domain or a tenant hostname.</summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>The node's address, <c>https://host:port</c> or <c>http://host:port</c>.</summary>
    public string Upstream { get; set; } = string.Empty;

    /// <summary>Where requests from the plain-HTTP listener go, when the node has a plain-HTTP listener of its own; null means <see cref="Upstream"/>.</summary>
    public string? PlainHttpUpstream { get; set; }

    /// <summary>
    /// SHA-256 over the node's TLS certificate SubjectPublicKeyInfo, hex, as the signer pins
    /// are written. When set, the upstream's certificate is accepted by this pin and nothing
    /// else; a reissued node certificate needs a new pin. Null means the shared CA or the
    /// system trust store decides.
    /// </summary>
    public string? PinnedSpki { get; set; }

    /// <summary>
    /// The host in the form the route table keys by: trimmed, lower-case, no trailing dot;
    /// null when blank or not a bare name (a scheme, a port, a path or a wildcard).
    /// </summary>
    public static string? NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0 || h.Contains("://") || h.Contains('/') || h.Contains(':') || h.Contains('*') || h.Contains(' '))
            return null;
        return h;
    }

    /// <summary>Parses an upstream address: absolute, <c>http</c> or <c>https</c>, with a host.</summary>
    public static bool TryParseUpstream(string? value, out Uri upstream)
    {
        upstream = null!;
        if (string.IsNullOrWhiteSpace(value)) return false;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var parsed)) return false;
        if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps) return false;
        if (string.IsNullOrEmpty(parsed.Host)) return false;
        upstream = parsed;
        return true;
    }

    /// <summary>
    /// A configured pin in canonical form: an optional <c>sha256:</c> prefix, colons and
    /// whitespace dropped, lower-case; null when it is not 32 hex bytes.
    /// </summary>
    public static string? NormalizePin(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return null;
        var value = configured.Trim();
        if (value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
            value = value["sha256:".Length..];
        value = value.Replace(":", string.Empty).Replace(" ", string.Empty).ToLowerInvariant();
        if (value.Length != 64) return null;
        foreach (var c in value)
        {
            if (!Uri.IsHexDigit(c)) return null;
        }
        return value;
    }
}
