using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>
/// A name this process answers to for a given tenant: the console's public domain, or one of the
/// tenant's own hostnames.
/// </summary>
/// <param name="Host">The name, lower-case, without trailing dot.</param>
/// <param name="IsPublicDomain">True when the name is <c>Https.PublicDomain</c>.</param>
/// <param name="TenantHostname">The tenant hostname row when the name is one; null for the public domain.</param>
public sealed record KnownHostname(string Host, bool IsPublicDomain, TenantHostnameEntity? TenantHostname);

/// <summary>
/// Decides which name to advertise in URLs that point back at this service. A request's Host
/// header is used only when it is a name this process is known by for the tenant in question;
/// anything else falls back to the configured public domain, so an arbitrary Host header can
/// never steer a client somewhere else.
/// </summary>
public interface IPublicNameResolver
{
    /// <summary>
    /// The known name that <paramref name="host"/> is for <paramref name="tenantId"/>, or null. The
    /// public domain is known for every tenant; a tenant hostname only for its own tenant.
    /// </summary>
    Task<KnownHostname?> ResolveAsync(string? host, Guid tenantId, CancellationToken cancellation = default);

    /// <summary>
    /// The HTTPS base URL (no trailing slash) to advertise to a client whose request arrived on
    /// <paramref name="requestHost"/>: that host when it is known for the tenant, else the public one.
    /// </summary>
    Task<string> BaseUrlForRequestAsync(string? requestHost, Guid tenantId, CancellationToken cancellation = default);

    /// <summary>
    /// The HTTPS base URL derived from a realm binding's service principal (<c>HTTP/host</c>): the
    /// principal's host when it is known for the tenant, else the public one. For callers that
    /// have no request, such as readiness and the setup kit.
    /// </summary>
    Task<string> BaseUrlForServicePrincipalAsync(string? servicePrincipal, Guid tenantId, CancellationToken cancellation = default);

    /// <summary>The HTTPS base URL for a known name, with the public port rule; the public base URL when null.</summary>
    string BaseUrl(string? knownHost);
}

/// <summary>Resolves names against <c>Https.PublicDomain</c> and the <c>TenantHostnames</c> table.</summary>
public sealed class PublicNameResolver(ModularCADbContext db, SystemConfig config) : IPublicNameResolver
{
    /// <summary>
    /// The host part of a Kerberos service principal such as <c>HTTP/ca.example.test</c> or
    /// <c>HTTP/ca.example.test@REALM</c>, lower-case without trailing dot; null when there is none.
    /// </summary>
    public static string? HostFromServicePrincipal(string? servicePrincipal)
    {
        if (string.IsNullOrWhiteSpace(servicePrincipal)) return null;
        var spn = servicePrincipal.Trim();
        var slash = spn.IndexOf('/');
        var host = slash >= 0 ? spn[(slash + 1)..] : spn;
        var at = host.IndexOf('@');
        if (at >= 0) host = host[..at];
        // A port suffix (HTTP/host:8443) is legal in an SPN; the name is what matters here.
        var colon = host.IndexOf(':');
        if (colon >= 0) host = host[..colon];
        return Normalize(host);
    }

    /// <summary>Lower-cases and strips the trailing dot; null for blank input.</summary>
    public static string? Normalize(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        return h.Length == 0 ? null : h;
    }

    /// <inheritdoc />
    public async Task<KnownHostname?> ResolveAsync(string? host, Guid tenantId, CancellationToken cancellation = default)
    {
        var h = Normalize(host);
        if (h == null) return null;

        var publicDomain = Normalize(config.Https.PublicDomain);
        if (publicDomain != null && string.Equals(h, publicDomain, StringComparison.Ordinal))
            return new KnownHostname(publicDomain, true, null);

        if (tenantId == Guid.Empty) return null;
        var row = await db.TenantHostnames.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Hostname == h && t.TenantId == tenantId, cancellation);
        return row == null ? null : new KnownHostname(row.Hostname, false, row);
    }

    /// <inheritdoc />
    public async Task<string> BaseUrlForRequestAsync(string? requestHost, Guid tenantId, CancellationToken cancellation = default)
        => BaseUrl((await ResolveAsync(requestHost, tenantId, cancellation))?.Host);

    /// <inheritdoc />
    public async Task<string> BaseUrlForServicePrincipalAsync(string? servicePrincipal, Guid tenantId, CancellationToken cancellation = default)
        => BaseUrl((await ResolveAsync(HostFromServicePrincipal(servicePrincipal), tenantId, cancellation))?.Host);

    /// <inheritdoc />
    public string BaseUrl(string? knownHost)
        => string.IsNullOrWhiteSpace(knownHost) ? config.Https.GetPublicHttpsBaseUrl() : config.Https.GetHttpsBaseUrlFor(knownHost);
}
