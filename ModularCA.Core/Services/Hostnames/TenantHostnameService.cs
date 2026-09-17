using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>
/// Manages the names a tenant is reached by: validates and records them, has the endpoint
/// certificate issued from the tenant's chosen CA, and keeps the listener's cache current.
/// </summary>
public sealed class TenantHostnameService(
    ModularCADbContext db,
    SystemConfig config,
    ITenantHostnameCertificateIssuer issuer,
    TenantHostnameCertificateCache cache,
    TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    // One RFC 1123 label: letters, digits and inner hyphens, at most 63 characters.
    private static readonly Regex Label = new("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.Compiled);

    /// <summary>
    /// The canonical form of a hostname: trimmed, lower-case, no trailing dot. Refuses anything
    /// that is not a plain DNS name: IP literals, wildcards, a scheme, a port or a path, or a
    /// label with characters a TLS client would refuse in a certificate (an underscore, say).
    /// </summary>
    /// <exception cref="InvalidOperationException">The value is not a usable DNS name.</exception>
    public static string NormalizeHostname(string? raw)
    {
        var host = PublicNameResolver.Normalize(raw)
            ?? throw new InvalidOperationException("A hostname is required.");
        if (host.Contains("://") || host.Contains('/') || host.Contains(':'))
            throw new InvalidOperationException("Enter a bare hostname: no scheme, port or path.");
        if (host.Contains('*'))
            throw new InvalidOperationException("Wildcards are not allowed; each name gets its own certificate.");
        if (host.Length > 253)
            throw new InvalidOperationException("A hostname may not exceed 253 characters.");
        var kind = Uri.CheckHostName(host);
        if (kind is UriHostNameType.IPv4 or UriHostNameType.IPv6)
            throw new InvalidOperationException("Enter a DNS name, not an IP address.");
        if (kind != UriHostNameType.Dns || !host.Split('.').All(Label.IsMatch))
            throw new InvalidOperationException($"'{host}' is not a valid DNS name.");
        return host;
    }

    /// <summary>The tenant's hostnames with their issuing CA and certificate, alphabetically.</summary>
    public Task<List<TenantHostnameEntity>> ListAsync(Guid tenantId, CancellationToken cancellation = default)
        => db.TenantHostnames.AsNoTracking().Include(h => h.IssuingCa).Include(h => h.Certificate)
            .Where(h => h.TenantId == tenantId).OrderBy(h => h.Hostname).ToListAsync(cancellation);

    /// <summary>One hostname with its issuing CA and certificate, or null.</summary>
    public Task<TenantHostnameEntity?> GetAsync(Guid id, CancellationToken cancellation = default)
        => db.TenantHostnames.AsNoTracking().Include(h => h.IssuingCa).Include(h => h.Certificate)
            .FirstOrDefaultAsync(h => h.Id == id, cancellation);

    /// <summary>
    /// Adds a hostname to the tenant and issues its certificate. The name must be new across the
    /// whole system and must not be one the listener already answers by another rule: the public
    /// domain, or the mTLS and EST subdomains. If issuance fails the name is not kept, so the
    /// table never lists a name the listener cannot serve.
    /// </summary>
    /// <exception cref="InvalidOperationException">Validation failed or the certificate could not be issued.</exception>
    public async Task<TenantHostnameEntity> CreateAsync(Guid tenantId, string? hostname, Guid issuingCaId, string? notes, CancellationToken cancellation = default)
    {
        var host = NormalizeHostname(hostname);
        foreach (var (reserved, what) in ReservedNames())
        {
            if (string.Equals(reserved, host, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"'{host}' is {what}; it cannot also be a tenant hostname.");
        }
        if (await db.TenantHostnames.AnyAsync(h => h.Hostname == host, cancellation))
            throw new InvalidOperationException($"'{host}' is already in use.");

        var ca = await db.CertificateAuthorities.AsNoTracking().FirstOrDefaultAsync(c => c.Id == issuingCaId, cancellation)
            ?? throw new InvalidOperationException("Choose one of the tenant's CAs to issue the certificate.");
        if (ca.TenantId != tenantId)
            throw new InvalidOperationException("The issuing CA must belong to this tenant.");
        if (ca.IsSshCa)
            throw new InvalidOperationException("An SSH CA cannot issue a TLS certificate.");
        if (!ca.IsEnabled || ca.IsDeleted || ca.CertificateId == null)
            throw new InvalidOperationException($"CA '{ca.Label ?? ca.Name}' cannot issue right now.");

        var entity = new TenantHostnameEntity
        {
            TenantId = tenantId,
            Hostname = host,
            IssuingCaId = issuingCaId,
            Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim(),
            CreatedAt = _time.GetUtcNow().UtcDateTime,
        };
        db.TenantHostnames.Add(entity);
        await db.SaveChangesAsync(cancellation);

        try
        {
            await issuer.IssueAsync(entity, cancellation);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            db.TenantHostnames.Remove(entity);
            await db.SaveChangesAsync(cancellation);
            cache.Reload();
            throw new InvalidOperationException($"'{host}' was not added: {ex.Message}", ex);
        }
        return (await GetAsync(entity.Id, cancellation))!;
    }

    /// <summary>Issues a new certificate for the hostname now, superseding the current one.</summary>
    /// <exception cref="KeyNotFoundException">No such hostname.</exception>
    /// <exception cref="InvalidOperationException">Issuance was refused.</exception>
    public async Task<CertificateEntity> ReissueAsync(Guid id, CancellationToken cancellation = default)
    {
        var entity = await db.TenantHostnames.AsNoTracking().FirstOrDefaultAsync(h => h.Id == id, cancellation)
            ?? throw new KeyNotFoundException("Hostname not found.");
        return await issuer.IssueAsync(entity, cancellation);
    }

    /// <summary>Removes the hostname: revokes its certificate, deletes its key file and its row, and stops serving it.</summary>
    /// <exception cref="KeyNotFoundException">No such hostname.</exception>
    public async Task DeleteAsync(Guid id, CancellationToken cancellation = default)
    {
        var entity = await db.TenantHostnames.FirstOrDefaultAsync(h => h.Id == id, cancellation)
            ?? throw new KeyNotFoundException("Hostname not found.");
        await issuer.RetireAsync(entity, cancellation);
        db.TenantHostnames.Remove(entity);
        await db.SaveChangesAsync(cancellation);
        cache.Reload();
    }

    /// <summary>Names the listener already answers by a rule of its own, with what each is.</summary>
    private IEnumerable<(string Name, string What)> ReservedNames()
    {
        var publicDomain = PublicNameResolver.Normalize(config.Https.PublicDomain);
        if (publicDomain != null) yield return (publicDomain, "the console's public hostname");
        var mtls = PublicNameResolver.Normalize(SubdomainUtil.ResolveFqdn(config.Mtls.AuthSubdomain, config.Https.PublicDomain));
        if (mtls != null) yield return (mtls, "the mTLS sign-in name");
        var est = PublicNameResolver.Normalize(SubdomainUtil.ResolveFqdn(config.Est.AuthSubdomain, config.Https.PublicDomain));
        if (est != null) yield return (est, "the EST client-certificate name");
    }
}
