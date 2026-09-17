using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Pkcs;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>Issues, replaces and retires the endpoint TLS certificate of a tenant hostname.</summary>
public interface ITenantHostnameCertificateIssuer
{
    /// <summary>
    /// Issues a fresh certificate and key for the hostname from its issuing CA, stores the key the
    /// way the console's web TLS key is stored, records the certificate on the row, supersedes the
    /// previous one and makes the listener serve the new one. Returns the new certificate row.
    /// </summary>
    /// <exception cref="InvalidOperationException">The CA cannot issue for this hostname, or issuance was refused.</exception>
    Task<CertificateEntity> IssueAsync(TenantHostnameEntity hostname, CancellationToken cancellation = default);

    /// <summary>Revokes the hostname's current certificate and removes its key file. The row is left to the caller.</summary>
    Task RetireAsync(TenantHostnameEntity hostname, CancellationToken cancellation = default);
}

/// <summary>
/// The web TLS issuance path applied to a tenant hostname: the same infrastructure CSR, the same
/// "Web TLS Certificate Profile", a signing profile of the chosen tenant CA, validity from the
/// profile, the key exported to a PKCS#12 file under the web TLS password.
/// </summary>
/// <remarks>
/// The signing profile is the one bootstrap and CA creation link to the web TLS profile for
/// the issuing CA (every CA gets one); when that link is missing, any signing profile whose
/// issuer is the CA serves, so an operator who trimmed the links is not locked out of the
/// feature by a detail they cannot see. There is no third choice: a certificate signed by a CA
/// of another tenant would put that tenant's name on this one's endpoint.
/// </remarks>
public sealed class TenantHostnameCertificateService(
    ModularCADbContext db,
    SystemConfig config,
    ICsrService csrService,
    ICertificateIssuanceService issuance,
    ICertificateRevocationService revocation,
    TenantHostnameCertificateCache cache,
    ILogger<TenantHostnameCertificateService> logger) : ITenantHostnameCertificateIssuer
{
    /// <summary>The cert profile the console's own certificate is issued under; tenant hostnames share it.</summary>
    public const string WebTlsCertProfileName = "Web TLS Certificate Profile";

    /// <inheritdoc />
    public async Task<CertificateEntity> IssueAsync(TenantHostnameEntity hostname, CancellationToken cancellation = default)
    {
        var row = await db.TenantHostnames.FirstOrDefaultAsync(h => h.Id == hostname.Id, cancellation)
            ?? throw new InvalidOperationException("The hostname no longer exists.");

        var ca = await db.CertificateAuthorities.AsNoTracking().FirstOrDefaultAsync(c => c.Id == row.IssuingCaId, cancellation)
            ?? throw new InvalidOperationException("The issuing CA no longer exists.");
        if (ca.TenantId != row.TenantId)
            throw new InvalidOperationException("The issuing CA belongs to another tenant.");
        if (!ca.IsEnabled || ca.IsDeleted)
            throw new InvalidOperationException($"CA '{ca.Label ?? ca.Name}' is disabled.");
        if (ca.CertificateId == null)
            throw new InvalidOperationException($"CA '{ca.Label ?? ca.Name}' has no certificate.");

        var certProfile = await db.CertProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Name == WebTlsCertProfileName, cancellation)
            ?? throw new InvalidOperationException($"'{WebTlsCertProfileName}' is missing. Run bootstrap to seed profiles.");

        var signingProfile = await ResolveSigningProfileAsync(certProfile.Id, ca.CertificateId.Value, cancellation)
            ?? throw new InvalidOperationException($"CA '{ca.Label ?? ca.Name}' has no signing profile to issue with.");

        // Same key handling as the web TLS certificate: an infrastructure CSR whose key pair is
        // returned to the caller and never stored in the database. The SAN is the hostname alone.
        var (csrId, keyPair) = await csrService.GenerateInfrastructureCsrAsync(
            $"CN={row.Hostname}", "ECDSA", 256, certProfile.Id, signingProfile.Id, [$"DNS:{row.Hostname}"]);

        // Validity from the profile, as the scheduled web TLS renewal takes it; the default
        // ceiling enforcement shortens rather than refuses, since a tenant ceiling must not stop
        // the tenant's own endpoint from getting a certificate.
        var result = await issuance.IssueCertificateAsync(csrId, null, null, cancellationToken: cancellation);
        foreach (var warning in result.Warnings)
            logger.LogWarning("Tenant hostname {Host}: issuance warning: {Warning}", row.Hostname, warning);

        var issued = CertificateUtil.ParseFromPem(result.Pem);
        var serial = CertificateUtil.FormatSerialNumber(issued.SerialNumber);
        var certEntity = await db.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial, cancellation)
            ?? throw new InvalidOperationException($"Issued certificate {serial} was not recorded.");

        var caCertEntity = await db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.CertificateId == ca.CertificateId, cancellation);
        var caCert = caCertEntity != null ? CertificateUtil.ParseFromPem(caCertEntity.Pem) : null;
        if (caCert != null)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(X509CertificateLoader.LoadCertificate(caCert.GetEncoded()));
            if (!chain.Build(X509CertificateLoader.LoadCertificate(issued.GetEncoded())))
                throw new InvalidOperationException("The issued certificate does not chain to the issuing CA; not installed.");
        }

        var store = new Pkcs12StoreBuilder().Build();
        var chainEntries = caCert != null
            ? new[] { new X509CertificateEntry(issued), new X509CertificateEntry(caCert) }
            : new[] { new X509CertificateEntry(issued) };
        store.SetKeyEntry(TenantHostnamePfxStore.KeyAlias, new AsymmetricKeyEntry(keyPair.Private), chainEntries);
        TenantHostnamePfxStore.Write(row.Id, store, config.Https.CertificatePassword ?? string.Empty);

        var previous = row.CertificateId;
        row.CertificateId = certEntity.CertificateId;
        await db.SaveChangesAsync(cancellation);
        hostname.CertificateId = certEntity.CertificateId;

        if (previous != null && previous != certEntity.CertificateId)
        {
            try
            {
                await revocation.RevokeCertificateAsync(previous, null, RevocationReason.Superseded);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Tenant hostname {Host}: previous certificate {Id} could not be revoked as superseded; the new one is live.", row.Hostname, previous);
            }
        }

        cache.Reload();
        logger.LogInformation("Tenant hostname {Host}: certificate {Serial} issued by {Ca}, expires {NotAfter:O}.",
            row.Hostname, serial, ca.Label ?? ca.Name, certEntity.NotAfter);
        return certEntity;
    }

    /// <inheritdoc />
    public async Task RetireAsync(TenantHostnameEntity hostname, CancellationToken cancellation = default)
    {
        if (hostname.CertificateId != null)
        {
            try
            {
                await revocation.RevokeCertificateAsync(hostname.CertificateId, null, RevocationReason.CessationOfOperation);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Tenant hostname {Host}: certificate {Id} could not be revoked on removal.", hostname.Hostname, hostname.CertificateId);
            }
        }
        TenantHostnamePfxStore.Delete(hostname.Id);
    }

    /// <summary>
    /// The signing profile linked to the web TLS profile whose issuer is the CA (the default one
    /// first), else any signing profile of the CA. Null when the CA has none.
    /// </summary>
    private async Task<SigningProfileEntity?> ResolveSigningProfileAsync(Guid certProfileId, Guid caCertificateId, CancellationToken cancellation)
    {
        var linked = await db.AllowedCertProfileSigningProfiles.AsNoTracking()
            .Where(l => l.CertProfileId == certProfileId && l.SigningProfile.IssuerId == caCertificateId)
            .Select(l => l.SigningProfile)
            .OrderByDescending(s => s.IsDefault).ThenBy(s => s.Name)
            .FirstOrDefaultAsync(cancellation);
        if (linked != null) return linked;

        return await db.SigningProfiles.AsNoTracking()
            .Where(s => s.IssuerId == caCertificateId)
            .OrderByDescending(s => s.IsDefault).ThenBy(s => s.Name)
            .FirstOrDefaultAsync(cancellation);
    }
}
