using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Helpers;

/// <summary>
/// The issuer chain a PKCS#12 carries beside an end-entity certificate, and the CA the
/// certificate belongs to. Shared by the stored-key export and the held-key delivery so both
/// files carry the same chain for the same certificate.
/// </summary>
/// <param name="Chain">DER-encoded issuer certificates, nearest issuer first.</param>
/// <param name="CaId">The issuing CA, when the signing profile names one.</param>
/// <param name="TenantId">The issuing CA's tenant.</param>
public sealed record IssuerChain(List<byte[]> Chain, Guid? CaId, Guid? TenantId);

/// <summary>
/// Walks the issuer chain from a certificate's signing profile.
/// </summary>
public static class IssuerChainResolver
{
    /// <summary>
    /// Resolves the chain for <paramref name="certEntity"/>, whose <see cref="CertificateEntity.SigningProfile"/>
    /// must be loaded. The direct issuer is always included, and the root only when it is the
    /// direct issuer, so a PKCS#12 carries what a client needs to present and not the trust
    /// anchor it should already hold. With <paramref name="includeChain"/> false only the CA and
    /// tenant are resolved.
    /// </summary>
    public static async Task<IssuerChain> ResolveAsync(ModularCADbContext db, CertificateEntity certEntity, bool includeChain)
    {
        var chain = new List<byte[]>();
        Guid? caId = null;
        Guid? tenantId = null;
        var issuerId = certEntity.SigningProfile?.IssuerId;
        if (issuerId == null)
            return new IssuerChain(chain, caId, tenantId);

        var directIssuerCa = await db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.CertificateId == issuerId);
        caId = directIssuerCa?.Id;
        tenantId = directIssuerCa?.TenantId;
        if (!includeChain)
            return new IssuerChain(chain, caId, tenantId);

        var directIssuerIsRoot = directIssuerCa?.ParentCaId == null;
        var visited = new HashSet<Guid>();
        while (issuerId.HasValue && visited.Add(issuerId.Value))
        {
            var issuerEntity = await db.Certificates
                .Include(c => c.SigningProfile)
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
            if (issuerEntity == null) break;

            var issuerCa = await db.CertificateAuthorities
                .AsNoTracking()
                .FirstOrDefaultAsync(ca => ca.CertificateId == issuerId.Value);

            // Skip the root when intermediates exist; include it when it is the direct issuer.
            if (issuerCa?.ParentCaId == null && !directIssuerIsRoot)
                break;

            chain.Add(CertificateUtil.ParseFromPem(issuerEntity.Pem).GetEncoded());

            if (issuerCa?.ParentCaId == null)
                break;

            issuerId = issuerEntity.SigningProfile?.IssuerId;
        }
        return new IssuerChain(chain, caId, tenantId);
    }
}
