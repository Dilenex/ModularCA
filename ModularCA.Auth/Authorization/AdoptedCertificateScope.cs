using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// The CA an adopted certificate belongs to. Every other certificate names its CA through its
/// signing profile; a certificate adopted from outside (<see cref="CertificateEntity.AdoptedAt"/>)
/// has none, and belongs to the CA whose current certificate verified it, which adoption stored
/// in <see cref="CertificateEntity.IssuerCertificateId"/>. Without this the CA-scoped revocation
/// endpoints could not place an adopted certificate under any CA, and only a caller with the
/// capability at system scope could revoke it.
/// <para>
/// It answers for adopted rows only. A row with neither a signing profile nor an adoption mark
/// keeps the behaviour it had.
/// </para>
/// </summary>
public static class AdoptedCertificateScope
{
    /// <summary>
    /// The CA and space of adopted certificate <paramref name="certificate"/>, or null when the
    /// row is not an adopted one or its issuer is no CA's current certificate.
    /// </summary>
    public static async Task<(Guid CaId, Guid? SpaceId)?> CaOfAsync(ModularCADbContext db, CertificateEntity? certificate)
    {
        ArgumentNullException.ThrowIfNull(db);
        if (certificate?.AdoptedAt == null || certificate.SigningProfileId != null || certificate.IssuerCertificateId is not Guid issuer)
            return null;
        var ca = await db.CertificateAuthorities.AsNoTracking().IgnoreQueryFilters()
            .Where(c => c.CertificateId == issuer)
            .Select(c => new { c.Id, c.SpaceId })
            .FirstOrDefaultAsync();
        return ca == null ? null : (ca.Id, ca.SpaceId);
    }
}
