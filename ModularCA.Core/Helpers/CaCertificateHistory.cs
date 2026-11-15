using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Keeps <c>CaCertificates</c> the whole history of every CA's certificates
/// (<c>docs/architecture/ca-certificate-renewal.md</c>): a CA's first certificate has a row from
/// the moment the CA is created, and a CA created before the table existed gets one after the
/// next start of the node, once the instance is not in DR mode
/// (<see cref="ModularCA.Core.Services.CaCertificateHistoryService"/>).
/// </summary>
public static class CaCertificateHistory
{
    /// <summary>The id of a certificate's key as the table records it: SHA-256 of its SubjectPublicKeyInfo, lower-case hex. Null when the certificate cannot be read.</summary>
    public static string? KeyIdOf(CertificateEntity row)
    {
        try
        {
            var certificate = row.RawCertificate is { Length: > 0 } ? new X509Certificate(row.RawCertificate) : CertificateUtil.ParseFromPem(row.Pem);
            return Convert.ToHexStringLower(SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(certificate.GetPublicKey()).GetDerEncoded()));
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// The row for a CA's first certificate, to be added in the transaction that creates the CA.
    /// Null when the certificate's key cannot be read; the next start then tries again.
    /// </summary>
    public static CaCertificateEntity? InitialRow(Guid caId, CertificateEntity certificate, DateTime activatedAt, Guid? ceremonyId = null)
        => KeyIdOf(certificate) is { } keyId
            ? new CaCertificateEntity
            {
                CertificateAuthorityId = caId,
                CertificateId = certificate.CertificateId,
                KeyId = keyId,
                Origin = CaCertificateEntity.OriginInitial,
                ActivatedAt = activatedAt,
                CeremonyId = ceremonyId,
            }
            : null;

    /// <summary>
    /// Tells the node's registry of CA certificates the current certificate of every CA whose
    /// certificate was renewed. The keystore files carry the certificate each key was committed
    /// with, so a process that has just started knows a renewed CA by its earlier certificate
    /// until this runs. Returns how many certificates were registered.
    /// </summary>
    public static async Task<int> RegisterRenewedAsync(ModularCADbContext db, ModularCA.Shared.Interfaces.IKeystoreCertificates registry, CancellationToken ct = default)
    {
        var renewed = await (from history in db.CaCertificates.AsNoTracking()
                             join ca in db.CertificateAuthorities.AsNoTracking() on history.CertificateId equals ca.CertificateId
                             join certificate in db.Certificates.AsNoTracking() on history.CertificateId equals certificate.CertificateId
                             where history.SupersededAt == null && history.Origin == CaCertificateEntity.OriginRenewal
                             select certificate.RawCertificate).ToListAsync(ct);
        var registered = 0;
        foreach (var raw in renewed)
        {
            if (raw is not { Length: > 0 })
                continue;
            registry.RegisterRenewedCaCertificate(new X509Certificate(raw));
            registered++;
        }
        return registered;
    }

    /// <summary>
    /// Gives every X.509 CA whose current certificate has no row an <c>Initial</c> one, dated
    /// when the certificate row was created: the CAs made before the table existed, and those
    /// made by bootstrap. It adds rows and changes none, and it can be run again at any time.
    /// A CA whose current certificate already has a row (it was created since, or renewed) is
    /// left as it is. Returns how many rows were added.
    /// </summary>
    public static async Task<int> EnsureInitialRowsAsync(ModularCADbContext db, CancellationToken ct = default)
    {
        var missing = await (from ca in db.CertificateAuthorities.IgnoreQueryFilters()
                             join certificate in db.Certificates on ca.CertificateId equals certificate.CertificateId
                             where !ca.IsSshCa && !db.CaCertificates.Any(h => h.CertificateId == certificate.CertificateId)
                             select new { CaId = ca.Id, Certificate = certificate }).AsNoTracking().ToListAsync(ct);
        var added = 0;
        foreach (var item in missing)
        {
            var created = item.Certificate.CreatedAt == default ? item.Certificate.NotBefore : item.Certificate.CreatedAt;
            if (InitialRow(item.CaId, item.Certificate, created) is not { } row)
                continue;
            db.CaCertificates.Add(row);
            added++;
        }
        if (added > 0)
            await db.SaveChangesAsync(ct);
        return added;
    }
}
