using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Helpers;

/// <summary>Why an unexpired mTLS credential found for a presented client certificate does not authenticate.</summary>
public enum MtlsCredentialRefusal
{
    /// <summary>The credential authenticates.</summary>
    None,

    /// <summary>
    /// The X.509 certificate behind the credential is revoked or on hold. The credential row itself
    /// may be revoked too: a permanent revocation revokes both.
    /// </summary>
    CertificateRevoked,

    /// <summary>
    /// The credential no longer points at a certificate record (its row was deleted and the foreign
    /// key set to null), so the certificate's revocation status cannot be read.
    /// </summary>
    CertificateRecordMissing,
}

/// <summary>A credential found for a presented client certificate, and whether it authenticates.</summary>
/// <param name="Credential">The unexpired credential with this thumbprint (see <see cref="MtlsCredentialStatus.FindForAuthenticationAsync"/>), or null when there is none.</param>
/// <param name="Refusal">Why <paramref name="Credential"/> does not authenticate; <see cref="MtlsCredentialRefusal.None"/> when it does.</param>
public readonly record struct MtlsCredentialMatch(MtlsCredentialEntity? Credential, MtlsCredentialRefusal Refusal)
{
    /// <summary>A credential was found and it authenticates.</summary>
    public bool Authenticates => Credential != null && Refusal == MtlsCredentialRefusal.None;

    /// <summary>The audit reason for a refused credential, or null when nothing was refused.</summary>
    public string? AuditReason => Refusal switch
    {
        MtlsCredentialRefusal.CertificateRevoked => "mtls_certificate_revoked",
        MtlsCredentialRefusal.CertificateRecordMissing => "mtls_certificate_record_missing",
        _ => null,
    };
}

/// <summary>
/// The one definition of an mTLS credential that may authenticate or count as an active factor:
/// the credential is unrevoked and unexpired, AND the certificate it was issued as is on record and
/// not revoked (a certificate on hold counts as revoked until it is released).
/// <para>
/// <see cref="MtlsCredentialEntity.IsRevoked"/> alone is not enough. Revoking the certificate through
/// the certificate pages, ACME, the integration API or a CA ceremony changes the certificate row, and
/// several of those paths never touch the credential row, so a revoked certificate kept signing in.
/// Reading the certificate's own status covers every path, present and future.
/// </para>
/// <para>
/// A credential with no certificate record does not authenticate. Enrolment always records the
/// certificate; the link is null only when that row was deleted, and then nothing can show that the
/// certificate is still good.
/// </para>
/// </summary>
public static class MtlsCredentialStatus
{
    /// <summary>Credentials that authenticate and count as an active factor at <paramref name="nowUtc"/>.</summary>
    public static Expression<Func<MtlsCredentialEntity, bool>> Usable(DateTime nowUtc) =>
        c => !c.IsRevoked && c.ExpiresAt > nowUtc && c.CertificateId != null && !c.Certificate!.Revoked;

    /// <summary>
    /// Finds the credential whose thumbprint is <paramref name="thumbprint"/> (and that belongs to
    /// <paramref name="userId"/> when given), with its user and certificate loaded, and says whether
    /// it authenticates. An unrevoked, unexpired credential is preferred. Failing that, an unexpired
    /// credential that was revoked while its certificate is revoked is returned with
    /// <see cref="MtlsCredentialRefusal.CertificateRevoked"/>, so a certificate revoked through the
    /// revocation service (which revokes the credential row too) is refused as revoked rather than
    /// as unknown. A null credential means no such credential exists, or it was revoked on its own
    /// while its certificate stayed good.
    /// </summary>
    public static async Task<MtlsCredentialMatch> FindForAuthenticationAsync(
        ModularCADbContext db, string thumbprint, Guid? userId, DateTime nowUtc, CancellationToken ct = default)
    {
        var query = db.MtlsCredentials
            .Include(c => c.User)
            .Include(c => c.Certificate)
            .Where(c => c.Thumbprint == thumbprint && c.ExpiresAt > nowUtc);
        if (userId is Guid uid)
            query = query.Where(c => c.UserId == uid);

        var credential = await query.Where(c => !c.IsRevoked).FirstOrDefaultAsync(ct);
        if (credential == null)
        {
            var revoked = await query
                .Where(c => c.IsRevoked && c.CertificateId != null && c.Certificate!.Revoked)
                .OrderByDescending(c => c.RevokedAt)
                .FirstOrDefaultAsync(ct);
            return revoked == null
                ? new MtlsCredentialMatch(null, MtlsCredentialRefusal.None)
                : new MtlsCredentialMatch(revoked, MtlsCredentialRefusal.CertificateRevoked);
        }
        if (credential.CertificateId == null || credential.Certificate == null)
            return new MtlsCredentialMatch(credential, MtlsCredentialRefusal.CertificateRecordMissing);
        if (credential.Certificate.Revoked)
            return new MtlsCredentialMatch(credential, MtlsCredentialRefusal.CertificateRevoked);
        return new MtlsCredentialMatch(credential, MtlsCredentialRefusal.None);
    }

    /// <summary>
    /// The accounts holding an unrevoked mTLS credential issued as <paramref name="certificateId"/>,
    /// expired or not: the accounts whose sessions that certificate may have opened.
    /// </summary>
    public static async Task<List<Guid>> HoldersOfCertificateAsync(ModularCADbContext db, Guid certificateId, CancellationToken ct = default)
        => await db.MtlsCredentials
            .Where(c => c.CertificateId == certificateId && !c.IsRevoked)
            .Select(c => c.UserId)
            .Distinct()
            .ToListAsync(ct);

    /// <summary>
    /// Marks every unrevoked mTLS credential issued as <paramref name="certificateId"/> revoked at
    /// <paramref name="nowUtc"/>, on the tracked context; the caller saves. Returns how many it marked.
    /// Used when a certificate is revoked permanently; a hold leaves the credential alone so that a
    /// release restores it, and <see cref="Usable"/> refuses it while the hold lasts.
    /// </summary>
    public static async Task<int> MarkRevokedForCertificateAsync(ModularCADbContext db, Guid certificateId, DateTime nowUtc, CancellationToken ct = default)
    {
        var credentials = await db.MtlsCredentials
            .Where(c => c.CertificateId == certificateId && !c.IsRevoked)
            .ToListAsync(ct);
        foreach (var credential in credentials)
        {
            credential.IsRevoked = true;
            credential.RevokedAt = nowUtc;
        }
        return credentials.Count;
    }
}
