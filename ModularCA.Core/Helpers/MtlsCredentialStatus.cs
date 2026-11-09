using System.Linq.Expressions;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;

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

    /// <summary>
    /// A CA certificate on the issuer chain above the certificate, the issuing CA's own or one
    /// further up, is revoked or on hold (see <see cref="MtlsIssuerStanding"/>).
    /// </summary>
    IssuerRevoked,

    /// <summary>
    /// A CA on the issuer chain above the certificate, the issuing CA or one further up, is
    /// disabled or deleted (see <see cref="MtlsIssuerStanding"/>).
    /// </summary>
    IssuerDisabled,
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
        MtlsCredentialRefusal.IssuerRevoked => "mtls_issuer_revoked",
        MtlsCredentialRefusal.IssuerDisabled => "mtls_issuer_disabled",
        _ => null,
    };
}

/// <summary>
/// The one definition of an mTLS credential that may authenticate or count as an active factor:
/// the credential is unrevoked and unexpired, the certificate it was issued as is on record and
/// not revoked (a certificate on hold counts as revoked until it is released), AND every CA above
/// that certificate is in good standing: not revoked or on hold, not disabled, not deleted
/// (<see cref="MtlsIssuerStanding"/>).
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
/// <para>
/// The certificate's own status says nothing about its issuer. A CA that is revoked, held,
/// disabled or deleted signs nothing more, but the client certificates it had already issued kept
/// signing in, because the chain check anchors at the issuing CA's certificate and never asks
/// about it or the CAs above it.
/// </para>
/// </summary>
public static class MtlsCredentialStatus
{
    /// <summary>
    /// Credentials that authenticate and count as an active factor at <paramref name="nowUtc"/>,
    /// given the standing of the CAs read by <see cref="MtlsIssuerStanding.LoadAsync"/>. A
    /// credential is left out when its signing CA, or the CA certificate its certificate was
    /// issued under, is refused by <paramref name="issuers"/>. Most callers want
    /// <see cref="UsableAsync"/>.
    /// </summary>
    /// <param name="nowUtc">The instant expiry is judged at.</param>
    /// <param name="issuers">The standing of every CA and CA certificate, read for this query.</param>
    public static Expression<Func<MtlsCredentialEntity, bool>> Usable(DateTime nowUtc, MtlsIssuerStanding issuers)
    {
        var refusedCas = issuers.RefusedCaIds;
        var refusedCaCertificates = issuers.RefusedCaCertificateIds;
        return c => !c.IsRevoked && c.ExpiresAt > nowUtc && c.CertificateId != null && !c.Certificate!.Revoked
            && !refusedCas.Contains(c.SigningCaId)
            && (c.Certificate.IssuerCertificateId == null || !refusedCaCertificates.Contains(c.Certificate.IssuerCertificateId.Value));
    }

    /// <summary>
    /// Reads the standing of every CA (<see cref="MtlsIssuerStanding.LoadAsync"/>) and returns
    /// <see cref="Usable(DateTime, MtlsIssuerStanding)"/> for it: the credentials that
    /// authenticate and count as an active factor at <paramref name="nowUtc"/>.
    /// </summary>
    /// <param name="db">The context the standing is read through.</param>
    /// <param name="nowUtc">The instant expiry is judged at.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<Expression<Func<MtlsCredentialEntity, bool>>> UsableAsync(
        ModularCADbContext db, DateTime nowUtc, CancellationToken ct = default)
        => Usable(nowUtc, await MtlsIssuerStanding.LoadAsync(db, ct));

    /// <summary>
    /// Finds the credential whose thumbprint is <paramref name="thumbprint"/> (and that belongs to
    /// <paramref name="userId"/> when given), with its user and certificate loaded, and says whether
    /// it authenticates. An unrevoked, unexpired credential is preferred. Failing that, an unexpired
    /// credential that was revoked while its certificate is revoked is returned with
    /// <see cref="MtlsCredentialRefusal.CertificateRevoked"/>, so a certificate revoked through the
    /// revocation service (which revokes the credential row too) is refused as revoked rather than
    /// as unknown. A null credential means no such credential exists, or it was revoked on its own
    /// while its certificate stayed good. An unrevoked credential whose certificate is good is
    /// still refused, with <see cref="MtlsCredentialRefusal.IssuerRevoked"/> or
    /// <see cref="MtlsCredentialRefusal.IssuerDisabled"/>, when a CA above the certificate is not
    /// in good standing (<see cref="MtlsIssuerStanding"/>).
    /// </summary>
    /// <param name="db">The context to read through.</param>
    /// <param name="thumbprint">SHA-256 thumbprint of the presented client certificate.</param>
    /// <param name="userId">The account the credential must belong to, or null for any account.</param>
    /// <param name="nowUtc">The instant expiry is judged at.</param>
    /// <param name="ct">Cancellation token.</param>
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
        var issuers = await MtlsIssuerStanding.LoadAsync(db, ct);
        return new MtlsCredentialMatch(credential,
            issuers.RefusalFor(credential.SigningCaId, credential.Certificate.IssuerCertificateId));
    }

    /// <summary>
    /// Whether a client certificate that has already chained to a trust anchor is in good standing
    /// by this instance's own records, for a gate that admits any trusted certificate rather than
    /// an enrolled credential (the <c>Mtls.RequiredPaths</c> gate).
    /// <para>
    /// Returns null when <paramref name="issuer"/> is not a CA certificate of this instance: the
    /// certificate comes from an external anchor this instance keeps no status for. Otherwise the
    /// certificate is looked up by serial number under that issuer (a legacy row with no issuer
    /// link counts too, so the check fails closed for it, as EST re-enrollment's does) and
    /// refused as <see cref="MtlsCredentialRefusal.CertificateRevoked"/> when a matching row is
    /// revoked or on hold, as <see cref="MtlsCredentialRefusal.CertificateRecordMissing"/> when no
    /// row matches (this instance's CA signed it, yet nothing shows it is still good), and as
    /// <see cref="MtlsCredentialRefusal.IssuerRevoked"/> or
    /// <see cref="MtlsCredentialRefusal.IssuerDisabled"/> when a CA above it is not in good
    /// standing (<see cref="MtlsIssuerStanding"/>). <see cref="MtlsCredentialRefusal.None"/> means
    /// it is good.
    /// </para>
    /// </summary>
    /// <param name="db">The context to read through.</param>
    /// <param name="certificate">The presented client certificate.</param>
    /// <param name="issuer">The certificate that issued it in the validated chain, or null when the chain has only the certificate.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<MtlsCredentialRefusal?> PresentedCertificateRefusalAsync(
        ModularCADbContext db, X509Certificate2 certificate, X509Certificate2? issuer, CancellationToken ct = default)
    {
        if (issuer == null)
            return null;

        var issuerSerial = CertificateUtil.NormalizeSerialForLookup(issuer.SerialNumber);
        var issuerRows = await db.Certificates.AsNoTracking()
            .Where(c => c.IsCA && c.SerialNumber == issuerSerial)
            .Select(c => new { c.CertificateId, c.RawCertificate, c.Pem })
            .ToListAsync(ct);
        var issuerId = issuerRows
            .Where(r => (r.RawCertificate ?? DerFromPem(r.Pem))?.AsSpan().SequenceEqual(issuer.RawData) == true)
            .Select(r => (Guid?)r.CertificateId)
            .FirstOrDefault();
        if (issuerId is not Guid issuerCertificateId)
            return null;

        var serial = CertificateUtil.NormalizeSerialForLookup(certificate.SerialNumber);
        var rows = await db.Certificates.AsNoTracking()
            .Where(c => c.SerialNumber == serial && (c.IssuerCertificateId == issuerCertificateId || c.IssuerCertificateId == null))
            .Select(c => new { c.Revoked })
            .ToListAsync(ct);
        if (rows.Count == 0)
            return MtlsCredentialRefusal.CertificateRecordMissing;
        if (rows.Any(r => r.Revoked))
            return MtlsCredentialRefusal.CertificateRevoked;

        return (await MtlsIssuerStanding.LoadAsync(db, ct)).RefusalFor(null, issuerCertificateId);
    }

    /// <summary>The DER of a stored PEM certificate, or null when it does not parse.</summary>
    private static byte[]? DerFromPem(string pem)
    {
        try { return string.IsNullOrWhiteSpace(pem) ? null : CertificateUtil.ParseFromPem(pem).GetEncoded(); }
        catch { return null; }
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
