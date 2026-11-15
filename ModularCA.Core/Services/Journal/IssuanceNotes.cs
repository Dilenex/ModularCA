using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services.Journal;

/// <summary>
/// What a request learns on its way to an issuance, kept for the moment the certificate is
/// signed, when it goes to the signer for the certificate's journal record
/// (<see cref="IssuanceOrigin"/>). It is kept against the request's database context, which the
/// protocol service, the token service and the issuance service of one request share, so
/// nothing has to be threaded through every call in between and nothing outlives the request.
/// </summary>
/// <remarks>
/// Only identifiers are noted: a token's row id, an order's id, a transaction's id. Never a
/// token, a secret or a hash of one.
/// </remarks>
public static class IssuanceNotes
{
    private sealed class Notes
    {
        public List<IssuanceSpent> Spent { get; } = new();
        public Dictionary<Guid, RequestNote> Requests { get; } = new();
    }

    private sealed record RequestNote(string? Protocol, IssuanceAnswers? Answers, string? Template);

    private static readonly ConditionalWeakTable<DbContext, Notes> Table = new();

    /// <summary>Notes that this request spent a one-time token; the next issuance on the same context records it.</summary>
    /// <param name="db">The request's database context.</param>
    /// <param name="kind">The token's kind (<see cref="TokenKind"/>).</param>
    /// <param name="id">The token's identifier: its row id, never its value.</param>
    /// <param name="use">Which use of the token this was, counted from 1.</param>
    public static void NoteSpent(DbContext db, ulong kind, string id, ulong use)
    {
        var notes = Table.GetOrCreateValue(db);
        lock (notes)
            notes.Spent.Add(new IssuanceSpent(kind, id, Math.Max(1, use)));
    }

    /// <summary>Notes the protocol a request row came in by, what it answers and the template it was made under.</summary>
    public static void NoteRequest(DbContext db, Guid requestId, string? protocol, IssuanceAnswers? answers = null, string? template = null)
    {
        var notes = Table.GetOrCreateValue(db);
        lock (notes)
            notes.Requests[requestId] = new RequestNote(protocol, answers, template);
    }

    /// <summary>
    /// What a protocol's own identifier answers: an ACME order for ACME, an enrollment
    /// transaction for SCEP and CMP, and nothing of its own for a protocol that has no
    /// transaction identifier, where the request row is what was answered.
    /// </summary>
    public static IssuanceAnswers? AnswersFor(string protocol, string? correlation)
    {
        if (string.IsNullOrWhiteSpace(correlation))
            return null;
        return protocol.ToUpperInvariant() switch
        {
            "ACME" => new IssuanceAnswers(AnswersKind.AcmeOrder, correlation),
            "SCEP" or "CMP" => new IssuanceAnswers(AnswersKind.EnrollmentTransaction, correlation),
            _ => null,
        };
    }

    /// <summary>
    /// Builds what the signer is told about the issuance of <paramref name="request"/>, and
    /// clears what was noted for it. A member the node does not know is left out: no
    /// <c>replaces</c> for a request that names no certificate it renews, no owner for a
    /// request nobody's account made.
    /// </summary>
    /// <param name="db">The request's database context.</param>
    /// <param name="request">The request row being issued.</param>
    /// <param name="certProfileId">The certificate profile the certificate is issued under.</param>
    /// <param name="spaceId">The issuing CA's space, when it has one.</param>
    /// <param name="replacesCertificateId">The certificate being reissued, when the caller names one the request row does not.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public static async Task<IssuanceOrigin> TakeAsync(ModularCADbContext db, CertRequestEntity request, Guid? certProfileId, Guid? spaceId,
        Guid? replacesCertificateId = null, CancellationToken cancellationToken = default)
    {
        List<IssuanceSpent>? spent = null;
        RequestNote? note = null;
        if (Table.TryGetValue(db, out var notes))
        {
            lock (notes)
            {
                if (notes.Spent.Count > 0)
                {
                    spent = notes.Spent.ToList();
                    notes.Spent.Clear();
                }
                notes.Requests.Remove(request.Id, out note);
            }
        }

        IssuanceReplaces? replaces = null;
        if ((replacesCertificateId ?? request.RenewalOfCertificateId) is Guid replacedId)
            replaces = await ReplacesAsync(db, replacedId, cancellationToken);

        return new IssuanceOrigin(
            Spent: spent,
            Answers: note?.Answers ?? new IssuanceAnswers(AnswersKind.PendingRequest, request.Id.ToString("D")),
            Replaces: replaces,
            Belongs: new IssuanceBelongs(
                Profile: certProfileId?.ToString("D"),
                Space: spaceId?.ToString("D"),
                OwnerKind: request.RequestorUserId != null ? OwnerKind.User : null,
                Owner: request.RequestorUserId?.ToString("D"),
                Template: note?.Template),
            Protocol: note?.Protocol ?? (request.IsInfrastructureCert ? "Infrastructure" : null),
            Requester: request.RequestorUserId?.ToString("D"));
    }

    /// <summary>The serial and <c>caKey</c> of a certificate that is being replaced; null when its row or its issuer cannot be read.</summary>
    public static async Task<IssuanceReplaces?> ReplacesAsync(ModularCADbContext db, Guid certificateId, CancellationToken cancellationToken = default)
    {
        var replaced = await db.Certificates.AsNoTracking()
            .Where(c => c.CertificateId == certificateId)
            .Select(c => new { c.SerialNumber, c.IssuerCertificateId })
            .FirstOrDefaultAsync(cancellationToken);
        if (replaced == null || string.IsNullOrWhiteSpace(replaced.SerialNumber))
            return null;
        var caKey = await CaKeys.OfCertificateAsync(db, replaced.IssuerCertificateId, cancellationToken);
        if (caKey == null)
            return null;
        try
        {
            return new IssuanceReplaces(new BigInteger(replaced.SerialNumber, 16).ToByteArrayUnsigned(), caKey);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

/// <summary>
/// The journal's name for a CA key: SHA-256 of the public key (SubjectPublicKeyInfo) of the CA
/// certificate. Read from the certificate row and remembered, since a certificate's key never
/// changes.
/// </summary>
public static class CaKeys
{
    private static readonly ConcurrentDictionary<Guid, byte[]> Known = new();

    /// <summary>The <c>caKey</c> of a CA certificate.</summary>
    public static byte[] Of(X509Certificate caCertificate)
        => SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caCertificate.GetPublicKey()).GetDerEncoded());

    /// <summary>The <c>caKey</c> of the CA certificate row <paramref name="caCertificateId"/>; null when the row is missing or does not parse.</summary>
    public static async Task<byte[]?> OfCertificateAsync(ModularCADbContext db, Guid? caCertificateId, CancellationToken cancellationToken = default)
    {
        if (caCertificateId is not Guid id)
            return null;
        if (Known.TryGetValue(id, out var known))
            return known;
        var row = await db.Certificates.AsNoTracking()
            .Where(c => c.CertificateId == id)
            .Select(c => new { c.RawCertificate, c.Pem })
            .FirstOrDefaultAsync(cancellationToken);
        return Remember(id, row?.RawCertificate, row?.Pem);
    }

    /// <summary>As <see cref="OfCertificateAsync"/>, for a caller that cannot wait: inside a save.</summary>
    public static byte[]? OfCertificate(ModularCADbContext db, Guid? caCertificateId)
    {
        if (caCertificateId is not Guid id)
            return null;
        if (Known.TryGetValue(id, out var known))
            return known;
        var row = db.Certificates.AsNoTracking()
            .Where(c => c.CertificateId == id)
            .Select(c => new { c.RawCertificate, c.Pem })
            .FirstOrDefault();
        return Remember(id, row?.RawCertificate, row?.Pem);
    }

    private static byte[]? Remember(Guid id, byte[]? raw, string? pem)
    {
        try
        {
            X509Certificate? certificate = raw is { Length: > 0 } ? new X509Certificate(raw)
                : !string.IsNullOrWhiteSpace(pem) ? CertificateUtil.ParseFromPem(pem) : null;
            if (certificate == null)
                return null;
            var hash = Of(certificate);
            Known[id] = hash;
            return hash;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }
}
