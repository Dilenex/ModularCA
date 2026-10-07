using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services;

/// <summary>
/// Fills <see cref="CertificateEntity.IssuerCertificateId"/> on rows written before it was
/// recorded, so CA-scoped access, lists and summaries (which scope by it) see them.
/// </summary>
/// <remarks>
/// The issuer is the CA certificate whose subject key identifier equals the row's authority key
/// identifier, or, when that does not decide it, whose subject is the row's issuer DN; either way
/// the row's signature must verify under the candidate's key. Several survivors are narrowed to
/// the CA certificate valid when the row was issued, then to the space of the row's signing
/// profile. Anything still ambiguous stays null: a wrong issuer would put the certificate in
/// another CA's scope, which is worse than leaving it out. Idempotent; runs at every startup.
/// </remarks>
public static class IssuerCertificateBackfill
{
    /// <summary>Outcome counts of one backfill pass.</summary>
    /// <param name="Scanned">Rows examined that had no issuer link.</param>
    /// <param name="Linked">Rows given an issuer.</param>
    /// <param name="Ambiguous">Rows left null because more than one issuer fitted.</param>
    /// <param name="Unmatched">Rows left null because no stored CA certificate issued them.</param>
    public sealed record Result(int Scanned, int Linked, int Ambiguous, int Unmatched);

    private sealed record Candidate(Guid CertificateId, X509Certificate Cert, byte[]? Ski, Guid? SpaceId);

    /// <summary>
    /// Links every certificate row with a null issuer that can be attributed unambiguously, in
    /// batches of <paramref name="batchSize"/>, and returns the counts. Rows are read untracked and
    /// only for the columns attribution needs, and linked with a set-based UPDATE per issuer, so a
    /// startup that finds only rows it cannot attribute costs a projection and a parse, not a
    /// tracked load and save.
    /// </summary>
    public static async Task<Result> RunAsync(
        ModularCADbContext db, ILogger? logger = null, int batchSize = 500, CancellationToken ct = default)
    {
        var owners = await IssuerChainResolver.ResolveCaCertificateOwnersAsync(db);
        var caRows = await db.Certificates.AsNoTracking()
            .Where(c => c.IsCA)
            .Select(c => new { c.CertificateId, c.RawCertificate, c.Pem })
            .ToListAsync(ct);
        var candidates = caRows
            .Select(r => Parse(r.RawCertificate, r.Pem) is { } x
                ? new Candidate(r.CertificateId, x, SubjectKeyId(x), owners.TryGetValue(r.CertificateId, out var o) ? o.SpaceId : null)
                : null)
            .OfType<Candidate>()
            .ToList();

        var profileIssuers = await db.SigningProfiles.AsNoTracking()
            .Where(sp => sp.IssuerId != null)
            .ToDictionaryAsync(sp => sp.Id, sp => sp.IssuerId!.Value, ct);

        int scanned = 0, linked = 0, ambiguous = 0, unmatched = 0;
        Guid? after = null;
        while (true)
        {
            var query = db.Certificates.AsNoTracking().Where(c => c.IssuerCertificateId == null);
            if (after is Guid last)
                query = query.Where(c => c.CertificateId.CompareTo(last) > 0);
            var batch = await query.OrderBy(c => c.CertificateId).Take(batchSize)
                .Select(c => new PendingRow(c.CertificateId, c.IsCA, c.SigningProfileId, c.RawCertificate, c.Pem))
                .ToListAsync(ct);
            if (batch.Count == 0)
                break;
            after = batch[^1].CertificateId;

            var links = new Dictionary<Guid, List<Guid>>();
            foreach (var row in batch)
            {
                scanned++;
                Guid? spaceHint = row.SigningProfileId is Guid spId
                    && profileIssuers.TryGetValue(spId, out var issuerId)
                    && owners.TryGetValue(issuerId, out var owner) ? owner.SpaceId : null;

                switch (FindIssuer(row, candidates, spaceHint, out var issuer))
                {
                    case Match.Unique:
                        if (!links.TryGetValue(issuer, out var rows))
                            links[issuer] = rows = [];
                        rows.Add(row.CertificateId);
                        break;
                    case Match.Ambiguous:
                        ambiguous++;
                        break;
                    default:
                        unmatched++;
                        break;
                }
            }
            foreach (var (issuer, ids) in links)
                linked += await LinkAsync(db, issuer, ids, ct);
            if (batch.Count < batchSize)
                break;
        }

        if (scanned > 0)
            logger?.LogInformation(
                "Issuer backfill: {Scanned} certificate(s) without an issuer link; linked {Linked}, left {Ambiguous} ambiguous and {Unmatched} unmatched.",
                scanned, linked, ambiguous, unmatched);
        return new Result(scanned, linked, ambiguous, unmatched);
    }

    private enum Match { None, Unique, Ambiguous }

    /// <summary>The columns of a row still without an issuer link that attribution reads.</summary>
    private sealed record PendingRow(Guid CertificateId, bool IsCA, Guid? SigningProfileId, byte[]? RawCertificate, string? Pem);

    /// <summary>
    /// Sets <paramref name="issuer"/> on the rows in <paramref name="ids"/> that are still unlinked,
    /// with one UPDATE on a relational provider (tracked entities otherwise, for the in-memory
    /// provider, which cannot execute one), and returns how many were linked.
    /// </summary>
    private static async Task<int> LinkAsync(ModularCADbContext db, Guid issuer, List<Guid> ids, CancellationToken ct)
    {
        var rows = db.Certificates.Where(c => ids.Contains(c.CertificateId) && c.IssuerCertificateId == null);
        if (db.Database.IsRelational())
            return await rows.ExecuteUpdateAsync(s => s.SetProperty(c => c.IssuerCertificateId, issuer), ct);

        var tracked = await rows.ToListAsync(ct);
        foreach (var row in tracked)
            row.IssuerCertificateId = issuer;
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        return tracked.Count;
    }

    /// <summary>
    /// Finds the one CA certificate that issued <paramref name="row"/>, or reports none or ambiguity.
    /// </summary>
    private static Match FindIssuer(PendingRow row, List<Candidate> candidates, Guid? spaceHint, out Guid issuer)
    {
        issuer = Guid.Empty;
        var cert = Parse(row.RawCertificate, row.Pem);
        if (cert == null)
            return Match.None;

        if (cert.SubjectDN.Equivalent(cert.IssuerDN) && Verifies(cert, cert))
        {
            if (!row.IsCA)
                return Match.None;
            issuer = row.CertificateId;
            return Match.Unique;
        }

        var aki = AuthorityKeyId(cert);
        var matches = aki == null ? [] : candidates
            .Where(c => c.CertificateId != row.CertificateId && c.Ski != null && c.Ski.AsSpan().SequenceEqual(aki) && Verifies(cert, c.Cert))
            .ToList();
        if (matches.Count == 0)
            matches = candidates
                .Where(c => c.CertificateId != row.CertificateId && c.Cert.SubjectDN.Equivalent(cert.IssuerDN) && Verifies(cert, c.Cert))
                .ToList();
        if (matches.Count == 0)
            return Match.None;

        if (matches.Count > 1)
        {
            var validAtIssue = matches.Where(c => c.Cert.IsValid(cert.NotBefore)).ToList();
            if (validAtIssue.Count > 0)
                matches = validAtIssue;
        }
        if (matches.Count > 1 && spaceHint != null)
        {
            var sameSpace = matches.Where(c => c.SpaceId == spaceHint).ToList();
            if (sameSpace.Count > 0)
                matches = sameSpace;
        }
        if (matches.Count > 1)
            return Match.Ambiguous;

        issuer = matches[0].CertificateId;
        return Match.Unique;
    }

    private static X509Certificate? Parse(byte[]? raw, string? pem)
    {
        try
        {
            if (raw is { Length: > 0 })
                return new X509CertificateParser().ReadCertificate(raw);
            return string.IsNullOrWhiteSpace(pem) ? null : CertificateUtil.ParseFromPem(pem);
        }
        catch { return null; }
    }

    private static bool Verifies(X509Certificate cert, X509Certificate issuer)
    {
        try { cert.Verify(issuer.GetPublicKey()); return true; }
        catch { return false; }
    }

    private static byte[]? SubjectKeyId(X509Certificate cert)
    {
        try
        {
            var ext = cert.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
            return ext == null ? null : SubjectKeyIdentifier.GetInstance(Asn1Object.FromByteArray(ext.GetOctets())).GetKeyIdentifier();
        }
        catch { return null; }
    }

    private static byte[]? AuthorityKeyId(X509Certificate cert)
    {
        try
        {
            var ext = cert.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
            return ext == null ? null : AuthorityKeyIdentifier.GetInstance(Asn1Object.FromByteArray(ext.GetOctets())).GetKeyIdentifier();
        }
        catch { return null; }
    }
}
