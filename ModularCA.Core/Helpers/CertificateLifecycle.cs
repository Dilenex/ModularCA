using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Replacement and issuance-channel facts about end-entity certificates, shared by the
/// certificate list, the certificate detail and the lifecycle summary so they cannot disagree.
/// </summary>
/// <remarks>
/// A certificate is replaced when any of these holds:
/// <list type="bullet">
/// <item>it is flagged <see cref="CertificateEntity.IsReissued"/>;</item>
/// <item>an issued request names it in <see cref="CertRequestEntity.RenewalOfCertificateId"/>
/// (reissue, auto-renewal, protocol renewal);</item>
/// <item>a certificate from the same issuing CA that is not revoked and not expired, started no
/// earlier and ends later, has the same subject DN and the same SAN set (order and case ignored).</item>
/// </list>
/// Every query here is driven by the candidate set the caller passes, so callers bound it.
/// </remarks>
public static class CertificateLifecycle
{
    /// <summary>How far back expired certificates are checked for a replacement.</summary>
    public const int ReplacementWindowDays = 90;

    /// <summary>The replacing certificate; both fields are null when only the reissue flag says so.</summary>
    public sealed record Replacement(Guid? SuccessorId, string? SuccessorSerial);

    /// <summary>Recognised issuance channels.</summary>
    public static class Channels
    {
        public const string Acme = "ACME";
        public const string Est = "EST";
        public const string Scep = "SCEP";
        public const string Cmp = "CMP";
        public const string Msae = "MSAE";
        public const string Manual = "Manual";
    }

    /// <summary>
    /// A SAN list reduced to a comparable key: decoded as the store decodes it, trimmed,
    /// lower-cased, de-duplicated and sorted.
    /// </summary>
    public static string SanSetKey(string? sanJson)
        => string.Join("\n", UpnSanEncoding.DeserializeStoredSans(sanJson)
            .Select(s => s.Trim().ToLowerInvariant())
            .Where(s => s.Length > 0)
            .Distinct()
            .OrderBy(s => s, StringComparer.Ordinal));

    /// <summary>
    /// Resolves the CA that issued a certificate: through its issuer certificate, or for a legacy
    /// row with no issuer link, through its signing profile's issuer.
    /// </summary>
    public sealed class IssuingCaMap(
        IReadOnlyDictionary<Guid, IssuerChainResolver.CaOwner> owners,
        IReadOnlyDictionary<Guid, Guid> profileIssuers)
    {
        /// <summary>Loads the signing-profile issuers and pairs them with <paramref name="owners"/>.</summary>
        public static async Task<IssuingCaMap> LoadAsync(ModularCADbContext db,
            IReadOnlyDictionary<Guid, IssuerChainResolver.CaOwner> owners, CancellationToken ct = default)
        {
            var profiles = await db.SigningProfiles.AsNoTracking()
                .Where(p => p.IssuerId != null)
                .Select(p => new { p.Id, IssuerId = p.IssuerId!.Value })
                .ToListAsync(ct);
            return new IssuingCaMap(owners, profiles.ToDictionary(p => p.Id, p => p.IssuerId));
        }

        /// <summary>The issuing CA's id, or null when neither link resolves to a CA.</summary>
        public Guid? CaOf(Guid? issuerCertificateId, Guid? signingProfileId)
        {
            if (issuerCertificateId is { } issuer)
                return owners.TryGetValue(issuer, out var o) ? o.CaId : null;
            if (signingProfileId is { } profile && profileIssuers.TryGetValue(profile, out var profileIssuer)
                && owners.TryGetValue(profileIssuer, out var po))
                return po.CaId;
            return null;
        }
    }

    /// <summary>
    /// Finds the replacement of every certificate in <paramref name="candidates"/> that has one.
    /// Certificates absent from the result are not replaced.
    /// </summary>
    /// <param name="db">The main database.</param>
    /// <param name="candidates">The certificates to check, already scoped and bounded by the caller.</param>
    /// <param name="caMap">Issuing-CA resolution for the same-CA rule.</param>
    /// <param name="now">The instant "not expired" is measured against.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<Dictionary<Guid, Replacement>> ResolveReplacementsAsync(
        ModularCADbContext db, IQueryable<CertificateEntity> candidates, IssuingCaMap caMap, DateTime now,
        CancellationToken ct = default)
    {
        var result = new Dictionary<Guid, Replacement>();

        var linked = await (
                from r in db.CertificateRequests.AsNoTracking()
                join p in candidates on r.RenewalOfCertificateId equals (Guid?)p.CertificateId
                join n in db.Certificates.AsNoTracking() on r.IssuedCertificateId equals (Guid?)n.CertificateId
                where n.CertificateId != p.CertificateId
                select new { Pred = p.CertificateId, n.CertificateId, n.SerialNumber, n.NotBefore })
            .ToListAsync(ct);
        foreach (var g in linked.GroupBy(l => l.Pred))
        {
            var s = g.OrderByDescending(x => x.NotBefore).First();
            result[g.Key] = new Replacement(s.CertificateId, s.SerialNumber);
        }

        var pairs = await (
                from p in candidates
                join n in db.Certificates.AsNoTracking() on p.SubjectDN equals n.SubjectDN
                where n.CertificateId != p.CertificateId && !n.IsCA && !n.Revoked && n.NotAfter > now
                      && n.NotBefore >= p.NotBefore && n.NotAfter > p.NotAfter
                select new
                {
                    Pred = p.CertificateId, PSan = p.SubjectAlternativeNamesJson, PIssuerCert = p.IssuerCertificateId,
                    PProfile = p.SigningProfileId, PIssuer = p.Issuer,
                    n.CertificateId, n.SerialNumber, NSan = n.SubjectAlternativeNamesJson, NIssuerCert = n.IssuerCertificateId,
                    NProfile = n.SigningProfileId, NIssuer = n.Issuer, n.NotBefore,
                })
            .ToListAsync(ct);
        foreach (var g in pairs.Where(p => !result.ContainsKey(p.Pred)).GroupBy(p => p.Pred))
        {
            var match = g
                .Where(x => SameIssuingCa(caMap.CaOf(x.PIssuerCert, x.PProfile), caMap.CaOf(x.NIssuerCert, x.NProfile), x.PIssuer, x.NIssuer)
                            && SanSetKey(x.PSan) == SanSetKey(x.NSan))
                .OrderByDescending(x => x.NotBefore)
                .FirstOrDefault();
            if (match != null)
                result[g.Key] = new Replacement(match.CertificateId, match.SerialNumber);
        }

        var flagged = await candidates.Where(c => c.IsReissued).Select(c => c.CertificateId).ToListAsync(ct);
        foreach (var id in flagged)
            result.TryAdd(id, new Replacement(null, null));

        return result;
    }

    private static bool SameIssuingCa(Guid? a, Guid? b, string issuerA, string issuerB)
        => a != null && b != null ? a == b : string.Equals(issuerA, issuerB, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The channel each certificate was issued through, where something on record says: an ACME
    /// order or SCEP transaction in the main database, an issuance row in the EST, CMP, MSAE, SCEP
    /// or ACME protocol audit, or else a console or portal request with a requestor (Manual).
    /// Meant for a handful of certificates; each lookup is by indexed id or serial.
    /// </summary>
    /// <param name="db">The main database.</param>
    /// <param name="audit">The audit database, or null when it is not available.</param>
    /// <param name="certs">Certificate ids and serials to resolve.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<Dictionary<Guid, string>> ResolveIssuanceChannelsAsync(
        ModularCADbContext db, AuditDbContext? audit, IReadOnlyCollection<(Guid Id, string Serial)> certs,
        CancellationToken ct = default)
    {
        var result = new Dictionary<Guid, string>();
        if (certs.Count == 0)
            return result;
        var ids = certs.Select(c => c.Id).Distinct().ToList();

        foreach (var id in await db.AcmeOrders.AsNoTracking()
                     .Where(o => o.CertificateId != null && ids.Contains(o.CertificateId.Value))
                     .Select(o => o.CertificateId!.Value).Distinct().ToListAsync(ct))
            result[id] = Channels.Acme;
        foreach (var id in await db.ScepTransactions.AsNoTracking()
                     .Where(t => t.IssuedCertificateId != null && ids.Contains(t.IssuedCertificateId.Value))
                     .Select(t => t.IssuedCertificateId!.Value).Distinct().ToListAsync(ct))
            result.TryAdd(id, Channels.Scep);

        var open = certs.Where(c => !result.ContainsKey(c.Id)).ToList();
        if (audit != null && open.Count > 0)
        {
            var serials = open.Select(c => c.Serial).Distinct().ToList();
            var bySerial = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            void Take(IEnumerable<string?> found, string channel)
            {
                foreach (var s in found)
                    if (s != null) bySerial.TryAdd(s, channel);
            }
            // The audit database is separate and only enriches the answer, so its being
            // unavailable leaves those channels unknown rather than failing the caller.
            try
            {
                Take(await audit.AuditEst.AsNoTracking()
                    .Where(a => a.Success && a.CertificateSerial != null && serials.Contains(a.CertificateSerial))
                    .Select(a => a.CertificateSerial).ToListAsync(ct), Channels.Est);
                Take(await audit.AuditCmp.AsNoTracking()
                    .Where(a => a.Success && a.CertificateSerial != null && serials.Contains(a.CertificateSerial)
                                && a.MessageType != "RR" && a.RevocationReason == null)
                    .Select(a => a.CertificateSerial).ToListAsync(ct), Channels.Cmp);
                Take(await audit.AuditMsae.AsNoTracking()
                    .Where(a => a.Success && a.CertificateSerial != null && serials.Contains(a.CertificateSerial))
                    .Select(a => a.CertificateSerial).ToListAsync(ct), Channels.Msae);
                Take(await audit.AuditScep.AsNoTracking()
                    .Where(a => a.Success && a.CertificateSerial != null && serials.Contains(a.CertificateSerial))
                    .Select(a => a.CertificateSerial).ToListAsync(ct), Channels.Scep);
                Take(await audit.AuditAcme.AsNoTracking()
                    .Where(a => a.Success && a.CertificateSerial != null && serials.Contains(a.CertificateSerial)
                                && a.Operation == "CertificateIssued")
                    .Select(a => a.CertificateSerial).ToListAsync(ct), Channels.Acme);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
            }
            foreach (var c in open)
                if (bySerial.TryGetValue(c.Serial, out var channel))
                    result[c.Id] = channel;
        }

        var stillOpen = ids.Where(id => !result.ContainsKey(id)).ToList();
        if (stillOpen.Count > 0)
        {
            foreach (var id in await db.CertificateRequests.AsNoTracking()
                         .Where(r => r.IssuedCertificateId != null && stillOpen.Contains(r.IssuedCertificateId.Value)
                                     && r.RequestorUserId != null && !r.IsInfrastructureCert)
                         .Select(r => r.IssuedCertificateId!.Value).Distinct().ToListAsync(ct))
                result[id] = Channels.Manual;
        }

        return result;
    }

    /// <summary>
    /// The certificates among <paramref name="ids"/> with a renewal request still in flight: one
    /// that names them, has issued nothing yet, and was not rejected, cancelled or failed.
    /// </summary>
    public static async Task<HashSet<Guid>> PendingRenewalsAsync(ModularCADbContext db, IReadOnlyCollection<Guid> ids,
        CancellationToken ct = default)
    {
        if (ids.Count == 0)
            return [];
        var list = ids.ToList();
        var pending = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.RenewalOfCertificateId != null && list.Contains(r.RenewalOfCertificateId.Value)
                        && r.IssuedCertificateId == null
                        && r.Status != "Rejected" && r.Status != "Cancelled" && r.Status != "Failed")
            .Select(r => r.RenewalOfCertificateId!.Value)
            .Distinct()
            .ToListAsync(ct);
        return pending.ToHashSet();
    }

    /// <summary>The CN of a subject DN, or null when it has none.</summary>
    public static string? CommonNameOf(string? subjectDn)
    {
        if (string.IsNullOrEmpty(subjectDn))
            return null;
        foreach (var part in subjectDn.Split(','))
        {
            var kv = part.Trim();
            if (kv.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return kv[3..].Trim();
        }
        return null;
    }
}
