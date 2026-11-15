using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>A CA's cryptoperiod as the console and the health answer show it: the facts and the notices they raise.</summary>
/// <param name="Facts">What is known about the CA's key and certificate over time.</param>
/// <param name="Advisories">The notices those facts raise under the instance's settings, most pressing first.</param>
public sealed record CaLifecycleReport(CaCryptoperiodFacts Facts, IReadOnlyList<CaKeyAdvisory> Advisories);

/// <summary>
/// Reads, for each X.509 CA, what <see cref="CaCryptoperiod"/> judges: how long its key has
/// signed, when its certificate ends, how far the certificates it issued reach, and how long
/// its profiles let it issue for. It reads and decides nothing: the notices are
/// <see cref="CaCryptoperiod.Advisories"/>'s, under the <c>CaLifecycle</c> settings as they are
/// when asked.
/// <para>
/// A CA's parent is identified (its name, the end of its certificate, and so the text of the
/// "outlives its parent" notice) only to a reader who may see the parent: one that is among the
/// CAs asked about, or one whose space the caller says the reader may see. For any other parent
/// the facts carry <see cref="CaCryptoperiodFacts.WithheldParent"/> and nothing that names or
/// dates it.
/// </para>
/// </summary>
public sealed class CaLifecycleService(ModularCADbContext db, SystemConfig config)
{
    /// <summary>How far up a certificate profile's inheritance is followed for a maximum validity.</summary>
    private const int MaxInheritanceDepth = 8;

    /// <summary>
    /// The cryptoperiod of each of <paramref name="cas"/>, by CA id. Each CA's
    /// <see cref="CertificateAuthorityEntity.Certificate"/> must be loaded; a CA without an X.509
    /// certificate is left out.
    /// </summary>
    /// <param name="cas">The CAs to describe: the ones the reader is being shown.</param>
    /// <param name="now">The instant the notices are judged at.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <param name="readerMaySeeSpace">
    /// Whether the reader may see a CA of the space given (null for an instance CA): the caller's
    /// space fence. It is asked only about a parent that is not among <paramref name="cas"/>.
    /// Null, the default, withholds every such parent, so a caller that forgets it leaks nothing.
    /// </param>
    public async Task<IReadOnlyDictionary<Guid, CaLifecycleReport>> DescribeAsync(
        IReadOnlyCollection<CertificateAuthorityEntity> cas, DateTime now, CancellationToken ct = default,
        Func<Guid?, bool>? readerMaySeeSpace = null)
    {
        var settings = config.CaLifecycle.ToSettings();
        var reports = new Dictionary<Guid, CaLifecycleReport>();
        var withCertificate = cas.Where(ca => !ca.IsSshCa && ca.Certificate != null && ca.CertificateId != null).ToList();
        if (withCertificate.Count == 0)
            return reports;

        // Parents that are not among the CAs asked about (a fenced caller, or a parent the list
        // leaves out) are read once, with their space: the reader is told who such a parent is
        // only where readerMaySeeSpace admits that space.
        var known = cas.ToDictionary(ca => ca.Id);
        var missingParents = withCertificate
            .Where(ca => ca.ParentCaId is Guid p && !known.ContainsKey(p))
            .Select(ca => ca.ParentCaId!.Value).Distinct().ToList();
        var parents = missingParents.Count == 0
            ? new Dictionary<Guid, (string Name, Guid? SpaceId, DateTime? NotAfter)>()
            : (await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
                .Where(ca => missingParents.Contains(ca.Id))
                .Select(ca => new { ca.Id, ca.Name, ca.SpaceId, NotAfter = ca.Certificate == null ? (DateTime?)null : ca.Certificate.NotAfter })
                .ToListAsync(ct))
                .ToDictionary(p => p.Id, p => (p.Name, p.SpaceId, p.NotAfter));

        // Each CA's own infrastructure profiles (OCSP responder, timestamp, CMP signer): the
        // profile it names for a role, and the seeded profile of every role, found the way
        // issuance finds it. The seeded one stays infrastructure for a CA that names another: it
        // is usually still linked to that CA, and it is no end-entity profile on any CA.
        var seeded = new HashSet<Guid>();
        foreach (var role in InfrastructureCertProfiles.All)
            if ((await InfrastructureCertProfiles.ResolveAsync(db, null, role, ct))?.Id is Guid id)
                seeded.Add(id);
        var infrastructure = new Dictionary<Guid, HashSet<Guid>>();
        foreach (var ca in withCertificate)
        {
            var ids = new HashSet<Guid>(seeded);
            foreach (var role in InfrastructureCertProfiles.All)
                if (InfrastructureCertProfiles.ChosenId(ca, role) is Guid chosen)
                    ids.Add(chosen);
            infrastructure[ca.CertificateId!.Value] = ids;
        }
        var profileLimits = await LongestProfileValidityAsync(withCertificate.Select(ca => ca.CertificateId!.Value).ToList(), infrastructure, ct);

        foreach (var ca in withCertificate)
        {
            var current = ca.Certificate!;
            var currentId = ca.CertificateId!.Value;

            // Every certificate the CA has had over the key it has now.
            var sameKey = new List<Guid> { currentId };
            try
            {
                var parsed = !string.IsNullOrWhiteSpace(current.Pem) ? CertificateUtil.ParseFromPem(current.Pem) : null;
                if (parsed != null)
                    sameKey = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, currentId, parsed, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // An unreadable certificate has no siblings the instance can vouch for.
            }

            DateTime? since = current.NotBefore;
            if (sameKey.Count > 1)
                since = await db.Certificates.AsNoTracking()
                    .Where(c => sameKey.Contains(c.CertificateId))
                    .MinAsync(c => (DateTime?)c.NotBefore, ct) ?? current.NotBefore;

            var latestIssued = await db.Certificates.AsNoTracking()
                .Where(c => c.IssuerCertificateId != null && sameKey.Contains(c.IssuerCertificateId.Value)
                    && !sameKey.Contains(c.CertificateId) && !c.Revoked && c.NotAfter > now)
                .MaxAsync(c => (DateTime?)c.NotAfter, ct);

            string? parentName = null;
            DateTime? parentNotAfter = null;
            CaWithheldParent? withheldParent = null;
            if (ca.ParentCaId is Guid parentId)
            {
                if (known.TryGetValue(parentId, out var parent))
                    (parentName, parentNotAfter) = (parent.Name, parent.Certificate?.NotAfter);
                else if (parents.TryGetValue(parentId, out var read))
                {
                    if (readerMaySeeSpace?.Invoke(read.SpaceId) == true)
                        (parentName, parentNotAfter) = (read.Name, read.NotAfter);
                    else
                        // Outside the reader's fence: only how the parent's end stands against this CA's.
                        withheldParent = read.NotAfter is DateTime end && end < current.NotAfter
                            ? (end <= now ? CaWithheldParent.Expired : CaWithheldParent.EndsFirst)
                            : CaWithheldParent.NoEarlierEnd;
                }
            }

            profileLimits.TryGetValue(currentId, out var limit);
            var facts = new CaCryptoperiodFacts(
                IsRoot: ca.ParentCaId == null && string.Equals(current.SubjectDN, current.Issuer, StringComparison.OrdinalIgnoreCase),
                KeyInUseSince: since,
                CertificateCount: sameKey.Count,
                CertificateNotBefore: current.NotBefore,
                CertificateNotAfter: current.NotAfter,
                ExpiryWarningAt: current.ExpiryWarningAt == default ? null : current.ExpiryWarningAt,
                ExpiryAlertAt: current.ExpiryAlertAt == default ? null : current.ExpiryAlertAt,
                LatestIssuedNotAfter: latestIssued,
                LongestProfileValidity: limit.Validity,
                LongestProfileName: limit.Name,
                ParentName: parentName,
                ParentCertificateNotAfter: parentNotAfter)
            { LongestProfileIsInfrastructure = limit.Infrastructure, WithheldParent = withheldParent };
            reports[ca.Id] = new CaLifecycleReport(facts, CaCryptoperiod.Advisories(facts, settings, now));
        }
        return reports;
    }

    /// <summary>
    /// For each CA certificate id, the longest maximum validity among the end-entity certificate
    /// profiles linked to a signing profile that issues from it, with the profile's name. A
    /// profile that sets no maximum takes the one it inherits; one with none anywhere is left out.
    /// The CA's own infrastructure profiles (<paramref name="infrastructure"/>, by CA certificate
    /// id) are left out too: their certificates are issued to end with the CA's. Only when a CA
    /// has no other profile with a maximum is the longest of those given, marked as such, so the
    /// fact is not empty; it raises no notice.
    /// </summary>
    private async Task<Dictionary<Guid, (TimeSpan? Validity, string? Name, bool Infrastructure)>> LongestProfileValidityAsync(
        List<Guid> caCertificateIds, IReadOnlyDictionary<Guid, HashSet<Guid>> infrastructure, CancellationToken ct)
    {
        var links = await (from link in db.AllowedCertProfileSigningProfiles.AsNoTracking()
                           join signing in db.SigningProfiles.AsNoTracking() on link.SigningProfileId equals signing.Id
                           join profile in db.CertProfiles.AsNoTracking() on link.CertProfileId equals profile.Id
                           where signing.IssuerId != null && caCertificateIds.Contains(signing.IssuerId.Value) && !profile.IsCaProfile
                           select new { IssuerId = signing.IssuerId!.Value, profile.Id, profile.Name, profile.ValidityPeriodMax, profile.InheritanceEnabled, profile.InheritsFromId })
            .ToListAsync(ct);

        var ancestors = new Dictionary<Guid, (string? Max, bool Inherits, Guid? From)>();
        async Task<string?> EffectiveMaxAsync(string? own, bool inherits, Guid? from)
        {
            var depth = 0;
            while (string.IsNullOrWhiteSpace(own) && inherits && from is Guid parentId && depth++ < MaxInheritanceDepth)
            {
                if (!ancestors.TryGetValue(parentId, out var parent))
                {
                    var row = await db.CertProfiles.AsNoTracking()
                        .Where(p => p.Id == parentId)
                        .Select(p => new { p.ValidityPeriodMax, p.InheritanceEnabled, p.InheritsFromId })
                        .FirstOrDefaultAsync(ct);
                    parent = row == null ? (null, false, null) : (row.ValidityPeriodMax, row.InheritanceEnabled, row.InheritsFromId);
                    ancestors[parentId] = parent;
                }
                (own, inherits, from) = parent;
            }
            return own;
        }

        var longest = new Dictionary<Guid, (TimeSpan? Validity, string? Name, bool Infrastructure)>();
        foreach (var link in links)
        {
            var own = infrastructure.TryGetValue(link.IssuerId, out var ids) && ids.Contains(link.Id);
            var max = await EffectiveMaxAsync(link.ValidityPeriodMax, link.InheritanceEnabled, link.InheritsFromId);
            if (string.IsNullOrWhiteSpace(max))
                continue;
            TimeSpan validity;
            try { validity = Iso8601ParserUtil.ParseIso8601(max); }
            catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException) { continue; }
            // An end-entity profile always displaces an infrastructure one; within a kind, the longer wins.
            if (!longest.TryGetValue(link.IssuerId, out var seen) || seen.Validity == null
                || (seen.Infrastructure && !own) || (seen.Infrastructure == own && validity > seen.Validity))
                longest[link.IssuerId] = (validity, link.Name, own);
        }
        return longest;
    }
}
