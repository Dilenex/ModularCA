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
    /// <param name="cas">The CAs to describe.</param>
    /// <param name="now">The instant the notices are judged at.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<IReadOnlyDictionary<Guid, CaLifecycleReport>> DescribeAsync(
        IReadOnlyCollection<CertificateAuthorityEntity> cas, DateTime now, CancellationToken ct = default)
    {
        var settings = config.CaLifecycle.ToSettings();
        var reports = new Dictionary<Guid, CaLifecycleReport>();
        var withCertificate = cas.Where(ca => !ca.IsSshCa && ca.Certificate != null && ca.CertificateId != null).ToList();
        if (withCertificate.Count == 0)
            return reports;

        // Parents that are not among the CAs asked about (a fenced caller) are read once.
        var known = withCertificate.ToDictionary(ca => ca.Id);
        var missingParents = withCertificate
            .Where(ca => ca.ParentCaId is Guid p && !known.ContainsKey(p))
            .Select(ca => ca.ParentCaId!.Value).Distinct().ToList();
        var parents = missingParents.Count == 0
            ? new Dictionary<Guid, (string Name, DateTime? NotAfter)>()
            : (await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
                .Where(ca => missingParents.Contains(ca.Id))
                .Select(ca => new { ca.Id, ca.Name, NotAfter = ca.Certificate == null ? (DateTime?)null : ca.Certificate.NotAfter })
                .ToListAsync(ct))
                .ToDictionary(p => p.Id, p => (p.Name, p.NotAfter));

        var profileLimits = await LongestProfileValidityAsync(withCertificate.Select(ca => ca.CertificateId!.Value).ToList(), ct);

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
            if (ca.ParentCaId is Guid parentId)
            {
                if (known.TryGetValue(parentId, out var parent))
                    (parentName, parentNotAfter) = (parent.Name, parent.Certificate?.NotAfter);
                else if (parents.TryGetValue(parentId, out var read))
                    (parentName, parentNotAfter) = read;
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
                ParentCertificateNotAfter: parentNotAfter);
            reports[ca.Id] = new CaLifecycleReport(facts, CaCryptoperiod.Advisories(facts, settings, now));
        }
        return reports;
    }

    /// <summary>
    /// For each CA certificate id, the longest maximum validity among the end-entity certificate
    /// profiles linked to a signing profile that issues from it, with the profile's name. A
    /// profile that sets no maximum takes the one it inherits; one with none anywhere is left out.
    /// </summary>
    private async Task<Dictionary<Guid, (TimeSpan? Validity, string? Name)>> LongestProfileValidityAsync(List<Guid> caCertificateIds, CancellationToken ct)
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

        var longest = new Dictionary<Guid, (TimeSpan? Validity, string? Name)>();
        foreach (var link in links)
        {
            var max = await EffectiveMaxAsync(link.ValidityPeriodMax, link.InheritanceEnabled, link.InheritsFromId);
            if (string.IsNullOrWhiteSpace(max))
                continue;
            TimeSpan validity;
            try { validity = Iso8601ParserUtil.ParseIso8601(max); }
            catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException) { continue; }
            if (!longest.TryGetValue(link.IssuerId, out var seen) || seen.Validity == null || validity > seen.Validity)
                longest[link.IssuerId] = (validity, link.Name);
        }
        return longest;
    }
}
