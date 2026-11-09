using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Whether a certificate is in its expiry warning or alert, read from the instants stored on it
/// (<see cref="CertificateEntity.ExpiryWarningAt"/>, <see cref="CertificateEntity.ExpiryAlertAt"/>),
/// and the re-compute of those instants when a profile's warning settings change. The lifecycle
/// summary, the certificate list's <c>expiring</c> and <c>alert</c> statuses, the expiry chart,
/// the notification job, the compliance scan and the health score all ask here, so they cannot
/// disagree.
/// </summary>
/// <remarks>
/// A certificate is in its warning while it is not revoked, has not expired, and its warning
/// instant has passed; in its alert likewise with the alert instant. Retired certificates and
/// dismissed warnings (<see cref="CertificateEntityExtensions.ExpiryWarningSilenced"/>) are
/// still in the window, as are replaced ones (<see cref="ReplacedAsync"/>): each caller decides
/// whether a silenced or replaced one counts.
/// </remarks>
public static class CertificateExpiry
{
    /// <summary>Not revoked, not expired, and past its soft warning instant at <paramref name="now"/>.</summary>
    public static Expression<Func<CertificateEntity, bool>> InWarning(DateTime now) =>
        c => !c.Revoked && c.NotAfter > now && c.ExpiryWarningAt <= now;

    /// <summary>Not revoked, not expired, and past its alert instant at <paramref name="now"/>.</summary>
    public static Expression<Func<CertificateEntity, bool>> InAlert(DateTime now) =>
        c => !c.Revoked && c.NotAfter > now && c.ExpiryAlertAt <= now;

    /// <summary>
    /// The lifecycle summary's replacement band: not revoked, and expired since
    /// <paramref name="windowStart"/>, expiring by <paramref name="expiringBy"/>, or in its expiry
    /// warning at <paramref name="now"/> (the condition of <see cref="InWarning"/>).
    /// </summary>
    public static Expression<Func<CertificateEntity, bool>> InReplacementBand(DateTime now, DateTime windowStart, DateTime expiringBy) =>
        c => !c.Revoked && ((c.NotAfter >= windowStart && c.NotAfter <= expiringBy) || (c.NotAfter > now && c.ExpiryWarningAt <= now));

    /// <summary>
    /// The ids of the certificates among <paramref name="candidates"/> that have been replaced, by the
    /// rule the lifecycle summary's <c>NotReplaced</c> counts use
    /// (<see cref="CertificateLifecycle.ResolveReplacementsAsync"/>).
    /// </summary>
    /// <param name="db">The main database.</param>
    /// <param name="candidates">The certificates to check, already bounded by the caller.</param>
    /// <param name="now">The instant a successor's "not expired" is measured against.</param>
    /// <param name="caMap">The issuing-CA resolution, or null to load it here.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<HashSet<Guid>> ReplacedAsync(ModularCADbContext db, IQueryable<CertificateEntity> candidates, DateTime now,
        CertificateLifecycle.IssuingCaMap? caMap = null, CancellationToken ct = default)
    {
        caMap ??= await CertificateLifecycle.IssuingCaMap.LoadAsync(db, await IssuerChainResolver.ResolveCaCertificateOwnersAsync(db), ct);
        return (await CertificateLifecycle.ResolveReplacementsAsync(db, candidates, caMap, now, ct)).Keys.ToHashSet();
    }

    /// <summary><see cref="InWarning"/> over values already loaded.</summary>
    public static bool IsInWarning(bool revoked, DateTime notAfter, DateTime warningAt, DateTime now) =>
        !revoked && notAfter > now && warningAt <= now;

    /// <summary><see cref="InAlert"/> over values already loaded.</summary>
    public static bool IsInAlert(bool revoked, DateTime notAfter, DateTime alertAt, DateTime now) =>
        !revoked && notAfter > now && alertAt <= now;

    /// <summary>
    /// The expiry warning settings issuance would use for <paramref name="profile"/> now: its own,
    /// merged with its parent's when it inherits (<see cref="ProfileResolutionService"/>).
    /// </summary>
    public static async Task<ExpiryWarningSettings> EffectiveSettingsAsync(ModularCADbContext db, CertProfileEntity profile, CancellationToken ct = default)
    {
        CertProfileEntity? parent = null;
        if (profile.InheritanceEnabled && profile.InheritsFromId is Guid parentId)
            parent = await db.CertProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == parentId, ct);
        return ProfileResolutionService.ForLoadedRows(NullLogger<ProfileResolutionService>.Instance)
            .ResolveLoaded(profile, parent).ExpiryWarnings;
    }

    /// <summary>
    /// Command timeout of the re-compute, which rewrites every live certificate of a profile in
    /// one statement: well past the 30-second default.
    /// </summary>
    public static readonly TimeSpan RecomputeCommandTimeout = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Saves the pending changes of <paramref name="db"/> and re-computes the expiry warning
    /// instants for each profile of <paramref name="profileIds"/>
    /// (<see cref="RecomputeAfterProfileChangeAsync"/>) in one transaction, so a re-compute that
    /// fails leaves the profile change unsaved as well, and saving the same values again
    /// re-computes again. The re-compute runs at <see cref="RecomputeCommandTimeout"/>.
    /// </summary>
    /// <remarks>
    /// The work runs under the context's execution strategy with the save accepted only after the
    /// commit, so a retrying strategy can run it again whole. Inside a transaction the caller began,
    /// it joins that transaction. With no profile to re-compute it only saves. The in-memory
    /// provider has no transactions: it saves, then re-computes.
    /// </remarks>
    /// <returns>How many certificates were re-computed.</returns>
    public static async Task<int> SaveAndRecomputeAsync(ModularCADbContext db, IReadOnlyCollection<Guid> profileIds, DateTime now,
        CancellationToken ct = default)
    {
        if (profileIds.Count == 0)
        {
            await db.SaveChangesAsync(ct);
            return 0;
        }
        if (!db.Database.IsRelational() || db.Database.CurrentTransaction != null)
        {
            await db.SaveChangesAsync(ct);
            return await RecomputeEachAsync(db, profileIds, now, ct);
        }

        return await db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            await db.SaveChangesAsync(acceptAllChangesOnSuccess: false, ct);
            var rows = await RecomputeEachAsync(db, profileIds, now, ct);
            await transaction.CommitAsync(ct);
            db.ChangeTracker.AcceptAllChanges();
            return rows;
        });
    }

    /// <summary><see cref="RecomputeAfterProfileChangeAsync"/> for each of <paramref name="profileIds"/>, at <see cref="RecomputeCommandTimeout"/>.</summary>
    private static async Task<int> RecomputeEachAsync(ModularCADbContext db, IReadOnlyCollection<Guid> profileIds, DateTime now, CancellationToken ct)
    {
        var relational = db.Database.IsRelational();
        var previousTimeout = relational ? db.Database.GetCommandTimeout() : null;
        if (relational)
            db.Database.SetCommandTimeout(RecomputeCommandTimeout);
        try
        {
            var rows = 0;
            foreach (var id in profileIds)
                rows += await RecomputeAfterProfileChangeAsync(db, id, now, ct);
            return rows;
        }
        finally
        {
            if (relational)
                db.Database.SetCommandTimeout(previousTimeout);
        }
    }

    /// <summary>
    /// Re-computes the expiry warning instants of the live certificates (not revoked, not expired
    /// at <paramref name="now"/>) issued under <paramref name="profileId"/> and under every profile
    /// that inherits from it, from those profiles' settings as they are now. One UPDATE per profile
    /// on PostgreSQL; certificate by certificate elsewhere.
    /// </summary>
    /// <returns>How many certificates were re-computed.</returns>
    public static async Task<int> RecomputeAfterProfileChangeAsync(ModularCADbContext db, Guid profileId, DateTime now, CancellationToken ct = default)
    {
        var profiles = await db.CertProfiles.AsNoTracking()
            .Where(p => p.Id == profileId || (p.InheritanceEnabled && p.InheritsFromId == profileId))
            .ToListAsync(ct);
        var rows = 0;
        foreach (var profile in profiles.OrderBy(p => p.Id == profileId ? 0 : 1))
            rows += await RecomputeAsync(db, profile.Id, await EffectiveSettingsAsync(db, profile, ct), now, ct);
        return rows;
    }

    /// <summary>
    /// Writes the instants <paramref name="settings"/> gives to every live certificate of
    /// <paramref name="profileId"/>, with the same arithmetic as <see cref="ExpiryWarningRule.Compute"/>
    /// (to the microsecond PostgreSQL stores). The SQL works in seconds, never in days, so the
    /// session time zone's daylight saving cannot shift an instant.
    /// </summary>
    /// <returns>How many certificates were updated.</returns>
    public static async Task<int> RecomputeAsync(ModularCADbContext db, Guid profileId, ExpiryWarningSettings settings, DateTime now, CancellationToken ct = default)
    {
        if (!db.Database.IsRelational())
        {
            var certs = await db.Certificates
                .Where(c => c.CertProfileId == profileId && !c.Revoked && c.NotAfter > now)
                .ToListAsync(ct);
            foreach (var c in certs)
                (c.ExpiryWarningAt, c.ExpiryAlertAt) = ExpiryWarningRule.Compute(c.NotBefore, c.NotAfter, c.IsCA, settings);
            await db.SaveChangesAsync(ct);
            return certs.Count;
        }

        var (neverWarn, warning, alert) = ExpiryWarningRule.Plan(settings);
        double Seconds(TimeSpan? span) => span is TimeSpan s ? s.TotalSeconds : -1;
        return await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "Certificates" AS c
            SET "ExpiryWarningAt" = c."NotAfter" - make_interval(secs => w.warning),
                "ExpiryAlertAt" = c."NotAfter" - make_interval(secs => LEAST(w.alert, w.warning))
            FROM (
                SELECT x."CertificateId",
                    CASE WHEN {neverWarn} THEN 0
                         WHEN x."IsCA" AND {Seconds(warning.CaWindow)} >= 0 THEN LEAST({Seconds(warning.CaWindow)}, x.life)
                         ELSE LEAST(x.life * {(double)warning.Percent} / 100,
                                    CASE WHEN {Seconds(warning.Cap)} >= 0 THEN {Seconds(warning.Cap)} ELSE x.life END)
                    END AS warning,
                    CASE WHEN {neverWarn} THEN 0
                         WHEN x."IsCA" AND {Seconds(alert.CaWindow)} >= 0 THEN LEAST({Seconds(alert.CaWindow)}, x.life)
                         ELSE LEAST(x.life * {(double)alert.Percent} / 100,
                                    CASE WHEN {Seconds(alert.Cap)} >= 0 THEN {Seconds(alert.Cap)} ELSE x.life END)
                    END AS alert
                FROM (
                    SELECT "CertificateId", "IsCA",
                        GREATEST(EXTRACT(EPOCH FROM ("NotAfter" - "NotBefore"))::double precision, 0) AS life
                    FROM "Certificates"
                    WHERE "CertProfileId" = {profileId} AND NOT "Revoked" AND "NotAfter" > {now}
                ) AS x
            ) AS w
            WHERE c."CertificateId" = w."CertificateId"
            """, ct);
    }
}
