using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Core.Services;

/// <summary>
/// When the CRLs in force start to expire. In a mode that signs no new CRL (DR mode) that moment
/// is a deadline: from then on a relying party that checks a CRL sees an expired one, until the
/// mode is lifted. The console's mode card and the hub's mode record both say it.
/// </summary>
public static class CrlDeadline
{
    /// <summary>
    /// The earliest <c>nextUpdate</c> among the newest full CRLs of the enabled X.509 CAs, as UTC;
    /// null when none has been signed. A read of what is stored: it signs nothing.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public static async Task<DateTime?> EarliestNextUpdateAsync(ModularCADbContext db, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var nextUpdates = await db.CertificateAuthorities.AsNoTracking()
            .Where(ca => !ca.IsSshCa && ca.IsEnabled)
            .Select(ca => db.Crls
                .Where(c => !c.IsDelta && c.Task!.CaCertificateId == ca.CertificateId)
                .OrderByDescending(c => c.CrlNumber)
                .Select(c => (DateTime?)c.NextUpdate)
                .FirstOrDefault())
            .ToListAsync(cancellationToken);
        var known = nextUpdates.Where(n => n != null).Select(n => DateTime.SpecifyKind(n!.Value, DateTimeKind.Utc)).ToList();
        return known.Count == 0 ? null : known.Min();
    }

    /// <summary>
    /// For each of <paramref name="caIds"/> that is a CA of this instance: its name and the
    /// <c>nextUpdate</c> of its newest stored full CRL, as UTC, which is when the CRL now
    /// published for it runs out; null when it has none. A read of what is stored.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="caIds">The CAs asked about.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public static async Task<IReadOnlyDictionary<Guid, (string Name, DateTime? NextUpdateUtc)>> PublishedForAsync(
        ModularCADbContext db, IReadOnlyCollection<Guid> caIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        if (caIds.Count == 0)
            return new Dictionary<Guid, (string, DateTime?)>();
        var rows = await db.CertificateAuthorities.AsNoTracking()
            .Where(ca => caIds.Contains(ca.Id))
            .Select(ca => new
            {
                ca.Id,
                ca.Name,
                NextUpdate = db.Crls
                    .Where(c => !c.IsDelta && c.Task!.CaCertificateId == ca.CertificateId)
                    .OrderByDescending(c => c.CrlNumber)
                    .Select(c => (DateTime?)c.NextUpdate)
                    .FirstOrDefault(),
            })
            .ToListAsync(cancellationToken);
        return rows.ToDictionary(r => r.Id,
            r => (r.Name, r.NextUpdate is DateTime next ? DateTime.SpecifyKind(next, DateTimeKind.Utc) : (DateTime?)null));
    }
}
