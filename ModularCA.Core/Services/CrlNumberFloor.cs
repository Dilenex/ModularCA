using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Core.Services;

/// <summary>
/// Keeps CRL numbers moving forward across a restore (RFC 5280 §5.2.3). A restored database
/// carries the counters as they were when the backup was taken; any CRL published after that
/// carried a higher number, so allocating from the restored counter would reuse numbers relying
/// parties have already seen. The floor raises every configuration's counter, full and delta
/// alike, to at least the Unix time in seconds at the moment of the restore.
/// </summary>
/// <remarks>
/// A time-derived floor needs nothing that a disaster may have taken with it: no published CRL
/// files, no reachable distribution point. Numbers advance by one per CRL, so the counters of a
/// CA never restored stay far below the current Unix time, and after a floor the counter only
/// overtakes the clock if more than one CRL a second was published on average since then. Full
/// and delta CRLs of a CA share one sequence (<see cref="CrlService"/> allocates from the
/// largest of the configuration's counter and the issuer's CRL rows), so raising both counters
/// to the same floor keeps the shared sequence and the delta's base reference intact. The floor
/// never lowers a counter that is already above it.
/// </remarks>
public static class CrlNumberFloor
{
    /// <summary>One configuration whose counter was raised: its id, issuer, kind, and the counter before and after.</summary>
    public sealed record Raised(Guid TaskId, string? IssuerDn, bool IsDelta, long Before, long After);

    /// <summary>The floor for a restore happening at <paramref name="nowUtc"/>: its Unix time in seconds.</summary>
    public static long FloorAt(DateTimeOffset nowUtc) => nowUtc.ToUnixTimeSeconds();

    /// <summary>
    /// Raises every CRL configuration's <c>LastCrlNumber</c> to at least <paramref name="floor"/>
    /// and makes every configuration due, so the node publishes a CRL above the floor when it
    /// next starts instead of serving the restored one until its schedule comes round. Returns
    /// the configurations whose counter changed.
    /// </summary>
    public static async Task<IReadOnlyList<Raised>> ApplyAsync(ModularCADbContext db, long floor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var raised = new List<Raised>();
        foreach (var config in await db.CrlConfigurations.ToListAsync(cancellationToken))
        {
            config.NextUpdateUtc = DateTime.MinValue;
            if (config.LastCrlNumber >= floor)
                continue;
            raised.Add(new Raised(config.TaskId, config.IssuerDN, config.IsDelta, config.LastCrlNumber, floor));
            config.LastCrlNumber = floor;
        }
        await db.SaveChangesAsync(cancellationToken);
        return raised;
    }
}
