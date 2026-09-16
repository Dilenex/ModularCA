using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services;

/// <summary>
/// Adds feature flags that a newer version introduced to an instance bootstrapped by an older one.
/// </summary>
/// <remarks>
/// <para>
/// Feature flags are rows, seeded once at bootstrap. An instance set up under a version that did
/// not know a flag has no row for it: the settings page cannot show it, the flag API answers 404
/// for it, and the path gate treats it as off. The operator has no supported way to turn the new
/// capability on. Confirmed on a staging host upgraded to the first build with MSAE: the protocol
/// page offered MSAE per CA, the settings page had nothing to enable.
/// </para>
/// <para>
/// This runs at every startup after migrations and inserts only the rows that are missing,
/// always disabled. An upgrade must never switch on a protocol the operator did not choose; it
/// only makes the choice available. Existing rows are never touched, so an operator's setting
/// survives. Flags a version introduces are listed here, beside the bootstrap seeds that create
/// them on a fresh install.
/// </para>
/// </remarks>
public static class FeatureFlagBackfill
{
    /// <summary>Flags introduced after 0.1.0, with the state an upgraded instance receives.</summary>
    public static IReadOnlyList<FeatureFlagEntity> IntroducedFlags { get; } =
    [
        new() { Name = "MSAE.Enabled", Enabled = false, Description = "Enable Windows autoenrollment (MSAE) endpoints" },
    ];

    /// <summary>
    /// Inserts any flag in <see cref="IntroducedFlags"/> that <paramref name="db"/> lacks, and
    /// returns the names added. Existing rows are left as they are.
    /// </summary>
    public static async Task<IReadOnlyList<string>> EnsureAsync(ModularCADbContext db, CancellationToken cancellationToken = default)
    {
        var names = IntroducedFlags.Select(f => f.Name).ToList();
        var present = await db.FeatureFlags
            .Where(f => names.Contains(f.Name))
            .Select(f => f.Name)
            .ToListAsync(cancellationToken);

        var added = new List<string>();
        foreach (var flag in IntroducedFlags)
        {
            if (present.Contains(flag.Name, StringComparer.Ordinal)) continue;
            db.FeatureFlags.Add(new FeatureFlagEntity
            {
                Name = flag.Name,
                Enabled = flag.Enabled,
                Value = flag.Value,
                Description = flag.Description,
                RequiresRestart = flag.RequiresRestart,
            });
            added.Add(flag.Name);
        }

        if (added.Count > 0)
            await db.SaveChangesAsync(cancellationToken);
        return added;
    }
}
