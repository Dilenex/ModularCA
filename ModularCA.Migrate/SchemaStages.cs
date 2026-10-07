using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Migrate;

/// <summary>
/// How the helper takes each destination database through its migration history, through
/// <see cref="SchemaVersionGate"/> as the control role does: the frozen baseline before the copy,
/// so the 0.3.0 rows land in the schema they were written for, and every later migration after
/// the copy has been verified, so those rows go through every precondition and transformation an
/// upgraded install's rows go through. A refusal becomes a <see cref="MigrationFailedException"/>
/// naming the migration and its message, which the run's rollback then handles.
/// </summary>
public static class SchemaStages
{
    /// <summary>Applies only <paramref name="baseline"/> to the empty database behind <paramref name="db"/>.</summary>
    /// <param name="db">A context on the destination database, as its runtime role.</param>
    /// <param name="baseline">The context's frozen baseline.</param>
    /// <param name="contextName">Which database, for messages.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task ApplyBaselineAsync(DbContext db, string baseline, string contextName, CancellationToken ct)
    {
        ThrowIfFailed(contextName, await SchemaVersionGate.ApplyBaselineForBootstrapAsync(db, baseline, ct));
        var state = await SchemaVersionGate.ReadAsync(db, ct);
        if (state.Applied.Count != 1 || !string.Equals(state.Applied[0], baseline, StringComparison.Ordinal))
            throw new MigrationFailedException(
                $"The {contextName} database records {string.Join(", ", state.Applied)} after applying its baseline, not {baseline} alone.");
    }

    /// <summary>
    /// Applies every migration after the baseline, after checking that this build's model matches
    /// its latest migration and that the database records nothing this build does not know.
    /// Returns the migrations applied.
    /// </summary>
    /// <param name="db">A context on the destination database, as its runtime role.</param>
    /// <param name="contextName">Which database, for messages.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<IReadOnlyList<string>> ApplyLaterAsync(DbContext db, string contextName, CancellationToken ct)
    {
        var state = await SchemaVersionGate.ReadAsync(db, ct);
        var verdict = SchemaVersionGate.Evaluate(state, appliesMigrations: true);
        if (verdict == SchemaVerdict.Current)
            return [];
        if (verdict != SchemaVerdict.ApplyPending)
            throw new MigrationFailedException(
                SchemaVersionGate.RefusalMessage(verdict, state, contextName)
                ?? $"The {contextName} database is {state.Presence} ({verdict}) after the copy.");
        if (db.Database.HasPendingModelChanges())
            throw new MigrationFailedException(
                $"This build's {contextName} model differs from its latest migration; the build is defective. "
                + "Nothing after the copy was applied.");

        ThrowIfFailed(contextName, await SchemaVersionGate.ApplyPendingAsync(db, state, ct));

        var after = await SchemaVersionGate.ReadAsync(db, ct);
        if (SchemaVersionGate.Evaluate(after, appliesMigrations: false) != SchemaVerdict.Current)
            throw new MigrationFailedException(
                $"The {contextName} database still lacks {string.Join(", ", after.Pending)} after its migrations were applied.");
        return state.Pending;
    }

    /// <summary>Throws the failure as the run's failure: the migration, why, and what this step committed.</summary>
    private static void ThrowIfFailed(string contextName, MigrationFailure? failure)
    {
        if (failure is null)
            return;
        var committed = failure.CommittedInThisRun.Count > 0 ? string.Join(", ", failure.CommittedInThisRun) : "none";
        throw new MigrationFailedException(
            $"migration {failure.Migration} of the {contextName} database failed on the copied data: "
            + $"{SchemaFailure.Describe(failure.Error)} Committed before it: {committed}.");
    }
}
