namespace ModularCA.Migrate;

/// <summary>
/// The order of a run once preflight has passed. The destination is built at the frozen
/// baselines; the 0.3.0 rows are copied into them and checked against the source while both are
/// still the same shape; only then are the later migrations applied, so the copied data goes
/// through every precondition and transformation an upgrade does; and only after that is the
/// configuration written. Any failure before the configuration is written rolls back everything
/// the run created, unless the operator asked to keep it.
/// </summary>
public static class MigrationRun
{
    /// <summary>The stages of a run, in the order <see cref="ExecuteAsync"/> calls them.</summary>
    public interface IStages
    {
        /// <summary>Creates the roles and databases and applies the frozen baselines.</summary>
        Task BuildAtBaselineAsync(CancellationToken ct);

        /// <summary>Copies the source into the baseline schema.</summary>
        Task CopyAsync(CancellationToken ct);

        /// <summary>Checks the copy against the source at the baseline stage; returns every problem found.</summary>
        Task<IReadOnlyList<string>> VerifyCopyAsync(CancellationToken ct);

        /// <summary>Applies every later migration as the runtime roles; throws on a refusal.</summary>
        Task ApplyUpgradeMigrationsAsync(CancellationToken ct);

        /// <summary>Writes the configuration and reports the result.</summary>
        Task ConfigureAsync(CancellationToken ct);

        /// <summary>Drops everything the run created.</summary>
        Task RollbackAsync(CancellationToken ct);
    }

    /// <summary>
    /// Runs the stages in order. Returns true when the configuration was written; false after a
    /// failure, which is reported through <paramref name="error"/> and rolled back unless
    /// <paramref name="keepOnFailure"/>; <paramref name="databases"/> names what would be kept.
    /// </summary>
    public static async Task<bool> ExecuteAsync(
        IStages stages, bool keepOnFailure, string databases, Action<string> say, Action<string> error, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stages);
        try
        {
            say("Creating the destination at the frozen baselines");
            await stages.BuildAtBaselineAsync(ct);
            say("");

            await stages.CopyAsync(ct);

            say("Verifying the copy against the source, before any later migration changes it");
            var failures = await stages.VerifyCopyAsync(ct);
            if (failures.Count > 0)
            {
                error("");
                error($"Verification failed. {failures.Count} problem(s):");
                foreach (var failure in failures)
                    error($"  - {failure}");
                throw new MigrationFailedException("verification failed");
            }
            say("");

            say("Applying the migrations after the baselines, as an upgrade would");
            await stages.ApplyUpgradeMigrationsAsync(ct);
            say("");

            await stages.ConfigureAsync(ct);
            return true;
        }
        catch (Exception ex)
        {
            error("");
            error($"(!) Migration failed: {ex.Message}");
            if (keepOnFailure)
            {
                error($"    The half-built databases {databases} were left in place for inspection (--keep-on-failure). "
                    + "Drop them before re-running.");
                return false;
            }
            error("    Removing anything this run created:");
            await stages.RollbackAsync(CancellationToken.None);
            error("    The source was not touched. Fix the problem above and run again.");
            return false;
        }
    }
}
