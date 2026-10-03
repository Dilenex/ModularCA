using ModularCA.Migrate;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// The order of a run after preflight, with fake stages: the copy lands in the baselines and is
/// verified there before any later migration runs; a refusal from a later migration is the run's
/// failure, with its message, and is rolled back; nothing is configured after a failure.
/// </summary>
public class MigrationRunTests
{
    private sealed class FakeStages : MigrationRun.IStages
    {
        public List<string> Calls { get; } = [];
        public IReadOnlyList<string> VerifyFailures { get; init; } = [];
        public Exception? ApplyThrows { get; init; }
        public Exception? CopyThrows { get; init; }

        public Task BuildAtBaselineAsync(CancellationToken ct) { Calls.Add("build"); return Task.CompletedTask; }

        public Task CopyAsync(CancellationToken ct)
        {
            Calls.Add("copy");
            return CopyThrows is null ? Task.CompletedTask : Task.FromException(CopyThrows);
        }

        public Task<IReadOnlyList<string>> VerifyCopyAsync(CancellationToken ct) { Calls.Add("verify"); return Task.FromResult(VerifyFailures); }

        public Task ApplyUpgradeMigrationsAsync(CancellationToken ct)
        {
            Calls.Add("apply");
            return ApplyThrows is null ? Task.CompletedTask : Task.FromException(ApplyThrows);
        }

        public Task ConfigureAsync(CancellationToken ct) { Calls.Add("configure"); return Task.CompletedTask; }

        public Task RollbackAsync(CancellationToken ct) { Calls.Add("rollback"); return Task.CompletedTask; }
    }

    private static async Task<(bool Ok, List<string> Errors)> RunAsync(FakeStages stages, bool keep = false)
    {
        var errors = new List<string>();
        var ok = await MigrationRun.ExecuteAsync(stages, keep, "'app' and 'audit'", _ => { }, errors.Add, CancellationToken.None);
        return (ok, errors);
    }

    [Fact]
    public async Task The_copy_is_verified_at_the_baseline_before_the_later_migrations_and_configured_last()
    {
        var stages = new FakeStages();
        var (ok, errors) = await RunAsync(stages);

        Assert.True(ok);
        Assert.Empty(errors);
        Assert.Equal(["build", "copy", "verify", "apply", "configure"], stages.Calls);
    }

    [Fact]
    public async Task A_copy_that_fails_verification_is_never_migrated_and_is_rolled_back()
    {
        var stages = new FakeStages { VerifyFailures = ["Tenants: 2 rows on the source, 1 on the destination."] };
        var (ok, errors) = await RunAsync(stages);

        Assert.False(ok);
        Assert.Equal(["build", "copy", "verify", "rollback"], stages.Calls);
        Assert.Contains(errors, e => e.Contains("Tenants: 2 rows on the source"));
    }

    [Fact]
    public async Task A_refusal_by_a_later_migration_is_the_runs_failure_and_is_rolled_back()
    {
        var refusal = "migration 20260929051025_FoldSystemTenant of the application database failed on the copied data: "
            + "PostgresException P0001: This instance has 2 SecurityPolicy rows.";
        var stages = new FakeStages { ApplyThrows = new MigrationFailedException(refusal) };
        var (ok, errors) = await RunAsync(stages);

        Assert.False(ok);
        Assert.Equal(["build", "copy", "verify", "apply", "rollback"], stages.Calls);
        Assert.Contains(errors, e => e.Contains(refusal));
        Assert.Contains(errors, e => e.Contains("The source was not touched"));
    }

    [Fact]
    public async Task Keep_on_failure_leaves_the_destination_and_names_it()
    {
        var stages = new FakeStages { ApplyThrows = new MigrationFailedException("refused") };
        var (ok, errors) = await RunAsync(stages, keep: true);

        Assert.False(ok);
        Assert.DoesNotContain("rollback", stages.Calls);
        Assert.Contains(errors, e => e.Contains("'app' and 'audit'") && e.Contains("--keep-on-failure"));
    }

    [Fact]
    public async Task Any_failure_after_the_build_rolls_back()
    {
        var stages = new FakeStages { CopyThrows = new InvalidOperationException("Tenants.Slug: cannot be represented") };
        var (ok, errors) = await RunAsync(stages);

        Assert.False(ok);
        Assert.Equal(["build", "copy", "rollback"], stages.Calls);
        Assert.Contains(errors, e => e.Contains("cannot be represented"));
    }
}
