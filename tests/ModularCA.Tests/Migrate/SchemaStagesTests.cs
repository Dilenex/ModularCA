using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Migrate;
using ModularCA.Tests.Database.GateMigrations;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// The helper's two schema stages, on SQLite with the gate tests' four migrations (A is the
/// baseline): only the baseline before the copy; every later migration after it, through the
/// gate, with a failure reported as the run's failure and what it committed left for the rollback.
/// </summary>
public sealed class SchemaStagesTests : IDisposable
{
    private const string A = "20990101000001_A";
    private const string B1 = "20990101000002_B1";
    private const string B2 = "20990101000003_B2";
    private const string C = "20990101000004_C";

    private readonly string _path = Path.Combine(Path.GetTempPath(), $"modularca-stages-{Guid.NewGuid():N}.db");

    /// <summary>Deletes the temporary database file.</summary>
    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { File.Delete(_path); } catch (IOException) { }
    }

    [Fact]
    public async Task Before_the_copy_only_the_baseline_is_applied()
    {
        Execute("SELECT 1");
        await using var db = Context();

        await SchemaStages.ApplyBaselineAsync(db, A, "application", CancellationToken.None);

        var state = await SchemaVersionGate.ReadAsync(db);
        Assert.Equal([A], state.Applied);
        Assert.Equal([B1, B2, C], state.Pending);
    }

    [Fact]
    public async Task A_baseline_that_is_not_the_first_migration_or_a_database_that_is_not_empty_is_refused()
    {
        Execute("SELECT 1");
        await using (var db = Context())
            await Assert.ThrowsAsync<InvalidOperationException>(() => SchemaStages.ApplyBaselineAsync(db, B1, "application", CancellationToken.None));

        Execute("CREATE TABLE copied (id INTEGER)");
        await using (var db = Context())
            await Assert.ThrowsAsync<InvalidOperationException>(() => SchemaStages.ApplyBaselineAsync(db, A, "application", CancellationToken.None));
    }

    [Fact]
    public async Task After_the_copy_every_later_migration_is_applied()
    {
        Execute("SELECT 1");
        await using var db = Context();
        await SchemaStages.ApplyBaselineAsync(db, A, "application", CancellationToken.None);
        Execute("INSERT INTO a VALUES (1)");

        var applied = await SchemaStages.ApplyLaterAsync(db, "application", CancellationToken.None);

        Assert.Equal([B1, B2, C], applied);
        Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(await SchemaVersionGate.ReadAsync(db), appliesMigrations: false));
        Assert.Empty(await SchemaStages.ApplyLaterAsync(db, "application", CancellationToken.None));
    }

    [Fact]
    public async Task A_migration_that_fails_on_the_copied_data_fails_the_run_naming_it_and_what_was_committed()
    {
        Execute("SELECT 1");
        await using var db = Context();
        await SchemaStages.ApplyBaselineAsync(db, A, "application", CancellationToken.None);
        Execute("CREATE TABLE c (id INTEGER)");

        var failed = await Assert.ThrowsAsync<MigrationFailedException>(() => SchemaStages.ApplyLaterAsync(db, "application", CancellationToken.None));

        Assert.Contains($"migration {C} of the application database failed on the copied data", failed.Message);
        Assert.Contains("table c already exists", failed.Message);
        Assert.Contains($"Committed before it: {B1}, {B2}.", failed.Message);
        Assert.Equal([A, B1, B2], (await SchemaVersionGate.ReadAsync(db)).Applied);
    }

    [Fact]
    public async Task A_database_recording_a_migration_this_build_does_not_know_is_refused_before_anything_is_applied()
    {
        Execute("SELECT 1");
        await using var db = Context();
        await SchemaStages.ApplyBaselineAsync(db, A, "audit", CancellationToken.None);
        Execute("INSERT INTO \"__EFMigrationsHistory\" VALUES ('20991231000000_Future', '10.0.12');");

        var refused = await Assert.ThrowsAsync<MigrationFailedException>(() => SchemaStages.ApplyLaterAsync(db, "audit", CancellationToken.None));

        Assert.Contains("20991231000000_Future", refused.Message);
        Assert.DoesNotContain(B1, (await SchemaVersionGate.ReadAsync(db)).Applied);
    }

    /// <summary>A context on the temporary file, unpooled so the file can be deleted.</summary>
    private GateTestContext Context() =>
        new(new DbContextOptionsBuilder<GateTestContext>().UseSqlite($"Data Source={_path};Pooling=False").Options);

    /// <summary>Runs <paramref name="sql"/> on its own connection.</summary>
    private void Execute(string sql)
    {
        using var connection = new SqliteConnection($"Data Source={_path};Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
