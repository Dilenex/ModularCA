using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Database.ProbeMigrations;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// <c>--upgrade-check --read-only</c> against a real PostgreSQL server (<c>MODULARCA_TEST_PG</c>,
/// a superuser connection string): the check an orchestrator runs beside a node that is still
/// serving. It exits 0 with nothing to apply and 5 with migrations pending, which it names and
/// does not rehearse; it refuses with 3, in the words of the full check, whatever can be refused
/// without a rehearsal; it finishes while another session holds the locks the rehearsal would
/// wait for; and the server refuses a write on its connection. Each test builds throwaway roles
/// and databases (<see cref="OwnershipFixture"/>) and drops them afterwards.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Three)]
public sealed class PostgresUpgradeCheckReadOnlyTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";
    private const string ProbePending = "20990201000002_ProbeAlter";
    private const string NothingToApply = "UPGRADE CHECK: PASS (nothing to apply). Nothing was changed.";

    private static string Server => Environment.GetEnvironmentVariable(ServerVariable)!;

    /// <summary>
    /// One migration pending in each database, and a session in each that holds, as a serving node
    /// does inside a request, ACCESS SHARE on the table that migration alters. The read-only check
    /// exits 5 and names the migration per database on a last line that is not an
    /// <c>UPGRADE CHECK:</c> line; every context it built was on the read-only connection, none on
    /// a migration connection. The full check, run next against the same sessions, cannot get the
    /// locks its rehearsal needs and exits 75: the read-only check did not ask for them.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Pending_migrations_exit_5_named_per_database_without_a_rehearsal_beside_sessions_that_block_one()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        await f.SeedProbeHistoryAsync(f.AppDatabase, AppProbeContext.History, f.App.Username);
        await f.SeedProbeHistoryAsync(f.AuditDatabase, AuditProbeContext.History, f.Audit.Username);
        var opened = new ConcurrentQueue<string>();
        SchemaStartupApi.UseContextFactory((kind, cs, timeout) =>
        {
            opened.Enqueue(cs);
            return kind == DatabaseKind.Application
                ? new AppProbeContext(ProbeOptions.For<AppProbeContext>(cs, timeout, AppProbeContext.History))
                : new AuditProbeContext(ProbeOptions.For<AuditProbeContext>(cs, timeout, AuditProbeContext.History));
        });
        var install = Path.Combine(Path.GetTempPath(), $"mca-upgrade-ro-{Guid.NewGuid():N}");

        await using var appSession = await ServingSessionAsync(f, f.App, "SELECT count(*) FROM public.\"Users\"");
        await using var auditSession = await ServingSessionAsync(f, f.Audit, "SELECT count(*) FROM public.\"AuditLogs\"");

        var clock = Stopwatch.StartNew();
        var (exit, report) = await CheckAsync(f.Targets(), readOnly: true,
            scopes: [("IntegrationApi.SpaceId", "instance")], installDirectory: install);
        var took = clock.Elapsed;

        Assert.True(exit == 5, report);
        Assert.Equal($"UPGRADE PENDING, NOT REHEARSED (application: {ProbePending}; audit: {ProbePending}). "
            + "Nothing was rehearsed and nothing was changed: stop the node and run --upgrade-check without --read-only before upgrading.",
            LastLine(report));
        Assert.DoesNotContain(Lines(report), l => l.StartsWith("UPGRADE CHECK: ", StringComparison.Ordinal));
        Assert.Equal(2, Lines(report).Count(l => l == "  dry run: not run (--read-only); no migration lock was taken."));
        Assert.Equal(2, Lines(report).Count(l => l.StartsWith($"  PENDING, NOT REHEARSED: 1 migration(s) pending: {ProbePending}.", StringComparison.Ordinal)));
        Assert.DoesNotContain("dry run: passed", report);
        Assert.DoesNotContain("REFUSED", report);
        Assert.Contains("configuration: integration key scopes", report);
        Assert.Contains("SSH CA keys: key files on this host", report);
        Assert.True(took < TimeSpan.FromSeconds(30), $"took {took}");

        // No context was built on a migration connection: nothing could have rehearsed or locked.
        Assert.NotEmpty(opened);
        Assert.All(opened, cs => Assert.Contains("default_transaction_read_only=on", cs));
        Assert.All(opened, cs => Assert.Contains("lock_timeout=500", cs));
        opened.Clear();

        // The same sessions stop the rehearsal: it waits for ACCESS EXCLUSIVE on the table each holds.
        var (full, fullReport) = await CheckAsync(f.Targets(), readOnly: false, new SchemaConfig { MigrationLockTimeoutSeconds = 1 });
        Assert.True(full == 75, fullReport);
        Assert.StartsWith("UPGRADE CHECK: UNREACHABLE (application dry run hit a transient error", LastLine(fullReport));
        Assert.Contains(opened, cs => !cs.Contains("default_transaction_read_only", StringComparison.Ordinal));

        await appSession.DisposeAsync();
        await auditSession.DisposeAsync();
        Assert.Equal(1, await f.CountAsync(f.AppDatabase, $"SELECT count(*) FROM public.\"{AppProbeContext.History}\""));
        Assert.Equal(1, await f.CountAsync(f.AuditDatabase, $"SELECT count(*) FROM public.\"{AuditProbeContext.History}\""));
        Assert.Equal(0, await f.ColumnCountAsync(f.AppDatabase, "Users", "GateProbe"));
        Assert.Equal(0, await f.ColumnCountAsync(f.AuditDatabase, "AuditLogs", "GateProbe"));
    }

    /// <summary>
    /// A current install has nothing to apply: 0, on the line the full check prints. Then, one at a
    /// time, what is refused without a rehearsal: an integration key scoped to no space, a schema
    /// newer than the build, and tables with no migration history. Each exits 3 with the same
    /// verdict line as the full check.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Nothing_pending_exits_0_and_what_needs_no_rehearsal_is_refused_with_3_in_the_full_checks_words()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        var history = "SELECT count(*) FROM public.\"__EFMigrationsHistory\"";
        var applied = await f.CountAsync(f.AppDatabase, history);

        var (exit, report) = await CheckAsync(f.Targets(), readOnly: true);
        Assert.True(exit == 0, report);
        Assert.Equal(NothingToApply, LastLine(report));
        Assert.DoesNotContain("NOT REHEARSED", report);
        Assert.Equal(NothingToApply, LastLine((await CheckAsync(f.Targets(), readOnly: false)).Report));

        IReadOnlyList<(string Key, string Value)> strayScope = [("CertManager.SpaceId", Guid.NewGuid().ToString())];
        await AssertRefusedAlikeAsync(f.Targets(),
            "UPGRADE CHECK: REFUSED (configuration: CertManager.SpaceId scoped to no existing space). Nothing was changed.", scopes: strayScope);

        await f.ExecuteAsync(f.AuditDatabase, "INSERT INTO public.\"__EFMigrationsHistory\" VALUES ('29990101000000_FromALaterBuild', '10.0.0')");
        await AssertRefusedAlikeAsync(f.Targets(), "UPGRADE CHECK: REFUSED (audit: schema newer than this build). Nothing was changed.");
        await f.ExecuteAsync(f.AuditDatabase, "DELETE FROM public.\"__EFMigrationsHistory\" WHERE \"MigrationId\" = '29990101000000_FromALaterBuild'");

        await f.ExecuteAsync(f.AuditDatabase, "CREATE TABLE public.history_kept AS TABLE public.\"__EFMigrationsHistory\"; DELETE FROM public.\"__EFMigrationsHistory\"");
        await AssertRefusedAlikeAsync([f.Targets()[1]], "UPGRADE CHECK: REFUSED (audit: tables but no migration history). Nothing was changed.");

        Assert.Equal(applied, await f.CountAsync(f.AppDatabase, history));
        Assert.Equal(0, await f.CountAsync(f.AuditDatabase, history));
    }

    /// <summary>
    /// The 0.3.1 layout, at the baselines: the application role cannot read its own tables and the
    /// audit role does not own the tables its pending migrations alter. Both are refused with 3,
    /// in the full check's words, and the pending migrations are not reported as merely pending.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Ownership_that_is_not_sound_is_refused_with_3_though_migrations_are_pending()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Legacy);

        var report = await AssertRefusedAlikeAsync(f.Targets(),
            "UPGRADE CHECK: REFUSED (application: could not be read; audit: ownership not sound). Nothing was changed.");

        Assert.Contains("adopt-ownership.sql", report);
        Assert.DoesNotContain("NOT REHEARSED", report);
        Assert.DoesNotContain("dry run:", report);
    }

    /// <summary>
    /// What a build alone decides is refused without a rehearsal too: a model that differs from its
    /// latest migration, and a pending migration with a statement outside a transaction, which the
    /// full check could not rehearse either. Both verdict lines are the full check's.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_defective_build_is_refused_with_3_without_a_rehearsal()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        IReadOnlyList<(string Name, DatabaseKind Kind, DbInstance Instance)> application = [f.Targets()[0]];

        await f.SeedProbeHistoryAsync(f.AppDatabase, DriftProbeContext.History, f.App.Username);
        SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
            new DriftProbeContext(ProbeOptions.For<DriftProbeContext>(cs, timeout, DriftProbeContext.History)));
        await AssertRefusedAlikeAsync(application, "UPGRADE CHECK: REFUSED (application: defective build). Nothing was changed.");

        await f.SeedProbeHistoryAsync(f.AppDatabase, NonTransactionalProbeContext.History, f.App.Username);
        SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
            new NonTransactionalProbeContext(ProbeOptions.For<NonTransactionalProbeContext>(cs, timeout, NonTransactionalProbeContext.History)));
        var report = await AssertRefusedAlikeAsync(application,
            "UPGRADE CHECK: REFUSED (application: migration 20990201000002_ProbeNonTransactional cannot be rehearsed). Nothing was changed.");
        Assert.Contains("This build is defective: install a correct build.", report);

        Assert.Equal(0, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname IN ('gate_probe_nt', 'gate_probe_drift')"));
    }

    /// <summary>
    /// A 0.3.x database with every later migration pending and an enabled SSH CA whose key file is
    /// not on this host: the read-only check refuses with 3 for the key file, the finding the full
    /// check has, while reporting the migrations as pending and not rehearsed.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_missing_ssh_ca_key_file_is_refused_with_3_while_the_migrations_stay_unrehearsed()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh, atBaseline: true);
        var ca = Guid.NewGuid();
        var key = Guid.NewGuid();
        var publicKey = ModularCA.Tests.Ssh.SshFixtures.Text("ca-ed25519.pub").Trim();
        await f.ExecuteAsRuntimeAsync(f.App, PostgresUpgradeHarnessTests.Seed030Sql
            + PostgresUpgradeHarnessTests.SeedSshCaWithKeyFileSql(ca, key, publicKey));
        var install = Path.Combine(Path.GetTempPath(), $"mca-upgrade-ro-{Guid.NewGuid():N}");
        var history = "SELECT count(*) FROM public.\"__EFMigrationsHistory\"";

        var (exit, report) = await CheckAsync(f.Targets(), readOnly: true, installDirectory: install);

        Assert.True(exit == 3, report);
        Assert.Equal("UPGRADE CHECK: REFUSED (SSH CA keys: 1 key file(s) missing or not matching). Nothing was changed.", LastLine(report));
        Assert.Contains("REFUSED: 1 SSH CA key file(s) are missing or do not hold their SSH CA's key.", report);
        Assert.Equal(2, Lines(report).Count(l => l.StartsWith("  PENDING, NOT REHEARSED: ", StringComparison.Ordinal)));
        Assert.DoesNotContain("dry run: passed", report);
        Assert.Equal(1, await f.CountAsync(f.AppDatabase, history));
        Assert.Equal(1, await f.CountAsync(f.AuditDatabase, history));
    }

    /// <summary>
    /// A migration in progress holds ACCESS EXCLUSIVE on the migration history. The read-only
    /// check does not queue behind it: it exits 75 with the full check's line, and soon.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Behind_a_migration_in_progress_it_exits_75_without_waiting_for_the_lock()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        await using var holder = new NpgsqlConnection(f.AdminConnectionString(f.AppDatabase));
        await holder.OpenAsync();
        await using var tx = await holder.BeginTransactionAsync();
        await new NpgsqlCommand("LOCK TABLE public.\"__EFMigrationsHistory\" IN ACCESS EXCLUSIVE MODE", holder, tx).ExecuteNonQueryAsync();

        var clock = Stopwatch.StartNew();
        var (exit, report) = await CheckAsync(f.Targets(), readOnly: true);
        var took = clock.Elapsed;

        Assert.True(exit == 75, report);
        Assert.Equal("UPGRADE CHECK: UNREACHABLE (application is locked, most likely by a migration in progress); try again. Nothing was changed.",
            LastLine(report));
        Assert.True(took < TimeSpan.FromSeconds(10), $"took {took}");

        await tx.RollbackAsync();
        (exit, report) = await CheckAsync(f.Targets(), readOnly: true);
        Assert.True(exit == 0, report);
    }

    /// <summary>
    /// The connection the read-only check reads with, as the application's runtime role, which owns
    /// its tables: the server itself refuses DDL and DML on it (25006), in and out of an explicit
    /// transaction, and its lock timeout is half a second. (A read-only transaction may still
    /// take a lock with LOCK TABLE; the check has no such statement, and the first test shows it
    /// builds nothing on a migration connection, the only place the product locks.)
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_server_refuses_every_write_on_the_read_only_checks_connection()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        await using var connection = new NpgsqlConnection(SchemaStartupApi.ReadOnlyCheckConnectionString(f.App));
        await connection.OpenAsync();

        Assert.Equal("on", (string?)await new NpgsqlCommand("SHOW default_transaction_read_only", connection).ExecuteScalarAsync());
        Assert.Equal("500ms", (string?)await new NpgsqlCommand("SHOW lock_timeout", connection).ExecuteScalarAsync());
        foreach (var write in new[]
                 {
                     "CREATE TABLE public.read_only_probe (id integer)",
                     "ALTER TABLE public.\"Users\" ADD COLUMN \"ReadOnlyProbe\" integer",
                     "DELETE FROM public.\"__EFMigrationsHistory\"",
                     "INSERT INTO public.\"__EFMigrationsHistory\" VALUES ('29990101000000_Probe', '10.0.0')",
                     "UPDATE public.\"Users\" SET \"Username\" = \"Username\"",
                 })
        {
            var refused = await Assert.ThrowsAsync<PostgresException>(() => new NpgsqlCommand(write, connection).ExecuteNonQueryAsync());
            Assert.True(refused.SqlState == "25006", $"{write}: {refused.SqlState} {refused.MessageText}");

            await using var transaction = await connection.BeginTransactionAsync();
            refused = await Assert.ThrowsAsync<PostgresException>(() => new NpgsqlCommand(write, connection, transaction).ExecuteNonQueryAsync());
            Assert.True(refused.SqlState == "25006", $"{write} in a transaction: {refused.SqlState} {refused.MessageText}");
            await transaction.RollbackAsync();
        }
        Assert.True(await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\"") > 0);
    }

    /// <summary>
    /// Runs the check both ways and asserts each exits 3 with <paramref name="verdict"/> as its
    /// last line, so the read-only check refuses in the full check's words. Returns the read-only
    /// report.
    /// </summary>
    private static async Task<string> AssertRefusedAlikeAsync(
        IReadOnlyList<(string Name, DatabaseKind Kind, DbInstance Instance)> targets, string verdict,
        IReadOnlyList<(string Key, string Value)>? scopes = null)
    {
        var (full, fullReport) = await CheckAsync(targets, readOnly: false, scopes: scopes);
        var (readOnly, readOnlyReport) = await CheckAsync(targets, readOnly: true, scopes: scopes);

        Assert.True(full == 3, fullReport);
        Assert.True(readOnly == 3, readOnlyReport);
        Assert.Equal(verdict, LastLine(fullReport));
        Assert.Equal(verdict, LastLine(readOnlyReport));
        return readOnlyReport;
    }

    /// <summary>Runs <c>SchemaStartup.UpgradeCheckAsync</c> and returns its exit status and report.</summary>
    private static async Task<(int Exit, string Report)> CheckAsync(
        IReadOnlyList<(string Name, DatabaseKind Kind, DbInstance Instance)> targets, bool readOnly, SchemaConfig? config = null,
        IReadOnlyList<(string Key, string Value)>? scopes = null, string? installDirectory = null)
    {
        var output = new StringWriter();
        var exit = await SchemaStartupApi.UpgradeCheckAsync(targets, config ?? new SchemaConfig(), output, scopes, installDirectory, readOnly);
        return (exit, output.ToString());
    }

    /// <summary>
    /// A session as <paramref name="instance"/>'s runtime role with a transaction left open after
    /// <paramref name="query"/>, so it holds ACCESS SHARE on what the query read, as a node does
    /// while it serves a request. Disposing it rolls back.
    /// </summary>
    private static async Task<NpgsqlConnection> ServingSessionAsync(OwnershipFixture f, DbInstance instance, string query)
    {
        var connection = new NpgsqlConnection(f.RuntimeConnectionString(instance, instance.Database));
        await connection.OpenAsync();
        await new NpgsqlCommand("BEGIN", connection).ExecuteNonQueryAsync();
        await new NpgsqlCommand(query, connection).ExecuteScalarAsync();
        return connection;
    }

    /// <summary>The report's lines, without line ends.</summary>
    private static List<string> Lines(string report) =>
        report.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0).ToList();

    /// <summary>The report's last line: the verdict.</summary>
    private static string LastLine(string report) => Lines(report)[^1];
}
