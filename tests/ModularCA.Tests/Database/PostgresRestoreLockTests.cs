using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Serilog.Events;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The lock that keeps a restore and a running process apart (<see cref="RestoreLock"/>), on a
/// real PostgreSQL server with real connections (<c>MODULARCA_TEST_PG</c>): a restore is refused
/// while a node or the signer service holds its key, and a second restore while one runs; a
/// starting process waits for a restore and goes on, or gives up with 75; the commands that are
/// neither run beside every kind of holder; a lock connection that drops is taken again, and a
/// restore that got in meanwhile is not passed over quietly; and the console's restore takes the
/// key on its own node's connection. Each test has roles and databases of its own
/// (<see cref="OwnershipFixture"/>), so no lock here is seen by another test.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Two)]
public sealed class PostgresRestoreLockTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    private static string Server => Environment.GetEnvironmentVariable(ServerVariable)!;

    /// <summary>A restore's lock as the command line takes it, without the grace for a node stopped a moment ago.</summary>
    private static readonly IRestoreExclusion CommandLine = new OwnConnectionRestoreExclusion(TimeSpan.Zero);

    private static string App(OwnershipFixture f) => PostgresConnection.Build(f.App);

    private static ServingDatabaseLock Node(OwnershipFixture f) => new(App(f), RestoreLock.NodeKey, probeInterval: TimeSpan.FromMilliseconds(200));

    private static ServingDatabaseLock Signer(OwnershipFixture f) => new(App(f), RestoreLock.SignerKey, holder: "signer");

    /// <summary>Asserts a verdict that refuses because the database is in use: status 3, the fixed phrases, and who.</summary>
    private static void AssertInUse(RestoreResult? verdict, string who)
    {
        Assert.NotNull(verdict);
        Assert.Equal(RestoreExit.Refused, verdict!.ExitCode);
        Assert.True(verdict.DatabaseInUse);
        Assert.StartsWith(RestoreExit.RefusedMarker + " (", verdict.Verdict);
        Assert.Contains(who, verdict.Verdict);
        Assert.Contains("stop", verdict.Verdict);
        Assert.EndsWith("Nothing was changed.", verdict.Verdict);
        Assert.DoesNotContain('\n', verdict.Verdict);
    }

    /// <summary>How many sessions hold or await an advisory lock of the restore lock's class in the database.</summary>
    private static Task<long> LockSessionsAsync(OwnershipFixture f) => f.CountAsync(f.AppDatabase,
        $"SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database WHERE l.locktype = 'advisory' AND l.classid = {RestoreLock.LockClass} AND d.datname = current_database()");

    /// <summary>Waits until the database holds exactly <paramref name="expected"/> restore locks: a closed connection's go a moment after it closed.</summary>
    private static async Task AssertLocksAsync(OwnershipFixture f, long expected)
    {
        var waited = Stopwatch.StartNew();
        long found;
        while ((found = await LockSessionsAsync(f)) != expected && waited.Elapsed < TimeSpan.FromSeconds(20))
            await Task.Delay(50);
        Assert.Equal(expected, found);
    }

    /// <summary>Ends, from the server's side, every connection that holds a restore lock in the database, as a database restart does.</summary>
    private static async Task DropLockConnectionsAsync(OwnershipFixture f)
    {
        await f.ExecuteAsync(f.AppDatabase,
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND application_name = 'ModularCA restore lock'");
        var waited = Stopwatch.StartNew();
        while (await LockSessionsAsync(f) > 0)
        {
            Assert.True(waited.Elapsed < TimeSpan.FromSeconds(20), "the server did not close the terminated sessions");
            await Task.Delay(50);
        }
    }

    private static async Task<(HealthStatus Status, JsonElement Data)> HealthAsync(ServingDatabaseLock servingLock)
    {
        var check = (IHealthCheck)Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.RestoreLockHealthCheck"), servingLock)!;
        var result = await check.CheckHealthAsync(new HealthCheckContext());
        return (result.Status, JsonDocument.Parse(JsonSerializer.Serialize(result.Data["restoreLock"])).RootElement);
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_restore_is_refused_with_3_while_a_node_or_the_signer_service_runs_and_goes_ahead_once_they_stopped()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        var users = await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\"");

        // A node is serving: it holds its key shared, on its own connection.
        await using (var node = Node(f))
        {
            Assert.Equal(ServingLockAttemptKind.Held, (await node.TryTakeAsync()).Kind);
            Assert.Equal(ServingLockState.Held, node.State);

            var (hold, verdict) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
            Assert.Null(hold);
            AssertInUse(verdict, "a node is serving from this application database");
            Assert.Contains("or another restore is running", verdict!.Verdict);
            // The refused restore left no lock behind, and the node's is as it was.
            await AssertLocksAsync(f, 1);
            Assert.Equal(ServingLockAttemptKind.Held, (await node.TryTakeAsync()).Kind);
        }

        // The signer service alone is running (a split install with the node stopped).
        await using (var signer = Signer(f))
        {
            Assert.Equal(ServingLockAttemptKind.Held, (await signer.TryTakeAsync()).Kind);
            var (hold, verdict) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
            Assert.Null(hold);
            AssertInUse(verdict, "the signer service is running");
            await AssertLocksAsync(f, 1);
        }

        // Both stopped: the restore has the database, and nothing was changed on the way.
        var (taken, none) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        Assert.Null(none);
        Assert.NotNull(taken);
        Assert.True(await taken!.StillHeldAsync());
        await taken.DisposeAsync();
        await AssertLocksAsync(f, 0);
        Assert.Equal(users, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\""));
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_second_restore_is_refused_while_one_runs()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);

        var (first, _) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        Assert.NotNull(first);

        var (second, verdict) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        Assert.Null(second);
        AssertInUse(verdict, "another restore is running");
        Assert.True(await first!.StillHeldAsync());

        // The grace covers a holder that is on its way out, and nothing longer.
        var releasing = Task.Run(async () => { await Task.Delay(500); await first.DisposeAsync(); });
        var (afterGrace, noVerdict) = await BackupRestore.TakeExclusionAsync(new OwnConnectionRestoreExclusion(TimeSpan.FromSeconds(10)), f.App);
        await releasing;
        Assert.Null(noVerdict);
        Assert.NotNull(afterGrace);
        await afterGrace!.DisposeAsync();
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_restore_whose_lock_connection_dropped_knows_it_before_it_changes_anything()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        var (hold, _) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        Assert.True(await hold!.StillHeldAsync());

        await DropLockConnectionsAsync(f);

        Assert.False(await hold.StillHeldAsync());
        await hold.DisposeAsync();
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_start_waits_for_a_restore_says_so_once_and_goes_on_when_the_restore_ends_in_time()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        using var log = new CapturedSerilog();
        var (restore, _) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        await using var node = Node(f);

        var clock = Stopwatch.StartNew();
        var starting = SchemaStartupApi.TakeServingLockAsync(node, f.App, new SchemaConfig { RestoreWaitSeconds = 60 });
        await Task.Delay(TimeSpan.FromSeconds(2.5));
        Assert.False(starting.IsCompleted, "the start went on beside a running restore");
        Assert.Equal(ServingLockState.NotTaken, node.State);
        await restore!.DisposeAsync();

        Assert.Null(await starting);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"took {clock.Elapsed}");
        Assert.Equal(ServingLockState.Held, node.State);
        Assert.Null(node.HoldReason);
        Assert.Single(log.Events, e => e.Level == LogEventLevel.Warning && e.Text.Contains("A restore is running on the application database"));
        Assert.True(log.Has(LogEventLevel.Warning, "waiting up to 60 s for the restore to finish (Schema.RestoreWaitSeconds)"));
        Assert.True(log.Has(LogEventLevel.Information, "the start goes on"));
        // Started: a restore is now refused.
        AssertInUse((await BackupRestore.TakeExclusionAsync(CommandLine, f.App)).Verdict, "a node is serving");
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_start_gives_up_with_75_when_the_restore_does_not_end_in_time_and_has_taken_nothing()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        using var log = new CapturedSerilog();
        var (restore, _) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);

        // A node, and a signer-only process, each wait on their own key.
        foreach (var starting in new[] { Node(f), Signer(f) })
        {
            await using var process = starting;
            var clock = Stopwatch.StartNew();
            var exit = await SchemaStartupApi.TakeServingLockAsync(process, f.App, new SchemaConfig { RestoreWaitSeconds = 2 });

            Assert.Equal(SchemaStartupApi.TempFailExitCode, exit);
            Assert.Equal(75, exit);
            Assert.InRange(clock.Elapsed, TimeSpan.FromSeconds(1.9), TimeSpan.FromSeconds(20));
            Assert.Equal(ServingLockState.NotTaken, process.State);
        }

        Assert.True(log.Has(LogEventLevel.Error, "was still running after 2 s (Schema.RestoreWaitSeconds), so this process did not start. Exiting with status 75"));
        // The restore was not disturbed: it still holds both keys, and they are the only locks.
        Assert.True(await restore!.StillHeldAsync());
        await AssertLocksAsync(f, 2);
        await restore.DisposeAsync();

        // No wait at all is a setting too.
        var (again, _) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        await using var impatient = Node(f);
        Assert.Equal(75, await SchemaStartupApi.TakeServingLockAsync(impatient, f.App, new SchemaConfig { RestoreWaitSeconds = 0 }));
        await again!.DisposeAsync();
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_start_waits_for_a_server_that_does_not_answer_then_exits_75_and_leaves_a_missing_database_to_the_schema_check()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);

        // Nothing listens there.
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var closedPort = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var nowhere = new DbInstance { Host = "127.0.0.1", Port = closedPort, Database = f.AppDatabase, Username = f.App.Username, Password = "x", SslMode = "Disable" };
        await using (var unreachable = new ServingDatabaseLock(PostgresConnection.Build(nowhere), RestoreLock.NodeKey))
        {
            Assert.Equal(ServingLockAttemptKind.Unreachable, (await unreachable.TryTakeAsync()).Kind);
            Assert.Equal(75, await SchemaStartupApi.TakeServingLockAsync(unreachable, nowhere, new SchemaConfig { WaitSeconds = 1 }));
        }

        // A database that is not there yet is setup recovery's: the start goes on without the lock.
        var missing = f.Instance(f.AppDatabase + "-absent", f.App.Username, f.App.Password);
        await using var early = new ServingDatabaseLock(PostgresConnection.Build(missing), RestoreLock.NodeKey);
        Assert.Equal(ServingLockAttemptKind.Unavailable, (await early.TryTakeAsync()).Kind);
        Assert.Null(await SchemaStartupApi.TakeServingLockAsync(early, missing, new SchemaConfig { WaitSeconds = 1 }));
        Assert.Equal(ServingLockState.NotTaken, early.State);
        Assert.Equal(HealthStatus.Healthy, (await HealthAsync(early)).Status);
        Assert.Equal("not_taken", (await HealthAsync(early)).Data.GetProperty("status").GetString());
    }

    /// <summary>
    /// The commands that are neither a restore nor a starting service take no lock and respect
    /// none: each ends as it does with nobody else there, beside a serving node and its signer,
    /// and beside a running restore.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_upgrade_checks_and_the_other_one_off_commands_run_beside_a_node_and_beside_a_restore()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);

        async Task<string> RunAllAsync()
        {
            var full = new StringWriter();
            var readOnly = new StringWriter();
            var results = new List<string>
            {
                $"upgrade-check={await SchemaStartupApi.UpgradeCheckAsync(f.Targets(), new SchemaConfig(), full)}",
                $"upgrade-check --read-only={await SchemaStartupApi.UpgradeCheckAsync(f.Targets(), new SchemaConfig(), readOnly, readOnly: true)}",
                $"db-ownership check={await SchemaStartupApi.CheckOwnershipAsync(f.Targets())}",
                $"instance id={await BackupRestore.ReadInstanceIdAsync(App(f)) ?? "none"}",
                $"schema version={await BackupRestore.ComputeSchemaVersionAsync(new SystemConfig { DB = { App = f.App, Audit = f.Audit } })}",
                // The schema check of a start, as the role that applies migrations: it is the lock step before it that waits, not this.
                $"schema check={(await SchemaStartupApi.EnforceAllAsync(f.Targets(), appliesMigrations: true, new SchemaConfig { WaitSeconds = 5 }))?.ToString() ?? "passed"}",
            };
            Assert.EndsWith("UPGRADE CHECK: PASS (nothing to apply). Nothing was changed.", full.ToString().TrimEnd());
            Assert.EndsWith("UPGRADE CHECK: PASS (nothing to apply). Nothing was changed.", readOnly.ToString().TrimEnd());
            return string.Join("; ", results);
        }

        var alone = await RunAllAsync();
        Assert.Contains("upgrade-check=0", alone);
        Assert.Contains("upgrade-check --read-only=0", alone);
        Assert.Contains("schema check=passed", alone);

        await using (var node = Node(f))
        await using (var signer = Signer(f))
        {
            Assert.Null(await SchemaStartupApi.TakeServingLockAsync(node, f.App, new SchemaConfig()));
            Assert.Null(await SchemaStartupApi.TakeServingLockAsync(signer, f.App, new SchemaConfig()));
            Assert.Equal(alone, await RunAllAsync());
            await AssertLocksAsync(f, 2);
        }

        var (restore, _) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        Assert.NotNull(restore);
        Assert.Equal(alone, await RunAllAsync());
        Assert.True(await restore!.StillHeldAsync());
        await restore.DisposeAsync();
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_lock_connection_that_drops_is_taken_again_and_an_ordinary_database_restart_leaves_the_node_healthy()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        await using var node = Node(f);
        Assert.Null(await SchemaStartupApi.TakeServingLockAsync(node, f.App, new SchemaConfig()));
        Assert.Equal("held", (await HealthAsync(node)).Data.GetProperty("status").GetString());

        // The keeper is running (200 ms here, 5 s in the product): it finds the dropped connection and takes the lock again.
        await DropLockConnectionsAsync(f);
        var waited = Stopwatch.StartNew();
        while (await LockSessionsAsync(f) == 0)
        {
            Assert.True(waited.Elapsed < TimeSpan.FromSeconds(20), "the node did not take its lock again");
            await Task.Delay(50);
        }
        await node.CheckNowAsync();

        Assert.Equal(ServingLockState.Held, node.State);
        Assert.Null(node.HoldReason);
        var (status, data) = await HealthAsync(node);
        Assert.Equal(HealthStatus.Healthy, status);
        Assert.Equal("held", data.GetProperty("status").GetString());
        Assert.False(data.GetProperty("scheduledJobsHeld").GetBoolean());
        // And it protects again.
        AssertInUse((await BackupRestore.TakeExclusionAsync(CommandLine, f.App)).Verdict, "a node is serving");
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_node_that_finds_a_restore_where_its_lock_was_says_so_holds_its_jobs_and_asks_to_be_restarted()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        // No keeper: the test makes each check itself, so the restore gets in between two of them.
        await using var node = new ServingDatabaseLock(App(f), RestoreLock.NodeKey, new SerilogLoggerFactoryForTests().CreateLogger("restore-lock"));
        using var log = new CapturedSerilog();
        Assert.Equal(ServingLockAttemptKind.Held, (await node.TryTakeAsync()).Kind);

        // The connection drops, and while the node has no lock a restore takes the database.
        await DropLockConnectionsAsync(f);
        var (restore, verdict) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        Assert.Null(verdict);

        await node.CheckNowAsync();
        Assert.Equal(ServingLockState.RestoreRunning, node.State);
        Assert.Contains("A restore is running on the application database while this process is running", node.HoldReason);
        var (running, runningData) = await HealthAsync(node);
        Assert.Equal(HealthStatus.Unhealthy, running);
        Assert.Equal("restore_running", runningData.GetProperty("status").GetString());
        Assert.True(runningData.GetProperty("scheduledJobsHeld").GetBoolean());
        // Checked again while the restore runs: the same state, said once.
        await node.CheckNowAsync();
        Assert.Equal(ServingLockState.RestoreRunning, node.State);
        Assert.Single(log.Events, e => e.Level == LogEventLevel.Error && e.Text.Contains("a restore is running on the application database while this node is running"));
        // The restore was not disturbed.
        Assert.True(await restore!.StillHeldAsync());

        // The restore ends. The node has its lock again, and is not as it was: it must be restarted.
        await restore.DisposeAsync();
        await node.CheckNowAsync();
        Assert.Equal(ServingLockState.RestartNeeded, node.State);
        Assert.Contains("Restart this process", node.HoldReason);
        var (after, afterData) = await HealthAsync(node);
        Assert.Equal(HealthStatus.Unhealthy, after);
        Assert.Equal("restart_needed", afterData.GetProperty("status").GetString());
        Assert.True(log.Has(LogEventLevel.Error, "a restore replaced the application database while this node was running"));
        // It stays so, whatever the connection does next, until the process is restarted.
        await DropLockConnectionsAsync(f);
        await node.CheckNowAsync();
        Assert.Equal(ServingLockState.RestartNeeded, node.State);
        // Its lock is held meanwhile: a further restore is refused.
        AssertInUse((await BackupRestore.TakeExclusionAsync(CommandLine, f.App)).Verdict, "a node is serving");
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_serving_process_that_finds_a_restore_beside_it_ends_itself_with_75_once()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        await using var node = new ServingDatabaseLock(App(f), RestoreLock.NodeKey, new SerilogLoggerFactoryForTests().CreateLogger("restore-lock"));
        using var log = new CapturedSerilog();
        var exits = new List<int>();
        SchemaStartupApi.ExitWhenRestoreFoundBeside(node, "node", exits.Add);
        Assert.Equal(ServingLockAttemptKind.Held, (await node.TryTakeAsync()).Kind);

        // An ordinary dropped connection, with no restore: taken again, and nothing ends.
        await DropLockConnectionsAsync(f);
        await node.CheckNowAsync();
        Assert.Equal(ServingLockState.Held, node.State);
        Assert.Empty(exits);

        // The connection drops again, and this time a restore takes the database before the next check.
        await DropLockConnectionsAsync(f);
        var (restore, verdict) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        Assert.Null(verdict);
        await using var held = restore!;

        await node.CheckNowAsync();
        Assert.Equal([75], exits);
        Assert.True(log.Has(LogEventLevel.Error, "so it stops now. Exiting with status 75"));
        // The real exit ends the process there. With the test's stand-in a further check asks for nothing more.
        await node.CheckNowAsync();
        Assert.Equal([75], exits);
        // The restore was not disturbed.
        Assert.True(await held.StillHeldAsync());
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_consoles_restore_on_a_single_node_takes_the_database_on_the_nodes_own_connection_and_gives_it_back()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        await using var node = Node(f);
        Assert.Null(await SchemaStartupApi.TakeServingLockAsync(node, f.App, new SchemaConfig()));
        // On a split install the signer service runs while the console restores through it.
        await using var signer = Signer(f);
        Assert.Null(await SchemaStartupApi.TakeServingLockAsync(signer, f.App, new SchemaConfig()));

        // The node does not block itself, and the running signer does not block it either.
        var (hold, verdict) = await BackupRestore.TakeExclusionAsync(node, f.App);
        Assert.Null(verdict);
        Assert.NotNull(hold);
        Assert.True(node.RestoringHere);
        Assert.Equal("A restore started from this node's console is running.", node.HoldReason);
        var (status, data) = await HealthAsync(node);
        Assert.Equal(HealthStatus.Healthy, status);
        Assert.Equal("restoring", data.GetProperty("status").GetString());
        // One connection holds the node's key twice over; no second connection was opened for it.
        Assert.Equal(1, await f.CountAsync(f.AppDatabase,
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND application_name = 'ModularCA restore lock' "
            + $"AND pid IN (SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = {RestoreLock.LockClass} AND objid = {RestoreLock.NodeKey})"));

        // While it runs: no other node starts, and no other restore.
        await using (var other = Node(f))
        {
            Assert.Equal(ServingLockAttemptKind.Busy, (await other.TryTakeAsync()).Kind);
            Assert.Equal(75, await SchemaStartupApi.TakeServingLockAsync(other, f.App, new SchemaConfig { RestoreWaitSeconds = 1 }));
        }
        AssertInUse((await BackupRestore.TakeExclusionAsync(CommandLine, f.App)).Verdict, "another restore is running");
        // The keeper's checks go on beside it and change nothing.
        await node.CheckNowAsync();
        Assert.True(await hold!.StillHeldAsync());

        // Done: the node holds its key shared as before, serves on, and is not told to restart by the lock.
        await hold.DisposeAsync();
        Assert.False(node.RestoringHere);
        Assert.Equal(ServingLockState.Held, node.State);
        Assert.Null(node.HoldReason);
        AssertInUse((await BackupRestore.TakeExclusionAsync(CommandLine, f.App)).Verdict, "a node is serving");
        await using var later = Node(f);
        Assert.Equal(ServingLockAttemptKind.Held, (await later.TryTakeAsync()).Kind);

        // And again, a second time from the same node.
        await later.DisposeAsync();
        var (second, none) = await BackupRestore.TakeExclusionAsync(node, f.App);
        Assert.Null(none);
        await second!.DisposeAsync();
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_consoles_restore_is_refused_while_another_node_serves_from_the_same_database_or_another_restore_runs()
    {
        await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
        await using var node = Node(f);
        await using var other = Node(f);
        Assert.Equal(ServingLockAttemptKind.Held, (await node.TryTakeAsync()).Kind);
        Assert.Equal(ServingLockAttemptKind.Held, (await other.TryTakeAsync()).Kind);

        var (hold, verdict) = await BackupRestore.TakeExclusionAsync(node, f.App);
        Assert.Null(hold);
        AssertInUse(verdict, "another node is serving from this application database");
        Assert.False(node.RestoringHere);
        Assert.Equal(ServingLockState.Held, node.State);
        Assert.Equal(ServingLockState.Held, other.State);

        // The other node stopped: now it goes ahead.
        await other.DisposeAsync();
        var (alone, none) = await BackupRestore.TakeExclusionAsync(node, f.App);
        Assert.Null(none);
        await alone!.DisposeAsync();

        // A node whose lock connection is down takes it again for the restore, and loses to a restore that holds the database.
        await DropLockConnectionsAsync(f);
        var (commandLine, _) = await BackupRestore.TakeExclusionAsync(CommandLine, f.App);
        AssertInUse((await BackupRestore.TakeExclusionAsync(node, f.App)).Verdict, "another restore is running");
        await commandLine!.DisposeAsync();
        var (recovered, noRefusal) = await BackupRestore.TakeExclusionAsync(node, f.App);
        Assert.Null(noRefusal);
        Assert.Equal(ServingLockState.Held, node.State);
        // The exclusive hold is lost with its connection, and says so.
        await DropLockConnectionsAsync(f);
        Assert.False(await recovered!.StillHeldAsync());
        await recovered.DisposeAsync();
    }

    /// <summary>A logger factory over the static Serilog logger, as the product builds the lock's logger.</summary>
    private sealed class SerilogLoggerFactoryForTests
    {
        public Microsoft.Extensions.Logging.ILogger CreateLogger(string name) => new Forwarder();

        private sealed class Forwarder : Microsoft.Extensions.Logging.ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
            public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state,
                Exception? exception, Func<TState, Exception?, string> formatter)
            {
                var level = logLevel switch
                {
                    Microsoft.Extensions.Logging.LogLevel.Error or Microsoft.Extensions.Logging.LogLevel.Critical => LogEventLevel.Error,
                    Microsoft.Extensions.Logging.LogLevel.Warning => LogEventLevel.Warning,
                    Microsoft.Extensions.Logging.LogLevel.Information => LogEventLevel.Information,
                    _ => LogEventLevel.Debug,
                };
                Serilog.Log.Write(level, "{Message}", formatter(state, exception));
            }
        }
    }
}
