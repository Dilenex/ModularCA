using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using Serilog.Events;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The exit code <c>SchemaStartup.EnforceAllAsync</c> returns for each way a connection can fail,
/// for the control role and for the others, and that each outcome reaches Serilog as well as the
/// console. The server is <see cref="RefusingPostgres"/>, so no PostgreSQL is needed; the outcomes
/// that need a real schema are in the opt-in harness.
/// </summary>
[Collection(SerilogCaptureCollection.Name)]
public sealed class SchemaStartupExitCodeTests
{
    private static readonly SchemaConfig ShortWait = new() { WaitSeconds = 1 };

    /// <summary>
    /// TCP connections one logical open makes: Npgsql's default GSS encryption mode (Prefer)
    /// reconnects without GSS after a failed attempt.
    /// </summary>
    private const int ConnectionsPerOpen = 2;

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_rejected_password_stops_every_role_with_3(bool appliesMigrations)
    {
        await using var server = new RefusingPostgres("28P01", "password authentication failed for user \"modularca_app\"");
        using var log = new CapturedSerilog();

        var exit = await SchemaStartupApi.EnforceAllAsync(
            [("application", DatabaseKind.Application, server.Instance("modularca-app", "modularca_app"))], appliesMigrations, ShortWait);

        Assert.Equal(3, exit);
        Assert.True(log.Has(LogEventLevel.Fatal, "28P01"), Dump(log));
        Assert.True(log.Has(LogEventLevel.Fatal, "Check the password"), Dump(log));
        Assert.True(log.Has(LogEventLevel.Fatal, "Nothing was applied to either database"), Dump(log));
    }

    [Theory]
    [InlineData("28000", "pg_hba.conf")]
    [InlineData("42501", "lacks a privilege")]
    public async Task A_refused_login_or_privilege_stops_the_control_role_with_3_and_the_likely_fix(string sqlState, string hint)
    {
        await using var server = new RefusingPostgres(sqlState, "refused");
        using var log = new CapturedSerilog();

        var exit = await SchemaStartupApi.EnforceAllAsync(
            [("audit", DatabaseKind.Audit, server.Instance("modularca-audit", "modularca_audit"))], true, ShortWait);

        Assert.Equal(3, exit);
        Assert.True(log.Has(LogEventLevel.Fatal, hint), Dump(log));
    }

    [Fact]
    public async Task A_missing_database_lets_the_control_role_start_for_setup_recovery()
    {
        await using var server = new RefusingPostgres("3D000", "database \"modularca-app\" does not exist");
        using var log = new CapturedSerilog();

        var exit = await SchemaStartupApi.EnforceAllAsync(
            [("application", DatabaseKind.Application, server.Instance("modularca-app", "modularca_app"))], true, ShortWait);

        Assert.Null(exit);
        Assert.True(log.Has(LogEventLevel.Information, "does not exist yet"), Dump(log));
        Assert.InRange(server.Connections, 1, ConnectionsPerOpen);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_server_not_accepting_connections_is_waited_for_then_exits_75(bool appliesMigrations)
    {
        await using var server = new RefusingPostgres("57P03", "the database system is starting up");
        using var log = new CapturedSerilog();
        var clock = Stopwatch.StartNew();

        var exit = await SchemaStartupApi.EnforceAllAsync(
            [("application", DatabaseKind.Application, server.Instance("modularca-app", "modularca_app"))], appliesMigrations, ShortWait);

        Assert.Equal(75, exit);
        Assert.True(clock.Elapsed >= TimeSpan.FromSeconds(0.9), $"gave up after {clock.Elapsed}");
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"gave up after {clock.Elapsed}");
        Assert.True(server.Connections >= 2, $"{server.Connections} attempt(s)");
        Assert.True(log.Has(LogEventLevel.Information, "cannot be reached"), Dump(log));
        Assert.True(log.Has(LogEventLevel.Error, "Gave up after 1 s (Schema.WaitSeconds)"), Dump(log));
    }

    [Fact]
    public async Task Both_databases_are_read_before_either_decides_and_a_bad_audit_database_stops_the_start()
    {
        await using var app = new RefusingPostgres("3D000", "database does not exist");
        await using var audit = new RefusingPostgres("28P01", "password authentication failed");
        using var log = new CapturedSerilog();

        var exit = await SchemaStartupApi.EnforceAllAsync(
        [
            ("application", DatabaseKind.Application, app.Instance("modularca-app", "modularca_app")),
            ("audit", DatabaseKind.Audit, audit.Instance("modularca-audit", "modularca_audit")),
        ], true, ShortWait);

        Assert.Equal(3, exit);
        Assert.InRange(app.Connections, 1, ConnectionsPerOpen);
        Assert.InRange(audit.Connections, 1, ConnectionsPerOpen);
        Assert.True(log.Has(LogEventLevel.Fatal, "The audit database 'modularca-audit'"), Dump(log));
    }

    [Fact]
    public async Task The_heartbeat_keeps_extending_the_start_timeout_while_one_read_hangs_on_a_silent_server()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var held = new List<TcpClient>();
        var accept = Task.Run(async () =>
        {
            try
            {
                while (true)
                    held.Add(await listener.AcceptTcpClientAsync());
            }
            catch (Exception)
            {
            }
        });
        var instance = new DbInstance
        {
            Host = "127.0.0.1", Port = ((IPEndPoint)listener.LocalEndpoint).Port, Database = "modularca-app",
            Username = "modularca_app", Password = "not-used", SslMode = "Disable",
        };
        var notifier = RecordingNotifier.Create();
        using var log = new CapturedSerilog();
        SchemaStartupApi.UseHeartbeatInterval(TimeSpan.FromMilliseconds(250));
        try
        {
            var clock = Stopwatch.StartNew();
            var exit = await SchemaStartupApi.EnforceAllAsync(
                [("application", DatabaseKind.Application, instance)], true, new SchemaConfig { WaitSeconds = 0 }, notifier);

            Assert.Equal(75, exit);
            var sent = ((RecordingNotifier)notifier).Sent;
            var extended = sent.Count(s => s.Contains("EXTEND_TIMEOUT_USEC=90000000", StringComparison.Ordinal));
            Assert.True(clock.Elapsed >= TimeSpan.FromSeconds(5), $"the read gave up after {clock.Elapsed}");
            Assert.True(extended >= 10, $"{extended} extension(s) in {clock.Elapsed}: {string.Join(" | ", sent)}");
            Assert.True(log.Has(LogEventLevel.Error, "cannot be reached"), Dump(log));
        }
        finally
        {
            SchemaStartupApi.UseHeartbeatInterval(null);
            listener.Stop();
            await accept;
            foreach (var client in held)
                client.Dispose();
        }
    }

    [Fact]
    public async Task A_migration_whose_connection_cannot_be_opened_reports_a_connect_failure_not_a_statement_timeout()
    {
        await using var server = new RefusingPostgres("57P03", "the database system is starting up");
        await using var db = new ModularCADbContext(new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<ModularCADbContext>()
            .UseNpgsql(SchemaStartupApi.MigrationConnectionString(server.Instance("modularca-app", "modularca_app"), new SchemaConfig())).Options);
        var state = new SchemaState([], db.Database.GetMigrations().ToList()) { Presence = DatabasePresence.Managed };

        var error = await Assert.ThrowsAsync<SchemaConnectException>(() => SchemaVersionGate.ApplyPendingAsync(db, state));

        Assert.Equal(SchemaFailureKind.Unreachable, SchemaFailure.Classify(error));
        Assert.True(SchemaFailure.TransientForMigration(error));
        Assert.False(SchemaFailure.IsStatementTimeout(error));
    }

    [Fact]
    public async Task The_ownership_check_verb_reports_an_unreadable_database_as_not_sound()
    {
        await using var server = new RefusingPostgres("28P01", "password authentication failed");

        var exit = await SchemaStartupApi.CheckOwnershipAsync(
            [("application", DatabaseKind.Application, server.Instance("modularca-app", "modularca_app"))]);

        Assert.Equal(3, exit);
    }

    /// <summary>Every captured event, for an assertion message.</summary>
    private static string Dump(CapturedSerilog log) =>
        string.Join(Environment.NewLine, log.Events.Select(e => $"{e.Level}: {e.Text}"));
}

/// <summary>Tests that replace the global Serilog logger run one at a time.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SerilogCaptureCollection
{
    /// <summary>The collection name.</summary>
    public const string Name = "Serilog capture";
}
