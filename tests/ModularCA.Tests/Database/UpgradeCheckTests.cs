using System.Reflection;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The <c>--upgrade-check</c> verb without a real schema: how findings map to the exit status and
/// the one-line verdict, what a database that refuses the login, is not up yet or does not exist
/// yields, and what the command does with a missing or unusable configuration. The dry run itself
/// runs against a real server in the opt-in harness, and so does what the read-only check
/// (<c>--upgrade-check --read-only</c>) reads and leaves alone
/// (<see cref="PostgresUpgradeCheckReadOnlyTests"/>).
/// </summary>
public sealed class UpgradeCheckTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-upgrade-check-{Guid.NewGuid():N}");

    /// <summary>Removes the temporary config directory.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(0, "Clean")]
    [InlineData(0, "Clean", "Clean")]
    [InlineData(75, "Clean", "Unreachable")]
    [InlineData(3, "Unreachable", "Refused")]
    [InlineData(3, "Refused", "Clean")]
    [InlineData(5, "PendingNotRehearsed")]
    [InlineData(5, "Clean", "PendingNotRehearsed", "Clean")]
    [InlineData(75, "PendingNotRehearsed", "Unreachable")]
    [InlineData(3, "PendingNotRehearsed", "Unreachable", "Refused")]
    public void Any_refusal_exits_3_otherwise_any_unreachable_exits_75_otherwise_pending_unrehearsed_exits_5_otherwise_0(
        int expected, params string[] readiness)
    {
        Assert.Equal(expected, SchemaStartupApi.UpgradeCheckExitCode(readiness));
    }

    /// <summary>An orchestrator tells the read-only check's verdicts apart by these: they must not drift.</summary>
    [Fact]
    public void The_status_and_the_marker_of_pending_and_not_rehearsed_are_fixed()
    {
        Assert.Equal(5, SchemaStartupApi.PendingNotRehearsedExitCode);
        Assert.Equal("UPGRADE PENDING, NOT REHEARSED", SchemaStartupApi.PendingNotRehearsedMarker);
        Assert.DoesNotContain(SchemaStartupApi.PendingNotRehearsedExitCode,
            new[] { 0, 1, SchemaStartupApi.ExitCode, SchemaStartupApi.AppliedThenFailedExitCode, SchemaStartupApi.TempFailExitCode });
    }

    [Fact]
    public void The_pending_and_not_rehearsed_verdict_lists_each_database_and_cannot_be_taken_for_a_pass()
    {
        var verdict = SchemaStartupApi.UpgradeCheckVerdict(
            ("PendingNotRehearsed", "application: 002_B, 003_C", 0), ("Clean", "configuration", 0), ("PendingNotRehearsed", "audit: 002_X", 0));

        Assert.Equal("UPGRADE PENDING, NOT REHEARSED (application: 002_B, 003_C; audit: 002_X). Nothing was rehearsed and nothing was changed: "
            + "stop the node and run --upgrade-check without --read-only before upgrading.", verdict);
        Assert.DoesNotContain("UPGRADE CHECK", verdict);
        Assert.DoesNotContain("PASS", verdict);
        Assert.DoesNotContain('\n', verdict);

        // A refusal or an unreachable database decides the line, as without --read-only.
        Assert.Equal("UPGRADE CHECK: REFUSED (audit: ownership not sound). Nothing was changed.",
            SchemaStartupApi.UpgradeCheckVerdict(("PendingNotRehearsed", "application: 002_B", 0), ("Refused", "audit: ownership not sound", 0)));
        Assert.Equal("UPGRADE CHECK: UNREACHABLE (audit cannot be reached); try again. Nothing was changed.",
            SchemaStartupApi.UpgradeCheckVerdict(("PendingNotRehearsed", "application: 002_B", 0), ("Unreachable", "audit cannot be reached", 0)));
    }

    /// <summary>The server refuses a write on the read-only check's connection, and a read there gives up on a lock in half a second.</summary>
    [Fact]
    public void The_read_only_check_connects_read_only_with_a_short_lock_timeout()
    {
        var instance = new DbInstance { Host = "127.0.0.1", Port = 5432, Database = "d", Username = "u", Password = "p", SslMode = "Disable" };

        var readOnly = new Npgsql.NpgsqlConnectionStringBuilder(SchemaStartupApi.ReadOnlyCheckConnectionString(instance));
        var gate = new Npgsql.NpgsqlConnectionStringBuilder(SchemaStartupApi.GateReadConnectionString(instance));

        Assert.Equal("-c lock_timeout=500 -c default_transaction_read_only=on", readOnly.Options);
        Assert.False(readOnly.Pooling);
        Assert.Equal(gate.Timeout, readOnly.Timeout);
        Assert.Equal(gate.CommandTimeout, readOnly.CommandTimeout);
        Assert.Equal("-c lock_timeout=3000", gate.Options);
    }

    [Fact]
    public void The_verdict_is_one_line_naming_what_decided_it()
    {
        Assert.Equal("UPGRADE CHECK: PASS (5 pending migration(s) would apply cleanly). Nothing was changed.",
            SchemaStartupApi.UpgradeCheckVerdict(("Clean", "application", 5), ("Clean", "audit", 0)));
        Assert.Equal("UPGRADE CHECK: PASS (nothing to apply). Nothing was changed.",
            SchemaStartupApi.UpgradeCheckVerdict(("Clean", "application", 0)));
        Assert.Equal("UPGRADE CHECK: REFUSED (application: migration X refuses). Nothing was changed.",
            SchemaStartupApi.UpgradeCheckVerdict(("Refused", "application: migration X refuses", 0), ("Unreachable", "audit cannot be reached", 0)));
        Assert.Equal("UPGRADE CHECK: UNREACHABLE (audit cannot be reached); try again. Nothing was changed.",
            SchemaStartupApi.UpgradeCheckVerdict(("Clean", "application", 4), ("Unreachable", "audit cannot be reached", 0)));
    }

    [Theory]
    [InlineData("28P01", 3, "UPGRADE CHECK: REFUSED (application: could not be read)", false)]
    [InlineData("57P03", 75, "UPGRADE CHECK: UNREACHABLE (application cannot be reached)", false)]
    [InlineData("3D000", 0, "UPGRADE CHECK: PASS (nothing to apply)", false)]
    [InlineData("28P01", 3, "UPGRADE CHECK: REFUSED (application: could not be read)", true)]
    [InlineData("57P03", 75, "UPGRADE CHECK: UNREACHABLE (application cannot be reached)", true)]
    [InlineData("3D000", 0, "UPGRADE CHECK: PASS (nothing to apply)", true)]
    public async Task A_database_that_cannot_be_read_is_refused_or_unreachable_and_a_missing_one_has_nothing_to_upgrade(
        string sqlState, int expected, string verdict, bool readOnly)
    {
        await using var server = new RefusingPostgres(sqlState, "refused");
        var output = new StringWriter();

        var exit = await SchemaStartupApi.UpgradeCheckAsync(
            [("application", DatabaseKind.Application, server.Instance("modularca-app", "modularca_app"))], new SchemaConfig(), output,
            readOnly: readOnly);

        Assert.Equal(expected, exit);
        Assert.Contains(verdict, output.ToString());
        Assert.Single(output.ToString().Split('\n'), l => l.StartsWith("UPGRADE CHECK: ", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Without_a_db_yaml_there_is_nothing_to_check_and_the_command_says_so_with_1(bool readOnly)
    {
        Directory.CreateDirectory(_dir);
        Assert.Equal(1, await RunCommandAsync(_dir, readOnly));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_config_yaml_this_build_cannot_read_is_a_refusal(bool readOnly)
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "db.yaml"),
            "App:\n  Host: 127.0.0.1\n  Port: 1\n  Database: modularca-app\n  Username: modularca_app\n  Password: x\n");
        File.WriteAllText(Path.Combine(_dir, "config.yaml"), "Schema: [unclosed\n");

        Assert.Equal(3, await RunCommandAsync(_dir, readOnly));
    }

    /// <summary>
    /// The command line documents the flag where an operator looks for it, and passes it on only
    /// when it is given: without <c>--read-only</c> the command is the full check.
    /// </summary>
    [Fact]
    public void The_entry_point_passes_read_only_on_and_names_it_in_the_usage()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        var source = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.API", "StartModularCA.cs"));

        Assert.Contains("Usage: --upgrade-check [--read-only] [--config-dir <installed config directory>]", source);
        Assert.Contains("readOnly: args.Contains(\"--read-only\", StringComparer.OrdinalIgnoreCase)", source);
    }

    /// <summary>Calls <c>UpgradeCheckCommand.RunAsync</c> on <paramref name="configDir"/>, with <c>--read-only</c> when <paramref name="readOnly"/>.</summary>
    private static Task<int> RunCommandAsync(string configDir, bool readOnly) =>
        (Task<int>)ApiAssembly.TypeNamed("ModularCA.API.Startup.UpgradeCheckCommand")
            .GetMethod("RunAsync", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, [configDir, readOnly])!;
}
