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
/// runs against a real server in the opt-in harness.
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
    public void Any_refusal_exits_3_otherwise_any_unreachable_exits_75_otherwise_0(int expected, params string[] readiness)
    {
        Assert.Equal(expected, SchemaStartupApi.UpgradeCheckExitCode(readiness));
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
    [InlineData("28P01", 3, "UPGRADE CHECK: REFUSED (application: could not be read)")]
    [InlineData("57P03", 75, "UPGRADE CHECK: UNREACHABLE (application cannot be reached)")]
    [InlineData("3D000", 0, "UPGRADE CHECK: PASS (nothing to apply)")]
    public async Task A_database_that_cannot_be_read_is_refused_or_unreachable_and_a_missing_one_has_nothing_to_upgrade(
        string sqlState, int expected, string verdict)
    {
        await using var server = new RefusingPostgres(sqlState, "refused");
        var output = new StringWriter();

        var exit = await SchemaStartupApi.UpgradeCheckAsync(
            [("application", DatabaseKind.Application, server.Instance("modularca-app", "modularca_app"))], new SchemaConfig(), output);

        Assert.Equal(expected, exit);
        Assert.Contains(verdict, output.ToString());
        Assert.Single(output.ToString().Split('\n'), l => l.StartsWith("UPGRADE CHECK: ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Without_a_db_yaml_there_is_nothing_to_check_and_the_command_says_so_with_1()
    {
        Directory.CreateDirectory(_dir);
        Assert.Equal(1, await RunCommandAsync(_dir));
    }

    [Fact]
    public async Task A_config_yaml_this_build_cannot_read_is_a_refusal()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "db.yaml"),
            "App:\n  Host: 127.0.0.1\n  Port: 1\n  Database: modularca-app\n  Username: modularca_app\n  Password: x\n");
        File.WriteAllText(Path.Combine(_dir, "config.yaml"), "Schema: [unclosed\n");

        Assert.Equal(3, await RunCommandAsync(_dir));
    }

    /// <summary>Calls <c>UpgradeCheckCommand.RunAsync</c> on <paramref name="configDir"/>.</summary>
    private static Task<int> RunCommandAsync(string configDir) =>
        (Task<int>)ApiAssembly.TypeNamed("ModularCA.API.Startup.UpgradeCheckCommand")
            .GetMethod("RunAsync", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, [configDir])!;
}
