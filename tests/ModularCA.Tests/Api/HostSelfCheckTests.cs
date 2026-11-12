using System.Reflection;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>HostSelfCheck</c>: <c>--upgrade-check</c> first proves that the build can build its web
/// host, so a payload that cannot start is refused before the version it replaces is stopped.
/// A sound build passes it; the upgrade check calls it before it looks for a configuration.
/// </summary>
public sealed class HostSelfCheckTests
{
    private static readonly Type Check = ApiAssembly.TypeNamed("ModularCA.API.Startup.HostSelfCheck");

    [Fact]
    public void A_sound_build_can_build_its_web_host()
    {
        var problem = (string?)Check.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, null);

        Assert.Null(problem);
    }

    /// <summary>The build script and an orchestrator match on this text; it must not drift.</summary>
    [Fact]
    public void The_marker_scripts_match_on_is_fixed()
    {
        Assert.Equal("THIS BUILD CANNOT START", (string)Check.GetField("Marker")!.GetRawConstantValue()!);
        var script = File.ReadAllText(Path.Combine(RepoRoot(), "scripts", "build-linux-dist.sh"));
        Assert.Contains("THIS BUILD CANNOT START", script);
    }

    /// <summary>
    /// The upgrade check runs the self-check before it reads anything: its call comes before the
    /// test for <c>db.yaml</c>, so an empty directory still exercises it.
    /// </summary>
    [Fact]
    public void The_upgrade_check_runs_it_before_it_looks_for_a_configuration()
    {
        var source = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.API", "Startup", "UpgradeCheckCommand.cs"));

        var selfCheck = source.IndexOf("HostSelfCheck.Run()", StringComparison.Ordinal);
        var dbYaml = source.IndexOf("File.Exists(dbYamlPath)", StringComparison.Ordinal);
        Assert.True(selfCheck > 0 && dbYaml > selfCheck, "HostSelfCheck.Run() must come before the db.yaml test");
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("ModularCA.sln not found above the test directory");
    }
}
