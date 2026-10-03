using System.Diagnostics;
using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// The tarball installer's upgrade check: <c>packaging/tests/install-upgrade-check-test.sh</c>
/// runs its decision logic under bash with stubs, and text assertions pin where it runs (after the
/// units stop, before anything in the install directory is replaced) and how (the new build as
/// the service account, against the installed config, nothing evaluated).
/// </summary>
public class InstallScriptTests
{
    [RequiresBashFact]
    public void The_upgrade_check_decisions_pass_under_bash_with_stubs()
    {
        var start = new ProcessStartInfo(DbOwnershipScriptTests.FindBash()!)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add(Path.Combine(RepoRoot(), "packaging", "tests", "install-upgrade-check-test.sh").Replace('\\', '/'));
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail("install-upgrade-check-test.sh did not finish in 120 s");
        }
        Assert.True(process.ExitCode == 0, stdout.Result + stderr.Result);
        Assert.Contains(" 0 failed", stdout.Result);
    }

    [Fact]
    public void The_check_runs_after_the_units_stop_and_before_the_payload_is_touched()
    {
        var code = CodeLines(Read("packaging/install.sh"));
        var stop = code.FindIndex(l => l.Trim() == "systemctl stop \"${RESTART[@]}\"");
        var check = code.FindIndex(l => l.Trim() == "upgrade_check");
        var wwwroot = code.FindIndex(l => l.Trim() == "rm -rf \"$APP_DIR/wwwroot\"");
        var copy = code.FindIndex(l => l.Contains("-exec cp -a {} \"$APP_DIR/\"", StringComparison.Ordinal));

        Assert.True(stop >= 0 && check >= 0 && wwwroot >= 0 && copy >= 0, "an anchor line is missing from install.sh");
        Assert.Single(code, l => l.Trim() == "upgrade_check");
        Assert.True(stop < check && check < wwwroot && check < copy);
    }

    [Fact]
    public void The_check_runs_the_new_build_as_the_service_account_against_the_installed_config_and_evaluates_nothing()
    {
        var code = CodeLines(Read("packaging/install.sh"));

        var run = Assert.Single(code, l => l.Contains("--upgrade-check", StringComparison.Ordinal) && l.Contains("runuser", StringComparison.Ordinal));
        Assert.Contains("runuser -u \"$SERVICE_USER\" -- env -i", run);
        Assert.Contains("\"$1/ModularCA.API\" --upgrade-check --config-dir \"$APP_DIR/config\"", run);
        Assert.DoesNotContain(code, l => Regex.IsMatch(l, @"\beval\b"));
        Assert.DoesNotContain(code, l => Regex.IsMatch(l, @"(^\s*|[;&|]\s*)(source|\.)\s") && !l.Contains("BASH_SOURCE", StringComparison.Ordinal));
        Assert.DoesNotContain(code, l => l.Contains("\"$APP_DIR/ModularCA.API\"", StringComparison.Ordinal) && !l.Contains("chmod", StringComparison.Ordinal));
    }

    /// <summary>The lines of a script that are not blank and not comments.</summary>
    private static List<string> CodeLines(string text) =>
        text.Split('\n').Select(l => l.TrimEnd('\r'))
            .Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#'))
            .ToList();

    /// <summary>A repository file's text.</summary>
    private static string Read(string relativePath) =>
        File.ReadAllText(Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar)));

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
