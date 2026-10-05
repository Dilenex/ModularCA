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

    /// <summary>
    /// The payload is replaced only inside <c>install_payload</c> (wwwroot removed, program files
    /// copied into <c>$APP_DIR</c>), which the top level calls once, after the units stop and the
    /// upgrade check returns.
    /// </summary>
    [Fact]
    public void The_check_runs_after_the_units_stop_and_before_the_payload_is_touched()
    {
        var code = CodeLines(Read("packaging/install.sh"));
        var stop = code.FindIndex(l => l == "    systemctl stop \"${RESTART[@]}\"");
        var check = code.FindIndex(l => l == "upgrade_check");
        var payload = code.FindIndex(l => l == "install_payload");
        var bodyStart = code.FindIndex(l => l == "install_payload() {");
        var bodyEnd = bodyStart < 0 ? -1 : code.FindIndex(bodyStart, l => l == "}");
        var wwwroot = code.FindIndex(l => l.Trim() == "rm -rf \"$APP_DIR/wwwroot\"");
        var copy = code.FindIndex(l => Regex.IsMatch(l, @"\bcp -a\b.*""\$APP_DIR/""", RegexOptions.None));

        Assert.True(stop >= 0 && check >= 0 && payload >= 0 && bodyStart >= 0 && bodyEnd > bodyStart && wwwroot >= 0 && copy >= 0,
            "an anchor line is missing from install.sh");

        // One check and one payload call, both at the top level, in that order after the stop.
        Assert.Single(code, l => l.Trim() == "upgrade_check");
        Assert.Single(code, l => Regex.IsMatch(l, @"\binstall_payload\b") && !l.EndsWith("() {", StringComparison.Ordinal));
        Assert.True(stop < check && check < payload, "the check must run after the units stop and before install_payload is called");

        // Nothing replaces the payload outside install_payload.
        Assert.Single(code, l => l.Trim() == "rm -rf \"$APP_DIR/wwwroot\"");
        Assert.Single(code, l => Regex.IsMatch(l, @"\bcp -a\b.*""\$APP_DIR/"""));
        Assert.True(bodyStart < wwwroot && wwwroot < bodyEnd && bodyStart < copy && copy < bodyEnd,
            "the payload must be replaced only inside install_payload");
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
