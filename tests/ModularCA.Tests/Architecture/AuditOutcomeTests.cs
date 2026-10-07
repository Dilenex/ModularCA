using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Architecture;

/// <summary>
/// An audit record named for a failure is never written as a success. Three notices about a
/// session refresh that was allowed were recorded as UserLoginFailed with success set, so the
/// console showed "OK" beside a failed sign-in and a count of failed sign-ins included them.
/// </summary>
public class AuditOutcomeTests
{
    private static readonly Regex FailureWrittenAsSuccess = new(
        @"LogAsync\(\s*(?:[\w.]+\.)?AuditActionType\.(\w*Failed)\b[^;]*?\bsuccess:\s*true",
        RegexOptions.Compiled | RegexOptions.Singleline);

    // The scheduler's records were split between "Scheduler" and "scheduler", so a search for
    // either actor found half of them.
    private static readonly Regex SchedulerActorSpelledOut = new(
        @"(?:actorUsername:\s*|LogAsync\(\s*(?:[\w.]+\.)?AuditActionType\.\w+,\s*null,\s*)""[Ss]cheduler""",
        RegexOptions.Compiled);

    [Fact]
    public void No_failure_action_is_recorded_as_a_success()
    {
        var found = Matches(FailureWrittenAsSuccess);

        Assert.True(found.Count == 0, "Recorded as a success:\n" + string.Join("\n", found));
    }

    [Fact]
    public void Scheduled_jobs_name_their_actor_through_the_one_constant()
    {
        var found = Matches(SchedulerActorSpelledOut);

        Assert.True(found.Count == 0, "Use SchedulerService.AuditActor:\n" + string.Join("\n", found));
        Assert.Equal("scheduler", ModularCA.Core.Services.SchedulerService.AuditActor);
    }

    [Fact]
    public void The_check_sees_a_scheduler_actor_spelled_out()
    {
        Assert.Matches(SchedulerActorSpelledOut, "await _audit.LogAsync(AuditActionType.CrlExported, null, \"Scheduler\",");
        Assert.Matches(SchedulerActorSpelledOut, "actorUsername: \"scheduler\",");
        Assert.DoesNotMatch(SchedulerActorSpelledOut, "await _audit.LogAsync(AuditActionType.CrlExported, null, SchedulerService.AuditActor,");
        Assert.DoesNotMatch(SchedulerActorSpelledOut, "details: new { outputPath, trigger = \"scheduler\" });");
    }

    private static List<string> Matches(Regex pattern)
    {
        var root = RepoRoot();
        var found = new List<string>();
        foreach (var project in Directory.EnumerateDirectories(root, "ModularCA.*"))
        {
            foreach (var file in Directory.EnumerateFiles(project, "*.cs", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(root, file);
                if (relative.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                    || relative.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
                    continue;

                foreach (Match match in pattern.Matches(File.ReadAllText(file)))
                    found.Add($"{relative}: {(match.Groups[1].Success ? match.Groups[1].Value : match.Value)}");
            }
        }

        return found;
    }

    [Fact]
    public void The_check_sees_a_failure_written_as_a_success()
    {
        const string wrong = "await _audit.LogAsync(AuditActionType.UserLoginFailed, id, name,\n    sourceIp: ip, success: true, errorMessage: \"x\");";
        const string right = "await _audit.LogAsync(AuditActionType.UserLoginFailed, id, name,\n    sourceIp: ip, success: false);\nawait _audit.LogAsync(AuditActionType.UserLogin, id, name, success: true);";

        Assert.Matches(FailureWrittenAsSuccess, wrong);
        Assert.DoesNotMatch(FailureWrittenAsSuccess, right);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
