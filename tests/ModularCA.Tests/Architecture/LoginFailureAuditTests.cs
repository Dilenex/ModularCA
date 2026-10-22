using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Architecture;

/// <summary>
/// Every <c>UserLoginFailed</c> audit entry is written as a failure. <c>IAuditService.LogAsync</c>
/// defaults <c>success</c> to true, so a call that leaves it out records a refused sign-in as OK,
/// which the Audit Logs page then shows with an OK badge and its Failed filter leaves out.
/// </summary>
public class LoginFailureAuditTests
{
    private static readonly string[] SourceProjects = ["ModularCA.API", "ModularCA.Auth", "ModularCA.Core"];

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    /// <summary>Each <c>LogAsync(...UserLoginFailed...)</c> call in the sources, with where it is.</summary>
    private static List<(string Where, string Call)> LoginFailedCalls()
    {
        var root = RepoRoot();
        var calls = new List<(string, string)>();
        var call = new Regex(@"LogAsync\(\s*(?:Shared\.Enums\.)?AuditActionType\.UserLoginFailed\b(?<args>.*?)\);", RegexOptions.Singleline);

        foreach (var project in SourceProjects)
        {
            foreach (var file in Directory.EnumerateFiles(Path.Combine(root, project), "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")) continue;
                var text = File.ReadAllText(file);
                foreach (Match m in call.Matches(text))
                {
                    var line = text[..m.Index].Count(c => c == '\n') + 1;
                    calls.Add(($"{Path.GetRelativePath(root, file)}:{line}", m.Groups["args"].Value));
                }
            }
        }

        return calls;
    }

    [Fact]
    public void The_calls_are_found()
    {
        Assert.True(LoginFailedCalls().Count >= 10, "Expected the sign-in paths' UserLoginFailed calls; the scan found too few.");
    }

    [Fact]
    public void Every_UserLoginFailed_entry_is_written_as_a_failure()
    {
        var unmarked = LoginFailedCalls()
            .Where(c => !Regex.IsMatch(c.Call, @"\bsuccess:\s*false\b"))
            .Select(c => c.Where)
            .ToList();

        Assert.True(unmarked.Count == 0,
            "These UserLoginFailed entries leave success at its default of true: " + string.Join(", ", unmarked));
    }
}
