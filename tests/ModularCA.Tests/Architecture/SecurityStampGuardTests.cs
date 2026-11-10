using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Architecture;

/// <summary>
/// Nothing assigns <c>UserEntity.SecurityStamp</c> without also ending the account's sessions, or
/// saying here why not. A rotated stamp only stops access tokens; <c>/auth/refresh</c> does not read
/// it, so a site that rotates the stamp and leaves the refresh tokens live signs nobody out: the
/// next refresh mints a token carrying the new stamp. <c>UserSessionTermination</c> does both, and
/// this test reads the product sources to hold every assignment to it. A new account gets its stamp
/// from the entity's property initializer, so creating a user assigns nothing.
/// </summary>
public class SecurityStampGuardTests
{
    private const string Helper = "UserSessionTermination.EndAllSessions";
    private const string TheHelperItself = "the helper itself: it revokes the refresh tokens beside this assignment";
    private const string GroupChange = "by design (owner, 2026-11-09): a group change only makes access tokens stale; refresh re-reads the groups and the session carries on";

    /// <summary>
    /// Assignments that deliberately do not go through the helper, as <c>file::member</c> → how many
    /// and why. The count is exact: one more assignment in a listed member fails the test.
    /// </summary>
    private static readonly Dictionary<string, (int Count, string Reason)> Allowed = new(StringComparer.Ordinal)
    {
        ["ModularCA.Core/Helpers/UserSessionTermination.cs::EndAllSessionsAsync"] = (2, TheHelperItself + " (two overloads)"),
        ["ModularCA.Core/Helpers/UserSessionTermination.cs::EndAllSessionsSetBasedAsync"] = (1, TheHelperItself),
        ["ModularCA.Shared/Entities/UserEntity.cs::(property initializer)"] = (1, "the stamp a new account starts with; it has no sessions to end"),
        ["ModularCA.Auth/Services/UserManagementService.cs::UpdateUser"] = (1, "by design (owner, 2026-11-09): a username or email change only makes access tokens stale; the client refreshes to pick up the new claims and the session carries on"),
        ["ModularCA.Auth/Services/UserManagementService.cs::AddUserToGroup"] = (1, GroupChange),
        ["ModularCA.Auth/Services/UserManagementService.cs::RemoveUserFromGroup"] = (1, GroupChange),
    };

    /// <summary>Every way the sources could write the stamp: an assignment or object initializer, a set-based update, a change-tracker write, the property's own initializer.</summary>
    private static readonly Regex[] Assignments =
    [
        new(@"\bSecurityStamp\s*=(?![=>])"),
        new(@"SetProperty\(\s*\w+\s*=>\s*\w+\.SecurityStamp\b"),
        new(@"\.SecurityStamp\s*\)\s*\.(?:CurrentValue|OriginalValue)\s*="),
        new(@"\bSecurityStamp\s*\{[^}]*\}\s*="),
    ];

    private static readonly Regex PropertyInitializer = new(@"\bSecurityStamp\s*\{[^}]*\}\s*=");

    /// <summary>A method or local-function signature at the start of a line; the member runs to the next one.</summary>
    private static readonly Regex Signature = new(
        @"^[ \t]*(?:(?:public|private|protected|internal|static|async|override|virtual|sealed|new|partial)\s+)+[\w<>\[\],.?() \t]+?[ \t]+(?<name>\w+)\s*(?:<[^>\r\n]*>)?\(",
        RegexOptions.Multiline);

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    /// <summary>The product sources: every <c>ModularCA.*</c> project at the repository root, without build output and migrations.</summary>
    private static IEnumerable<(string Path, string Text)> ProductSources()
    {
        var root = RepoRoot();
        var sep = Path.DirectorySeparatorChar;
        foreach (var project in Directory.EnumerateDirectories(root, "ModularCA.*"))
        {
            foreach (var file in Directory.EnumerateFiles(project, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains($"{sep}obj{sep}") || file.Contains($"{sep}bin{sep}") || file.Contains($"{sep}Migrations{sep}"))
                    continue;
                yield return (Path.GetRelativePath(root, file).Replace('\\', '/'), File.ReadAllText(file));
            }
        }
    }

    /// <summary>One write of the stamp: where it is, the member it sits in, and whether that member calls the helper.</summary>
    private sealed record Write(string File, int Line, string Member, bool MemberCallsHelper)
    {
        public string Key => $"{File}::{Member}";
    }

    /// <summary>Every write of the stamp in <paramref name="sources"/>, comment lines left out.</summary>
    private static List<Write> Writes(IEnumerable<(string Path, string Text)> sources)
    {
        var writes = new List<Write>();
        foreach (var (path, raw) in sources)
        {
            if (!raw.Contains("SecurityStamp", StringComparison.Ordinal))
                continue;

            // Blank comment lines out, keeping line numbers.
            var text = Regex.Replace(raw, @"^[ \t]*//.*$", string.Empty, RegexOptions.Multiline);
            var signatures = Signature.Matches(text);
            var seen = new HashSet<int>();
            foreach (var pattern in Assignments)
            {
                foreach (Match m in pattern.Matches(text))
                {
                    var line = text[..m.Index].Count(c => c == '\n') + 1;
                    if (!seen.Add(line))
                        continue;

                    if (PropertyInitializer.IsMatch(m.Value))
                    {
                        writes.Add(new Write(path, line, "(property initializer)", false));
                        continue;
                    }

                    var own = signatures.LastOrDefault(s => s.Index < m.Index);
                    var next = signatures.FirstOrDefault(s => s.Index > m.Index);
                    var body = own == null ? text : text[own.Index..(next?.Index ?? text.Length)];
                    writes.Add(new Write(path, line, own?.Groups["name"].Value ?? "(no member)",
                        own != null && body.Contains(Helper, StringComparison.Ordinal)));
                }
            }
        }
        return writes;
    }

    /// <summary>What is wrong with <paramref name="writes"/> under <paramref name="allowed"/>: one line per problem.</summary>
    private static List<string> Problems(List<Write> writes, Dictionary<string, (int Count, string Reason)> allowed)
    {
        var problems = new List<string>();
        foreach (var group in writes.GroupBy(w => w.Key).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var where = string.Join(", ", group.Select(w => $"line {w.Line}"));
            if (allowed.TryGetValue(group.Key, out var entry))
            {
                if (group.Count() != entry.Count)
                    problems.Add($"{group.Key} ({where}): {group.Count()} assignment(s), but the allow-list covers {entry.Count} ({entry.Reason}). "
                                 + "End the sessions through UserSessionTermination instead of assigning the stamp, or, if the new assignment is deliberate, correct the count and the reason in Allowed.");
                continue;
            }
            if (group.All(w => w.MemberCallsHelper))
                continue;

            problems.Add($"{group.Key} ({where}): assigns SecurityStamp without ending the account's sessions. /auth/refresh does not read the stamp, "
                         + "so the account's refresh tokens would go on minting sessions. Replace the assignment with UserSessionTermination.EndAllSessionsAsync "
                         + "(or EndAllSessionsSetBasedAsync where a set-based UPDATE is wanted), which rotates the stamp and revokes the refresh tokens together. "
                         + "If the rotation is deliberately not meant to end sessions, name the member in Allowed in SecurityStampGuardTests with the reason, "
                         + "and add a test that a refresh token issued before the change still works.");
        }

        foreach (var stale in allowed.Keys.Where(k => writes.All(w => w.Key != k)).OrderBy(k => k, StringComparer.Ordinal))
            problems.Add($"{stale}: on the allow-list, but no assignment is there any more. Remove it from Allowed.");
        return problems;
    }

    [Fact]
    public void Every_stamp_assignment_ends_the_sessions_or_says_why_not()
    {
        var problems = Problems(Writes(ProductSources()), Allowed);

        Assert.True(problems.Count == 0, "SecurityStamp assignments that do not end sessions:\n" + string.Join("\n", problems));
    }

    /// <summary>The scan sees the sources at all: the helper and the three by-design sites are found where the list says.</summary>
    [Fact]
    public void The_scan_finds_the_known_assignments()
    {
        var keys = Writes(ProductSources()).Select(w => w.Key).ToHashSet(StringComparer.Ordinal);

        Assert.All(Allowed.Keys, k => Assert.Contains(k, keys));
    }

    /// <summary>
    /// The guard on made-up sources: an assignment in a member that does not call the helper is
    /// reported, in each form the stamp can be written, and one beside a helper call is not.
    /// </summary>
    [Theory]
    [InlineData("user.SecurityStamp = Guid.NewGuid().ToString();", true)]
    [InlineData("var u = new UserEntity { Id = id, SecurityStamp = \"x\" };", true)]
    [InlineData("await db.Users.ExecuteUpdateAsync(s => s.SetProperty(u => u.SecurityStamp, stamp));", true)]
    [InlineData("db.Entry(user).Property(u => u.SecurityStamp).CurrentValue = stamp;", true)]
    [InlineData("user.SecurityStamp = stamp; await UserSessionTermination.EndAllSessionsAsync(db, user, now);", false)]
    [InlineData("// user.SecurityStamp = stamp;", false)]
    [InlineData("if (user.SecurityStamp == stamp) return;", false)]
    [InlineData("var stamps = users.Select(u => u.SecurityStamp);", false)]
    public void A_new_assignment_without_the_helper_is_reported(string statement, bool reported)
    {
        var source = $$"""
            public class Sample
            {
                public async Task Helper(Db db) { await Task.Yield(); }

                public async Task Change(Db db, UserEntity user)
                {
                    {{statement}}
                }

                private static void After() { }
            }
            """;

        var problems = Problems(Writes([("ModularCA.Sample/Sample.cs", source)]), []);

        if (reported)
            Assert.Contains("ModularCA.Sample/Sample.cs::Change", Assert.Single(problems));
        else
            Assert.Empty(problems);
    }

    /// <summary>A second assignment in an allow-listed member is not covered by the first one's reason.</summary>
    [Fact]
    public void An_extra_assignment_in_an_allow_listed_member_is_reported()
    {
        const string source = """
            public class Sample
            {
                public void Change(UserEntity user)
                {
                    user.SecurityStamp = "a";
                    user.SecurityStamp = "b";
                }
            }
            """;
        var allowed = new Dictionary<string, (int Count, string Reason)> { ["ModularCA.Sample/Sample.cs::Change"] = (1, "one is deliberate") };

        Assert.Contains("allow-list covers 1", Assert.Single(Problems(Writes([("ModularCA.Sample/Sample.cs", source)]), allowed)));
    }
}
