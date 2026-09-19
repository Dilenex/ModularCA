using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// That no raw SQL still speaks MySQL.
/// <para>
/// The provider swap converted the queries Entity Framework does not write for us, but one was
/// missed: the scheduler checked whether a table existed with
/// <c>TABLE_SCHEMA = DATABASE()</c> — a function PostgreSQL does not have, filtering on a column
/// that means a schema there rather than a database. It threw on every poll, once every thirty
/// seconds, which stopped the scheduler main loop before any job ran. Nothing caught it because
/// raw SQL is only exercised against a real server, and the unit suite has none.
/// </para>
/// <para>
/// A source scan is a poor substitute for running the statement, and it is still worth having:
/// these tokens cannot appear in valid PostgreSQL, so finding one is always a defect, and the
/// cost of the check is reading some text.
/// </para>
/// </summary>
public class NoMySqlSyntaxTests
{
    /// <summary>
    /// Constructs no valid PostgreSQL statement contains, matched case sensitively and outside
    /// comments. Deliberately narrow: a token that could legitimately appear in a PowerShell
    /// string or in prose is not worth the false positives.
    /// </summary>
    private static readonly string[] MySqlOnly =
    [
        "DATABASE()",
        "UTC_TIMESTAMP",
        "AUTO_INCREMENT",
        "ON DUPLICATE KEY",
        "LAST_INSERT_ID",
        "SQL_CALC_FOUND_ROWS",
        "ENGINE=InnoDB",
    ];

    /// <summary>
    /// The projects whose SQL must be PostgreSQL. <c>ModularCA.Migrate</c> is excluded on purpose:
    /// it is the one thing that still has to read a MariaDB database, which is the whole reason
    /// the rest of the product can refuse to.
    /// </summary>
    private static readonly string[] Projects =
    [
        "ModularCA.Core", "ModularCA.API", "ModularCA.Auth",
        "ModularCA.Database", "ModularCA.Keystore", "ModularCA.Shared", "ModularCA.Bootstrap",
    ];

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ModularCA.sln")))
            directory = directory.Parent;

        Assert.True(directory is not null,
            "could not locate the repository root from " + AppContext.BaseDirectory);
        return directory!.FullName;
    }

    [Fact]
    public void No_product_source_contains_mysql_only_sql()
    {
        var root = RepositoryRoot();
        var offenders = new List<string>();

        foreach (var project in Projects)
        {
            var directory = Path.Combine(root, project);
            if (!Directory.Exists(directory))
                continue;

            foreach (var file in Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                    || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                    // The migrations describe a schema; the MySQL ones are history, not queries.
                    || file.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}"))
                {
                    continue;
                }

                var lineNumber = 0;
                foreach (var line in File.ReadLines(file))
                {
                    lineNumber++;

                    // Comment lines are skipped, and the match is case sensitive. Both matter:
                    // the first pass of this test reported three offenders and all three were
                    // false — a C# method called _loadDatabase(), and two comments describing
                    // exactly the MySQL syntax being removed, including the one explaining this
                    // very bug. A guard that cries wolf gets deleted.
                    var trimmed = line.TrimStart();
                    if (trimmed.StartsWith("//", StringComparison.Ordinal)
                        || trimmed.StartsWith("*", StringComparison.Ordinal)
                        || trimmed.StartsWith("/*", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    foreach (var token in MySqlOnly)
                    {
                        if (line.Contains(token, StringComparison.Ordinal))
                            offenders.Add($"{Path.GetRelativePath(root, file)}:{lineNumber} has '{token}'");
                    }
                }
            }
        }

        Assert.True(offenders.Count == 0,
            "These carry SQL that only MySQL understands, and will throw against PostgreSQL:\n  "
            + string.Join("\n  ", offenders));
    }

    [Fact]
    public void The_scan_can_actually_see_the_source()
    {
        // A scan that silently finds nothing because it is looking in the wrong place passes
        // forever and guards nothing. This proves it is reading real files.
        var scheduler = Path.Combine(RepositoryRoot(), "ModularCA.Core", "Services", "SchedulerService.cs");

        Assert.True(File.Exists(scheduler), $"expected to find {scheduler}");
        Assert.Contains("to_regclass", File.ReadAllText(scheduler));
    }
}
