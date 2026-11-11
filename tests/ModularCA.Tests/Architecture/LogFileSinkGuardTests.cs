using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Architecture;

/// <summary>
/// No log file sink is opened in shared mode. Off Windows, Serilog's shared mode creates a named
/// system mutex before it opens the file. On a Linux install that failed for each of the three
/// file names the rolling sink tries, the sink then dropped every event, and the node ran for
/// weeks with its journal intact and no log file. Every file the product writes has one writer
/// (the node its own, the signer role one under its own directory), so shared mode buys nothing.
/// </summary>
public class LogFileSinkGuardTests
{
    private static readonly Regex Shared = new(@"shareds*:s*true");

    [Fact]
    public void No_product_source_opens_a_log_file_in_shared_mode()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        var sep = Path.DirectorySeparatorChar;

        var offenders = Directory.EnumerateDirectories(dir!.FullName, "ModularCA.*")
            .SelectMany(project => Directory.EnumerateFiles(project, "*.cs", SearchOption.AllDirectories))
            .Where(file => !file.Contains($"{sep}obj{sep}") && !file.Contains($"{sep}bin{sep}"))
            .Where(file => Shared.IsMatch(Regex.Replace(File.ReadAllText(file), @"^[ 	]*//.*$", string.Empty, RegexOptions.Multiline)))
            .Select(file => Path.GetRelativePath(dir.FullName, file))
            .ToList();

        Assert.True(offenders.Count == 0, "Log file sinks opened in shared mode: " + string.Join(", ", offenders));
    }
}
