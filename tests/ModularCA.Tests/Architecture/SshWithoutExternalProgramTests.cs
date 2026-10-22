using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Architecture;

/// <summary>
/// The node signs SSH certificates and creates SSH CA keys through the signer, and builds KRLs in
/// process (<c>docs/architecture/ssh-keystore.md</c>, stage 3). It runs no program for any of it
/// and has no setting that names one. This reads the source of <c>ModularCA.Core</c> and
/// <c>ModularCA.API</c> to hold that: neither names <c>ssh-keygen</c> or its retired setting
/// anywhere, and no SSH source file of theirs starts a process. Nor does any of them read a key
/// file, with one exception by name: the import of stage 4, which moves the key files of an
/// older install into the signer and removes them.
/// </summary>
public class SshWithoutExternalProgramTests
{
    private static readonly string[] Projects = ["ModularCA.Core", "ModularCA.API"];

    /// <summary>The program, the retired setting that named it, and the helper that ran it.</summary>
    private static readonly Regex NamesTheProgram = new(
        @"ssh-keygen|SshKeygenPath|ProcessRunner", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Every way a source file starts a process.</summary>
    private static readonly Regex StartsAProcess = new(
        @"System\.Diagnostics\.Process\b|\bProcessStartInfo\b|\bProcess\.Start\b|using\s+System\.Diagnostics\s*;[\s\S]*\bnew\s+Process\b",
        RegexOptions.Compiled);

    /// <summary>The plaintext key files of before: nothing here reads a key path or a key directory.</summary>
    private static readonly Regex ReadsAKeyFile = new(
        @"PrivateKeyPath\s*[!)]|\.PrivateKeyPath\s*,|KeyStoragePath|ssh-ca-keys", RegexOptions.Compiled);

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static IEnumerable<(string Path, string Text)> Sources(Func<string, bool>? where = null)
    {
        var root = RepoRoot();
        foreach (var project in Projects)
        {
            foreach (var file in Directory.EnumerateFiles(Path.Combine(root, project), "*.cs", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
                if (relative.Contains("/bin/") || relative.Contains("/obj/"))
                    continue;
                if (where == null || where(relative))
                    yield return (relative, File.ReadAllText(file));
            }
        }
    }

    private static bool IsSshSource(string relativePath) => Path.GetFileName(relativePath).Contains("Ssh", StringComparison.Ordinal);

    private static List<string> Hits(IEnumerable<(string Path, string Text)> sources, Regex pattern)
        => sources.SelectMany(s => pattern.Matches(s.Text).Select(m => $"{s.Path}: {m.Value.Trim()}")).ToList();

    [Fact]
    public void The_ssh_sources_are_actually_found()
    {
        var ssh = Sources(IsSshSource).Select(s => s.Path).ToList();

        Assert.Contains("ModularCA.Core/Services/SshCaService.cs", ssh);
        Assert.Contains("ModularCA.Core/Services/SshCertificateOptions.cs", ssh);
        Assert.Contains("ModularCA.API/Controllers/v1/Admin/AdminSshController.cs", ssh);
        Assert.Contains("ModularCA.API/Controllers/v1/User/UserSshController.cs", ssh);
        Assert.Contains("ModularCA.API/Controllers/v1/Public/PublicSshController.cs", ssh);
        Assert.True(Sources().Count() > 300, "The node's source was not found; every check below would pass on nothing.");
    }

    [Fact]
    public void Nothing_in_the_node_names_ssh_keygen_its_setting_or_the_helper_that_ran_it()
    {
        var found = Hits(Sources(), NamesTheProgram);

        Assert.True(found.Count == 0, "The node runs no program for SSH:\n" + string.Join("\n", found));
        Assert.False(File.Exists(Path.Combine(RepoRoot(), "ModularCA.Core", "Helpers", "ProcessRunner.cs")));
    }

    [Fact]
    public void No_ssh_source_starts_a_process()
    {
        var found = Hits(Sources(IsSshSource), StartsAProcess);

        Assert.True(found.Count == 0, "SSH code starts no process:\n" + string.Join("\n", found));
    }

    /// <summary>
    /// The one SSH source that reads key files, and the only one that may: the one-time import of
    /// the plaintext key files of before into the signer (stage 4, "The import"). It has to read
    /// each file to hand its key to the signer, and to overwrite and delete it afterwards.
    /// Everything else that needs to know about a key file (the upgrade check, the readiness
    /// page, the admin key list, the factory reset) asks this file.
    /// </summary>
    private const string TheImport = "ModularCA.Core/Services/SshKeyFileImport.cs";

    /// <summary>What reads, writes or removes a file or a directory.</summary>
    private static readonly Regex TouchesFiles = new(
        @"\bFile\.(Read|Write|Delete|Open|Exists|SetUnixFileMode)|\bDirectory\.(Create|Delete)|Path\.GetTemp", RegexOptions.Compiled);

    [Fact]
    public void No_ssh_source_reads_a_key_file_or_a_key_directory_except_the_import()
    {
        var sources = Sources(s => IsSshSource(s) && s != TheImport).ToList();
        var found = Hits(sources, ReadsAKeyFile);

        Assert.True(found.Count == 0, "SSH code reads no key file:\n" + string.Join("\n", found));
        Assert.DoesNotContain(sources, s => TouchesFiles.IsMatch(s.Text));

        // The exception is that one file by name, and it is the import: were it gone, or no
        // longer reading key files, the carve-out would be excusing nothing.
        var import = Assert.Single(Sources(s => s == TheImport));
        Assert.Matches(ReadsAKeyFile, import.Text);
        Assert.Matches(TouchesFiles, import.Text);
        Assert.Contains("SigningPurpose.SshKeyMigration", import.Text);
        Assert.Empty(Hits([import], StartsAProcess));
    }

    [Fact]
    public void The_checks_see_what_they_look_for()
    {
        Assert.Matches(NamesTheProgram, "var (exit, _, err) = await ProcessRunner.RunAsync(_config.SshCa.SshKeygenPath, args);");
        Assert.Matches(NamesTheProgram, "/// Generates a new SSH CA key pair using ssh-keygen.");
        Assert.Matches(StartsAProcess, "using var process = Process.Start(start)!;");
        Assert.Matches(StartsAProcess, "var start = new ProcessStartInfo(path)");
        Assert.Matches(StartsAProcess, "System.Diagnostics.Process.GetCurrentProcess()");
        Assert.Matches(ReadsAKeyFile, "var args = new List<string> { \"-s\", caKey.PrivateKeyPath!, \"-I\" };");
        Assert.Matches(ReadsAKeyFile, "Path.Combine(AppContext.BaseDirectory, _config.SshCa.KeyStoragePath)");
        Assert.DoesNotMatch(ReadsAKeyFile, "PrivateKeyPath = null,");
        Assert.DoesNotMatch(StartsAProcess, "The signer builds and signs the certificate; the node processes the reply.");
    }
}
