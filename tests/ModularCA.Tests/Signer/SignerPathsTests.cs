using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// Where the signer reads its files from: the shared layout under the application directory,
/// exactly as before <c>--signer-dir</c>, or the signer's own directory, from which every
/// settings file, identity file and log comes and nothing under <c>config/</c> or <c>logs/</c>.
/// </summary>
public sealed class SignerPathsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-signerpaths-" + Guid.NewGuid().ToString("N"));
    private readonly string _base;

    public SignerPathsTests()
    {
        _base = Path.Combine(_root, "app");
        Directory.CreateDirectory(_base);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public void The_shared_layout_is_the_paths_every_install_has_had()
    {
        var paths = SignerPaths.Shared(_base);
        var defaults = new SignerConfig();

        Assert.False(paths.IsDedicated);
        Assert.Null(paths.SignerDirectory);
        Assert.Equal(Path.Combine(_base, "config", "config.yaml"), paths.ConfigPath);
        Assert.Equal(Path.Combine(_base, "config", "db.yaml"), paths.DbYamlPath);
        Assert.Equal(Path.Combine(_base, "config", "keystore.yaml"), paths.KeystoreYamlPath);
        Assert.Equal(Path.Combine(_base, "keystores"), paths.KeystoresDirectory);
        Assert.Equal(Path.Combine(_base, "logs"), paths.LogsDirectory);
        Assert.Equal(SignerConfig.ResolvePath(defaults.ServerCertificate, _base), paths.ResolveFile(defaults.ServerCertificate));
        Assert.Equal(SignerConfig.ResolvePath(defaults.IdentityCa, _base), paths.ResolveFile(defaults.IdentityCa));
    }

    [Fact]
    public void Without_the_flag_the_command_line_gives_the_shared_layout_for_every_role()
    {
        foreach (var args in new[] { Array.Empty<string>(), new[] { "--role", "signer" }, new[] { "--role", "node" }, new[] { "--upgrade-check", "--config-dir", "/x" } })
        {
            var paths = SignerPaths.ForRun(args, _base, out var absent);
            Assert.False(paths.IsDedicated);
            Assert.Null(absent);
            Assert.Equal(SignerPaths.Shared(_base).ConfigPath, paths.ConfigPath);
        }
    }

    [Fact]
    public void The_signers_own_directory_holds_every_file_it_reads()
    {
        var dir = Path.Combine(_root, "signer");
        var paths = SignerPaths.Dedicated(_base, dir);

        Assert.True(paths.IsDedicated);
        Assert.Equal(Path.Combine(dir, "signer.yaml"), paths.ConfigPath);
        Assert.Equal(Path.Combine(dir, "db.yaml"), paths.DbYamlPath);
        Assert.Equal(Path.Combine(dir, "keystore.yaml"), paths.KeystoreYamlPath);
        Assert.Equal(Path.Combine(dir, "logs"), paths.LogsDirectory);
        Assert.Equal(Path.Combine(_base, "keystores"), paths.KeystoresDirectory);
        Assert.Equal(Path.Combine(dir, "signer-server.pfx"), paths.ResolveFile(new SignerConfig().ServerCertificate));
        Assert.Equal(Path.Combine(dir, "signer-identity-ca.pfx"), paths.ResolveFile(new SignerConfig().IdentityCa));
    }

    [Theory]
    [InlineData("signer-server.pfx", "signer-server.pfx")]
    [InlineData("config/signer-server.pfx", "signer-server.pfx")]
    [InlineData("./config/signer-server.pfx", "signer-server.pfx")]
    [InlineData("config\\signer-server.pfx", "signer-server.pfx")]
    [InlineData("identity/server.pfx", "identity/server.pfx")]
    [InlineData("logs/modularca-.log", "logs/modularca-.log")]
    public void In_its_own_directory_a_relative_path_resolves_there_and_config_names_the_directory(string configured, string expected)
    {
        var dir = Path.Combine(_root, "signer");
        Assert.Equal(Path.GetFullPath(Path.Combine(dir, expected)), Path.GetFullPath(SignerPaths.Dedicated(_base, dir).ResolveFile(configured)));
    }

    [Fact]
    public void A_rooted_path_is_used_as_it_is_in_either_layout()
    {
        var rooted = Path.Combine(_root, "elsewhere", "server.pfx");
        Assert.Equal(rooted, SignerPaths.Shared(_base).ResolveFile(rooted));
        Assert.Equal(rooted, SignerPaths.Dedicated(_base, Path.Combine(_root, "signer")).ResolveFile(rooted));
    }

    [Fact]
    public void With_its_own_directory_nothing_the_signer_reads_or_logs_is_under_the_nodes_config_or_logs()
    {
        var dir = Path.Combine(_root, "signer");
        Directory.CreateDirectory(dir);
        var paths = SignerPaths.ForRun(new[] { "--role", "signer", SignerPaths.Flag, dir }, _base, out var absent);
        Assert.Null(absent);

        var signer = new SignerConfig();
        var read = paths.SettingsFiles(signer).Append(paths.ResolveFile("logs/modularca-.log")).Append(paths.LogsDirectory).ToList();
        var nodeConfig = Path.Combine(_base, "config") + Path.DirectorySeparatorChar;
        var nodeLogs = Path.Combine(_base, "logs") + Path.DirectorySeparatorChar;
        Assert.Equal(5, paths.SettingsFiles(signer).Count);
        foreach (var path in read)
        {
            var full = Path.GetFullPath(path);
            Assert.StartsWith(Path.GetFullPath(dir), full, StringComparison.Ordinal);
            Assert.False(full.StartsWith(nodeConfig, StringComparison.OrdinalIgnoreCase), $"{full} is under the node's config/");
            Assert.False((full + Path.DirectorySeparatorChar).StartsWith(nodeLogs, StringComparison.OrdinalIgnoreCase), $"{full} is under the node's logs/");
        }
        Assert.DoesNotContain(read, p => p.EndsWith("config.yaml", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_named_directory_that_does_not_exist_is_the_shared_layout_and_is_reported()
    {
        var dir = Path.Combine(_root, "not-created");
        var paths = SignerPaths.ForRun(new[] { "--role", "signer", SignerPaths.Flag, dir }, _base, out var absent);

        Assert.False(paths.IsDedicated);
        Assert.Equal(Path.GetFullPath(dir), absent);
        Assert.Equal(Path.Combine(_base, "config", "config.yaml"), paths.ConfigPath);
    }

    [Fact]
    public void The_flag_is_made_absolute()
    {
        var paths = SignerPaths.FromArgs(new[] { SignerPaths.Flag, "relative-signer" }, _base);
        Assert.True(Path.IsPathRooted(paths.SignerDirectory!));
        Assert.Equal(Path.GetFullPath("relative-signer"), paths.SignerDirectory);
    }

    [Theory]
    [InlineData("--signer-dir")]
    [InlineData("--signer-dir|--role|signer")]
    [InlineData("--signer-dir|")]
    [InlineData("--signer-dir|/a|--signer-dir|/b")]
    public void A_flag_with_no_value_or_given_twice_is_refused(string commandLine)
        => Assert.Throws<ArgumentException>(() => SignerPaths.FromArgs(commandLine.Split('|'), _base));
}
