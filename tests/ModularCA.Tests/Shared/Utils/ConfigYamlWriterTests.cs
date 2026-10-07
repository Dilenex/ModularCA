using System.Text.RegularExpressions;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// <c>config.yaml</c> as the running node writes it: never the <c>db.yaml</c> credentials, and
/// always in place, so a split install's signer keeps its group read.
/// </summary>
public sealed class ConfigYamlWriterTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-config-writer-{Guid.NewGuid():N}");

    /// <summary>Creates a scratch directory.</summary>
    public ConfigYamlWriterTests() => Directory.CreateDirectory(_dir);

    /// <summary>Removes the scratch directory.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static SystemConfig ConfigWithDbCredentials()
    {
        var config = new SystemConfig();
        config.DB.App.Username = "modularca_app";
        config.DB.App.Password = "app-password-from-db-yaml";
        config.DB.Audit.Password = "audit-password-from-db-yaml";
        config.JWT.Secret = "jwt-secret";
        config.Backup.EncryptionMode = "StoredPassword";
        return config;
    }

    [Fact]
    public void The_serialised_configuration_carries_no_db_section_or_password()
    {
        var yaml = ConfigYamlWriter.Serialize(ConfigWithDbCredentials());

        Assert.DoesNotContain("app-password-from-db-yaml", yaml);
        Assert.DoesNotContain("audit-password-from-db-yaml", yaml);
        Assert.DoesNotContain("modularca_app", yaml);
        Assert.DoesNotMatch(new Regex(@"^DB:", RegexOptions.Multiline), yaml);
    }

    [Fact]
    public void Everything_else_round_trips()
    {
        var path = Path.Combine(_dir, "config.yaml");
        ConfigYamlWriter.Write(path, ConfigWithDbCredentials());

        var loaded = YamlConfigLoader.Load(path, _ => { });

        Assert.Equal("jwt-secret", loaded.JWT.Secret);
        Assert.Equal("StoredPassword", loaded.Backup.EncryptionMode);
        Assert.Equal(string.Empty, loaded.DB.App.Password);
    }

    [Fact]
    public void Serialising_leaves_the_running_configuration_untouched()
    {
        var config = ConfigWithDbCredentials();

        ConfigYamlWriter.Serialize(config);

        Assert.Equal("app-password-from-db-yaml", config.DB.App.Password);
    }

    [Fact]
    public void An_existing_file_is_rewritten_in_place_and_keeps_its_mode()
    {
        var path = Path.Combine(_dir, "config.yaml");
        File.WriteAllText(path, "old: true\n");
        var groupRead = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead;
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, groupRead);

        ConfigYamlWriter.Write(path, ConfigWithDbCredentials());

        Assert.Contains("jwt-secret", File.ReadAllText(path));
        Assert.Equal(["config.yaml"], Directory.GetFiles(_dir).Select(Path.GetFileName));
        if (!OperatingSystem.IsWindows())
            Assert.Equal(groupRead, File.GetUnixFileMode(path));
    }

    [Fact]
    public void A_new_file_is_created_owner_only()
    {
        var path = Path.Combine(_dir, "new.yaml");

        ConfigYamlWriter.WriteKeepingAccess(path, "x: 1\n");

        Assert.Equal("x: 1\n", File.ReadAllText(path));
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }

    [Fact]
    public void The_db_section_of_an_older_file_is_removed_and_nothing_else()
    {
        const string yaml = "JWT:\n  Secret: s\nDB:\n  App:\n    Password: \"p\"\n\n  Audit:\n    Password: \"q\"\nBackup:\n  OutputPath: backups\n";

        var stripped = ConfigYamlWriter.WithoutDbSection(yaml);

        Assert.Equal("JWT:\n  Secret: s\nBackup:\n  OutputPath: backups\n", stripped);
        Assert.Equal("JWT:\n  Secret: s\n", ConfigYamlWriter.WithoutDbSection("JWT:\n  Secret: s\n"));
    }

    /// <summary>
    /// Every runtime writer of <c>config.yaml</c> goes through <see cref="ConfigYamlWriter"/>:
    /// none serialises the configuration itself, and none tightens the file to owner-only after
    /// writing it, which would take the signer's group read away on a split install.
    /// </summary>
    [Fact]
    public void Every_writer_of_config_yaml_goes_through_the_writer()
    {
        var root = RepoRoot();
        var offenders = new List<string>();
        foreach (var project in Directory.GetDirectories(root, "ModularCA.*"))
        {
            foreach (var file in Directory.EnumerateFiles(project, "*.cs", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
                if (relative.Contains("/bin/") || relative.Contains("/obj/") || relative.EndsWith("/ConfigYamlWriter.cs"))
                    continue;
                var text = File.ReadAllText(file);
                if (!text.Contains("config.yaml", StringComparison.Ordinal))
                    continue;

                if (Regex.IsMatch(text, @"\.Serialize\(_?config\)") && !relative.EndsWith("/BootstrapDatabaseSetup.cs"))
                    offenders.Add($"{relative}: serialises the configuration itself");
                if (Regex.IsMatch(text, @"SetOwnerOnly\((configPath|configYamlPath|yamlPath)\)"))
                    offenders.Add($"{relative}: makes config.yaml owner-only after writing it");
            }
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
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
