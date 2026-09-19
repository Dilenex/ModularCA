using ModularCA.Migrate;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// Pointing the deployment at its new database, and keeping the way back.
/// <para>
/// The last step of a migration used to be ten lines of YAML printed to a terminal, two of them
/// thirty-odd random characters, shown once, to be transcribed into an owner-only file. That is
/// where a migration that worked becomes a node that will not start.
/// </para>
/// </summary>
public class ConfigUpdateTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "mca-config-" + Guid.NewGuid().ToString("N"));

    private const string MariaDbConfig = """
        App:
          Host: localhost
          Port: 3306
          Database: modularca
          Username: mca_app
          Password: old-app-secret
          SslMode: Preferred
        Audit:
          Host: localhost
          Port: 3306
          Database: modularca_audit
          Username: mca_audit
          Password: old-audit-secret
          SslMode: Preferred
        """;

    private string WriteSourceConfig()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "db.yaml");
        File.WriteAllText(path, MariaDbConfig);
        return path;
    }

    private MigrationOptions Options(string? configPath, bool noWrite = false) =>
        CommandLine.Parse([
            .. configPath is null ? new[]
            {
                "--source-host", "localhost", "--source-user", "mca_app", "--source-password", "s",
                "--source-app-db", "modularca", "--source-audit-db", "modularca_audit",
            } : ["--config", configPath],
            "--target-host", "127.0.0.1",
            .. noWrite ? new[] { "--no-write-config" } : [],
        ]);

    /// <summary>Removes the temporary directory.</summary>
    /// <remarks>
    /// Attributes are cleared first: File.Copy carries the read-only flag onto the backup, so the
    /// write-failure test below leaves two files the directory cannot be deleted over.
    /// </remarks>
    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            foreach (var file in Directory.EnumerateFiles(_directory))
                File.SetAttributes(file, FileAttributes.Normal);
            Directory.Delete(_directory, recursive: true);
        }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void The_mariadb_settings_are_kept_before_anything_is_written()
    {
        var path = WriteSourceConfig();

        var result = ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", DateTime.Now);

        var backup = Assert.Single(result.Backups);
        Assert.True(File.Exists(backup));
        Assert.Equal(MariaDbConfig, File.ReadAllText(backup));
    }

    [Fact]
    public void The_written_config_names_the_postgresql_databases_and_the_new_passwords()
    {
        var path = WriteSourceConfig();

        var result = ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", DateTime.Now);

        Assert.Contains(path, result.Written);
        var written = YamlDbConfigLoader.Load(path)!;

        Assert.Equal(5432, written.App.Port);
        Assert.Equal("app-pw", written.App.Password);
        Assert.Equal("audit-pw", written.Audit.Password);
        Assert.Equal("modularca", written.App.Database);
        Assert.Equal("modularca_audit", written.Audit.Database);
    }

    [Fact]
    public void The_backup_carries_the_moment_it_was_taken()
    {
        // Two runs against the same deployment must not have the second one overwrite the only
        // copy of the original MariaDB settings with a copy of the first run's PostgreSQL ones.
        var path = WriteSourceConfig();
        var first = ConfigUpdate.BackupPathFor(path, new DateTime(2026, 9, 19, 11, 30, 0));
        var second = ConfigUpdate.BackupPathFor(path, new DateTime(2026, 9, 19, 11, 45, 0));

        Assert.NotEqual(first, second);
        Assert.Contains("mariadb", first);
        Assert.StartsWith(path, first);
    }

    [Fact]
    public void A_second_run_does_not_clobber_the_first_backup()
    {
        var path = WriteSourceConfig();
        var when = DateTime.Now;

        var first = ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", when);
        Assert.True(first.Any);

        // Same timestamp, so the same backup name: the copy must refuse rather than overwrite a
        // backup that would now hold PostgreSQL settings labelled as the MariaDB ones.
        var second = ConfigUpdate.Apply(Options(path), "app-pw-2", "audit-pw-2", when);

        Assert.False(second.Any);
        Assert.NotNull(second.Reason);
        Assert.Equal(MariaDbConfig, File.ReadAllText(first.Backups[0]));
    }

    [Fact]
    public void Nothing_is_written_when_the_operator_asked_for_that()
    {
        var path = WriteSourceConfig();

        var result = ConfigUpdate.Apply(Options(path, noWrite: true), "app-pw", "audit-pw", DateTime.Now);

        Assert.False(result.Any);
        Assert.Empty(result.Backups);
        Assert.Contains("--no-write-config", result.Reason);
        Assert.Equal(MariaDbConfig, File.ReadAllText(path));
    }

    [Fact]
    public void Nothing_is_written_when_there_was_no_config_to_begin_with()
    {
        // Everything supplied on the command line, so there is no deployment here to point
        // anywhere. The settings get printed instead.
        var result = ConfigUpdate.Apply(Options(configPath: null), "app-pw", "audit-pw", DateTime.Now);

        Assert.False(result.Any);
        Assert.Contains("command line", result.Reason);
    }

    [Fact]
    public void A_failure_to_write_is_reported_rather_than_thrown()
    {
        // The migration has already succeeded and been verified by this point. A configuration
        // that cannot be written is a message and a manual step, not a failed migration — and the
        // backup taken first still stands, so the way back survives even this.
        var path = WriteSourceConfig();
        var options = Options(path);
        File.SetAttributes(path, FileAttributes.ReadOnly);

        try
        {
            var result = ConfigUpdate.Apply(options, "app-pw", "audit-pw", DateTime.Now);

            Assert.False(result.Any);
            Assert.NotNull(result.Reason);
            Assert.Equal(MariaDbConfig, File.ReadAllText(path));
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }
    private const string ConfigYaml = """
        Https:
          PublicDomain: ca4.example.net
          PublicPort: 443
        DB:
          App:
            Host: localhost
            Port: 3306
            Username: mca_app
            Password: "old-app-secret"
            Database: modularca
            SslMode: Preferred
          Audit:
            Host: localhost
            Port: 3306
            Username: mca_audit
            Password: "old-audit-secret"
            Database: modularca_audit
            SslMode: Preferred
        Features:
          MSAE: true
        """;

    private string WriteBothConfigs()
    {
        var path = WriteSourceConfig();
        File.WriteAllText(Path.Combine(_directory, "config.yaml"), ConfigYaml);
        return path;
    }

    [Fact]
    public void Both_files_are_updated_because_both_carry_the_settings()
    {
        // db.yaml alone is not enough: config.yaml has the same settings under DB:, and a node
        // started with only one of them updated goes looking for the database it used to have.
        var path = WriteBothConfigs();

        var result = ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", DateTime.Now);

        Assert.Equal(2, result.Written.Count);
        Assert.Equal(2, result.Backups.Count);
        Assert.Contains(result.Written, w => w.EndsWith("config.yaml", StringComparison.Ordinal));
    }

    [Fact]
    public void Everything_in_config_yaml_that_is_not_the_db_section_survives()
    {
        // A migration has no business touching TLS, features, mail or scheduling. Bootstrap
        // rewrites that whole file from scratch; doing the same here would silently discard
        // whatever the operator has changed since.
        var path = WriteBothConfigs();

        ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", DateTime.Now);
        var after = File.ReadAllText(Path.Combine(_directory, "config.yaml"));

        Assert.Contains("PublicDomain: ca4.example.net", after);
        Assert.Contains("MSAE: true", after);
        Assert.DoesNotContain("old-app-secret", after);
        Assert.Contains("app-pw", after);
    }

    [Fact]
    public void The_updated_config_yaml_loads_back_as_the_node_will_read_it()
    {
        var path = WriteBothConfigs();

        ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", DateTime.Now);
        var loaded = YamlConfigLoader.Load(Path.Combine(_directory, "config.yaml"));

        Assert.Equal(5432, loaded.DB.App.Port);
        Assert.Equal("app-pw", loaded.DB.App.Password);
        Assert.Equal("audit-pw", loaded.DB.Audit.Password);
        Assert.Equal("modularca_audit", loaded.DB.Audit.Database);
    }

    [Fact]
    public void A_password_is_written_quoted_in_both_files()
    {
        // A generated password is arbitrary text. An unquoted scalar that reads as a number, a
        // boolean, or that starts with a character the parser treats specially stops being the
        // string it was — and surfaces much later as a connection refused.
        var path = WriteBothConfigs();

        ConfigUpdate.Apply(Options(path), "12345", "true", DateTime.Now);

        Assert.Contains("\"12345\"", File.ReadAllText(path));
        Assert.Contains("\"true\"", File.ReadAllText(Path.Combine(_directory, "config.yaml")));
    }

    [Fact]
    public void A_config_yaml_with_no_db_section_gains_one()
    {
        var path = WriteSourceConfig();
        File.WriteAllText(Path.Combine(_directory, "config.yaml"), "Features:\n  MSAE: true\n");

        ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", DateTime.Now);
        var loaded = YamlConfigLoader.Load(Path.Combine(_directory, "config.yaml"));

        Assert.Equal("app-pw", loaded.DB.App.Password);
    }

    [Fact]
    public void A_deployment_without_a_config_yaml_still_gets_its_db_yaml()
    {
        // The two are updated together where both exist; a db.yaml on its own is still worth
        // writing rather than refusing over a file that is not there.
        var path = WriteSourceConfig();

        var result = ConfigUpdate.Apply(Options(path), "app-pw", "audit-pw", DateTime.Now);

        Assert.Single(result.Written);
        Assert.Contains(path, result.Written);
    }
}
