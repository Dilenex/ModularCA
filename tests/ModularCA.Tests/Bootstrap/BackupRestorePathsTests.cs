using System.IO.Compression;
using ModularCA.Bootstrap;
using ModularCA.Shared.Signing;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Runs only when the test host's own <c>config/db.yaml</c> is absent: with one present, a
/// restore driven from a test would write into the databases it names.
/// </summary>
public sealed class NoLocalDbYamlFactAttribute : FactAttribute
{
    /// <summary>Skips when <c>config/db.yaml</c> exists beside the test assembly.</summary>
    public NoLocalDbYamlFactAttribute()
    {
        if (File.Exists(Path.Combine(AppContext.BaseDirectory, "config", "db.yaml")))
            Skip = "config/db.yaml exists beside the test assembly; a restore would target the databases it names.";
    }
}

/// <summary>
/// Where backup and restore write now that the program files are root's and only
/// <c>config/</c>, <c>keystores/</c>, <c>logs/</c> and <c>backups/</c> are the service's, and
/// which databases a restore writes into: this host's own <c>db.yaml</c>, never the archive's.
/// </summary>
public sealed class BackupRestorePathsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"mca-backup-paths-{Guid.NewGuid():N}");
    private readonly string _base;
    private readonly string _config;

    /// <summary>Creates a scratch application directory with an empty <c>config/</c>.</summary>
    public BackupRestorePathsTests()
    {
        _base = Path.Combine(_root, "opt", "modularca");
        _config = Path.Combine(_base, "config");
        Directory.CreateDirectory(_config);
    }

    /// <summary>Removes the scratch directory.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private static string RuntimeDirectoryOf(string baseDir, string path)
    {
        var relative = Path.GetRelativePath(baseDir, path).Replace('\\', '/');
        return relative.Split('/')[0];
    }

    [Fact]
    public void The_default_archive_goes_to_backups_not_beside_the_binary()
    {
        var path = BackupRestore.ResolveArchivePath(null, _base, null, "modularca-backup-20261005-000000");

        Assert.Equal(Path.Combine(_base, "backups", "modularca-backup-20261005-000000.zip"), path);
        Assert.Equal("backups", RuntimeDirectoryOf(_base, path));
    }

    [Fact]
    public void The_default_archive_follows_the_configured_output_path()
    {
        var path = BackupRestore.ResolveArchivePath(null, _base, "backups/nightly", "b");

        Assert.Equal(Path.Combine(_base, "backups", "nightly", "b.zip"), path);
    }

    [Fact]
    public void An_explicit_archive_path_under_backups_is_allowed()
    {
        var explicitPath = Path.Combine(_base, "backups", "mine.zip");

        Assert.Equal(explicitPath, BackupRestore.ResolveArchivePath(explicitPath, _base, null, "ignored"));
    }

    [Theory]
    [InlineData("sibling")]
    [InlineData("rooted")]
    public void An_archive_path_outside_the_application_directory_is_refused(string kind)
    {
        // A sibling that shares the prefix, and a rooted Backup.OutputPath elsewhere.
        var outside = Path.Combine(_root, "opt", "modularca-backups");
        Assert.Throws<InvalidOperationException>(() => kind == "sibling"
            ? BackupRestore.ResolveArchivePath(Path.Combine(outside, "x.zip"), _base, null, "x")
            : BackupRestore.ResolveArchivePath(null, _base, outside, "x"));
    }

    [Fact]
    public void The_pre_restore_snapshot_goes_to_backups_on_a_host_without_config_yaml()
    {
        var path = BackupRestore.PreRestoreSnapshotPath(_base, _config, new DateTime(2026, 10, 5, 1, 2, 3, DateTimeKind.Utc));

        Assert.Equal(Path.Combine(_base, "backups", "pre-restore-20261005-010203.zip"), path);
    }

    [Fact]
    public void The_pre_restore_snapshot_goes_to_the_backup_directory_this_hosts_config_names()
    {
        File.WriteAllText(Path.Combine(_config, "config.yaml"), "Backup:\n  OutputPath: backups/site-a\n");

        var path = BackupRestore.PreRestoreSnapshotPath(_base, _config, DateTime.UtcNow);

        Assert.Equal(Path.Combine(_base, "backups", "site-a"), Path.GetDirectoryName(path));
        Assert.StartsWith("pre-restore-", Path.GetFileName(path));
    }

    [Fact]
    public void An_unreadable_config_yaml_still_leaves_the_snapshot_a_place_in_backups()
    {
        File.WriteAllText(Path.Combine(_config, "config.yaml"), "Backup: [unclosed\n");

        var path = BackupRestore.PreRestoreSnapshotPath(_base, _config, DateTime.UtcNow);

        Assert.Equal("backups", RuntimeDirectoryOf(_base, path));
    }

    private void WriteDbYaml(string appDatabase, string appUser, string appPassword) =>
        File.WriteAllText(Path.Combine(_config, "db.yaml"), $"""
            App:
              Host: db.new-host.example
              Port: 5433
              Database: {appDatabase}
              Username: {appUser}
              Password: "{appPassword}"
              SslMode: VerifyFull
            Audit:
              Host: db.new-host.example
              Port: 5433
              Database: new-audit
              Username: new_audit
              Password: "audit-secret"
              SslMode: VerifyFull
            """);

    [Fact]
    public void A_restore_targets_this_hosts_db_yaml_not_the_db_section_of_a_config_yaml()
    {
        WriteDbYaml("new-app", "new_app", "new-secret");
        // An old, polluted config.yaml naming the host the backup was taken on.
        File.WriteAllText(Path.Combine(_config, "config.yaml"), """
            DB:
              App:
                Host: db.old-host.example
                Database: old-app
                Username: old_app
                Password: "old-secret"
            """);

        var target = BackupRestore.LoadRestoreTargetDatabases(_config, out var problem);

        Assert.Null(problem);
        Assert.NotNull(target);
        Assert.Equal("db.new-host.example", target!.DB.App.Host);
        Assert.Equal(5433, target.DB.App.Port);
        Assert.Equal("new-app", target.DB.App.Database);
        Assert.Equal("new_app", target.DB.App.Username);
        Assert.Equal("new-secret", target.DB.App.Password);
        Assert.Equal("VerifyFull", target.DB.App.SslMode);
        Assert.Equal("new-audit", target.DB.Audit.Database);
        Assert.Equal("audit-secret", target.DB.Audit.Password);
    }

    [Fact]
    public void A_host_without_db_yaml_has_no_restore_target_and_says_so()
    {
        File.WriteAllText(Path.Combine(_config, "config.yaml"), "DB:\n  App:\n    Database: old-app\n    Username: old_app\n");

        var target = BackupRestore.LoadRestoreTargetDatabases(_config, out var problem);

        Assert.Null(target);
        Assert.Contains("db.yaml", problem);
    }

    [Fact]
    public void A_db_yaml_naming_no_application_database_is_no_restore_target()
    {
        WriteDbYaml("", "new_app", "x");

        Assert.Null(BackupRestore.LoadRestoreTargetDatabases(_config, out var problem));
        Assert.Contains("names no application database", problem);
    }

    [NoLocalDbYamlFact]
    public async Task A_restore_on_a_host_without_db_yaml_stops_before_the_signer_or_anything_else_is_touched()
    {
        // A plain archive whose config.yaml names another host's database with credentials.
        var staging = Path.Combine(_root, "archive");
        Directory.CreateDirectory(Path.Combine(staging, "config"));
        File.WriteAllText(Path.Combine(staging, "manifest.json"), """{"Version":"1.0","AppDatabase":"old-app"}""");
        File.WriteAllText(Path.Combine(staging, "db-app.dump"), "PGDMP");
        File.WriteAllText(Path.Combine(staging, "config", "config.yaml"),
            "DB:\n  App:\n    Host: db.old-host.example\n    Database: old-app\n    Username: old_app\n    Password: \"old-secret\"\n");
        var archive = Path.Combine(_root, "modularca-backup-test.zip");
        ZipFile.CreateFromDirectory(staging, archive);

        var liveConfig = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
        var before = File.Exists(liveConfig) ? File.ReadAllBytes(liveConfig) : null;
        var signerAsked = false;

        var exit = await BackupRestore.Restore(archive, _ =>
        {
            signerAsked = true;
            throw new InvalidOperationException("the signer must not be built");
        }, skipSchemaCheck: true, interactive: false);

        Assert.Equal(1, exit);
        Assert.False(signerAsked);
        Assert.Equal(before, File.Exists(liveConfig) ? File.ReadAllBytes(liveConfig) : null);
        Assert.Empty(Directory.GetFiles(AppContext.BaseDirectory, "pre-restore-*.zip"));
    }

    /// <summary>
    /// An archive whose backup could not dump the database used to restore its keystores and
    /// config over a database they did not belong to, and report success.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task An_archive_without_its_application_database_is_refused_before_anything_is_touched(bool emptyDump)
    {
        var staging = Path.Combine(_root, "archive");
        Directory.CreateDirectory(Path.Combine(staging, "config"));
        File.WriteAllText(Path.Combine(staging, "manifest.json"), """{"Version":"1.0","AppDatabase":"old-app"}""");
        File.WriteAllText(Path.Combine(staging, "config", "config.yaml"), "JWT:\n  Issuer: ModularCA\n");
        if (emptyDump)
            File.WriteAllBytes(Path.Combine(staging, "db-app.dump"), []);
        var archive = Path.Combine(_root, "modularca-backup-test.zip");
        ZipFile.CreateFromDirectory(staging, archive);
        var signerAsked = false;
        var output = new StringWriter();
        var console = Console.Out;
        Console.SetOut(output);
        int exit;
        try
        {
            exit = await BackupRestore.Restore(archive, _ =>
            {
                signerAsked = true;
                throw new InvalidOperationException("the signer must not be built");
            }, skipSchemaCheck: true, interactive: false);
        }
        finally
        {
            Console.SetOut(console);
        }

        Assert.Equal(1, exit);
        Assert.False(signerAsked);
        Assert.Contains("holds no application database", output.ToString());
    }

    [Theory]
    [InlineData(null, 60)]
    [InlineData(0, 1)]
    [InlineData(-5, 1)]
    [InlineData(90, 90)]
    public void A_database_tool_may_run_for_the_configured_minutes_and_never_less_than_one(int? configured, int minutes)
    {
        var backup = configured is null ? null : new ModularCA.Shared.Models.Config.BackupConfig { DatabaseTimeoutMinutes = configured.Value };

        Assert.Equal(minutes * 60_000, BackupRestore.DatabaseToolTimeoutMs(backup));
    }

    [Fact]
    public void A_restored_config_yaml_loses_the_archives_db_section_and_keeps_the_rest()
    {
        var source = Path.Combine(_root, "archived-config.yaml");
        File.WriteAllText(source, "JWT:\n  Issuer: ModularCA\nDB:\n  App:\n    Password: \"old-secret\"\nBackup:\n  OutputPath: backups\n");
        var destination = Path.Combine(_config, "config.yaml");
        File.WriteAllText(destination, "old\n");

        BackupRestore.RestoreConfigFile(source, destination);

        var restored = File.ReadAllText(destination);
        Assert.DoesNotContain("old-secret", restored);
        Assert.DoesNotContain("DB:", restored);
        Assert.Contains("Issuer: ModularCA", restored);
        Assert.Contains("OutputPath: backups", restored);
    }

    [Fact]
    public void A_restored_config_file_keeps_the_mode_of_the_file_it_replaces_and_a_new_one_is_owner_only()
    {
        var source = Path.Combine(_root, "archived.yaml");
        File.WriteAllText(source, "Signer: {}\n");
        var existing = Path.Combine(_config, "config.yaml");
        File.WriteAllText(existing, "old\n");
        var created = Path.Combine(_config, "mail.yaml");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(existing, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);

        BackupRestore.RestoreConfigFile(source, existing);
        BackupRestore.RestoreConfigFile(source, created);

        Assert.Equal("Signer: {}\n", File.ReadAllText(existing));
        Assert.Equal("Signer: {}\n", File.ReadAllText(created));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead, File.GetUnixFileMode(existing));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(created));
        }
    }
}
