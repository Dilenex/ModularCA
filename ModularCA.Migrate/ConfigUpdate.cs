using ModularCA.Shared.Utils;

namespace ModularCA.Migrate;

/// <summary>
/// Points the deployment at the database it now has, and keeps the one it had.
/// <para>
/// The alternative was printing ten lines of YAML, including two generated passwords, and asking
/// the operator to transcribe them. That is the step where a migration that worked becomes a node
/// that will not start: the passwords are thirty-odd random characters, they are shown exactly
/// once, and the file they belong in is owner-only root. Writing it is both safer and less work.
/// </para>
/// <para>
/// The backup is the point, though. It is taken before anything is written, it holds the MariaDB
/// credentials verbatim, and it is what makes the rollback real rather than theoretical: the
/// source database was never touched, so restoring one file and reinstalling 0.3.0 puts the
/// deployment back exactly where it started.
/// </para>
/// </summary>
public static class ConfigUpdate
{
    /// <summary>What happened to the deployment's configuration.</summary>
    /// <param name="Written">The files that now name the PostgreSQL databases.</param>
    /// <param name="Backups">Where the MariaDB configuration was kept, one per file written.</param>
    /// <param name="Reason">Why nothing was written, when nothing was.</param>
    public sealed record Result(
        IReadOnlyList<string> Written, IReadOnlyList<string> Backups, string? Reason)
    {
        /// <summary>Whether anything was changed.</summary>
        public bool Any => Written.Count > 0;

        /// <summary>A result meaning nothing was written, for the stated reason.</summary>
        /// <param name="reason">Why.</param>
        /// <returns>The result.</returns>
        public static Result Nothing(string reason) => new([], [], reason);
    }

    /// <summary>
    /// Builds the name of the backup, which carries the moment it was taken so a second run
    /// cannot quietly overwrite the first one's copy of the original.
    /// </summary>
    /// <param name="configPath">The configuration file being backed up.</param>
    /// <param name="now">The time to stamp it with.</param>
    /// <returns>The backup path.</returns>
    public static string BackupPathFor(string configPath, DateTime now) =>
        configPath + $".mariadb-{now:yyyyMMdd-HHmmss}.bak";

    /// <summary>
    /// Backs up the existing configuration and writes one naming the PostgreSQL databases.
    /// </summary>
    /// <param name="options">The resolved options, which carry the configuration path.</param>
    /// <param name="appPassword">The generated application role password.</param>
    /// <param name="auditPassword">The generated audit role password.</param>
    /// <param name="now">The time to stamp the backup with.</param>
    /// <returns>What was done, or why it was not.</returns>
    public static Result Apply(
        MigrationOptions options, string appPassword, string auditPassword, DateTime now)
    {
        if (options.NoWriteConfig)
            return Result.Nothing("--no-write-config was given");

        if (options.ConfigPath is not string dbYamlPath)
            return Result.Nothing(
                "there is no db.yaml to update — every setting was supplied on the command line");

        var written = new List<string>();
        var backups = new List<string>();

        try
        {
            // db.yaml is entirely ours, so it is rewritten.
            Backup(dbYamlPath, now, backups);
            YamlDbConfigLoader.Write(dbYamlPath, new YamlDbConfigLoader.DbYamlConfig
            {
                App = Instance(options, options.TargetAppDatabase, options.TargetAppRole, appPassword),
                Audit = Instance(options, options.TargetAuditDatabase, options.TargetAuditRole, auditPassword),
            });
            written.Add(dbYamlPath);

            // config.yaml carries the same settings under DB:, beside everything else the
            // deployment has been configured with. Leaving it behind is what makes a node start
            // against the database it used to have — so both are updated, or neither is.
            var configYamlPath = Path.Combine(
                Path.GetDirectoryName(dbYamlPath) ?? ".", "config.yaml");

            if (File.Exists(configYamlPath))
            {
                Backup(configYamlPath, now, backups);

                var original = File.ReadAllText(configYamlPath);
                var db = ConfigYamlDbSection.From(options, appPassword, auditPassword);
                File.WriteAllText(configYamlPath, ConfigYamlDbSection.Replace(original, db));
                FileSecurityUtil.SetOwnerOnly(configYamlPath);

                // Proved rather than assumed: a spliced file that does not load back as intended
                // is restored, because a broken config.yaml stops the node from starting at all.
                if (Verify(configYamlPath, db) is string problem)
                {
                    Restore(backups);
                    return Result.Nothing($"config.yaml did not load back as expected ({problem}); "
                        + "both files were restored from their backups");
                }

                written.Add(configYamlPath);
            }

            return new Result(written, backups, null);
        }
        catch (Exception ex)
        {
            // Never fatal. The migration itself succeeded and has been verified; the operator can
            // always place the files by hand, and is told exactly what to put in them.
            Restore(backups);
            return Result.Nothing(ex.Message);
        }
    }

    /// <summary>
    /// Copies a file aside before it is changed, refusing rather than overwriting an existing
    /// backup — a second run must not replace the only copy of the original with a copy of the
    /// first run's output.
    /// </summary>
    private static void Backup(string path, DateTime now, List<string> backups)
    {
        var backup = BackupPathFor(path, now);
        File.Copy(path, backup, overwrite: false);
        FileSecurityUtil.SetOwnerOnly(backup);
        backups.Add(backup);
    }

    /// <summary>Puts every backed-up file back, best effort.</summary>
    private static void Restore(List<string> backups)
    {
        foreach (var backup in backups)
        {
            try
            {
                var original = backup[..backup.LastIndexOf(".mariadb-", StringComparison.Ordinal)];
                File.Copy(backup, original, overwrite: true);
                FileSecurityUtil.SetOwnerOnly(original);
            }
            catch
            {
                // Reported by the caller as a failure to write; nothing more can be done here.
            }
        }
    }

    /// <summary>
    /// Loads a spliced config.yaml back and checks the DB section says what it was meant to.
    /// </summary>
    /// <param name="path">The file to check.</param>
    /// <param name="expected">What it should now carry.</param>
    /// <returns>A description of the mismatch, or null when it loaded correctly.</returns>
    private static string? Verify(string path, Shared.Models.Config.DbConfig expected)
    {
        var loaded = YamlConfigLoader.Load(path);

        if (loaded.DB.App.Database != expected.App.Database
            || loaded.DB.App.Username != expected.App.Username
            || loaded.DB.App.Password != expected.App.Password
            || loaded.DB.App.Port != expected.App.Port)
        {
            return "the App section does not match";
        }

        if (loaded.DB.Audit.Database != expected.Audit.Database
            || loaded.DB.Audit.Username != expected.Audit.Username
            || loaded.DB.Audit.Password != expected.Audit.Password
            || loaded.DB.Audit.Port != expected.Audit.Port)
        {
            return "the Audit section does not match";
        }

        return null;
    }

    /// <summary>
    /// Renders the configuration as the node will read it, for the case where it cannot be
    /// written and an operator has to place it by hand.
    /// </summary>
    /// <remarks>
    /// Produced by the same serializer the loader pairs with, rather than assembled from print
    /// statements, so the shape cannot drift from what the deserializer expects.
    /// </remarks>
    /// <param name="options">The resolved options.</param>
    /// <param name="appPassword">The generated application role password.</param>
    /// <param name="auditPassword">The generated audit role password.</param>
    /// <returns>The YAML text of a complete db.yaml.</returns>
    public static string Render(MigrationOptions options, string appPassword, string auditPassword)
    {
        var temporary = Path.Combine(Path.GetTempPath(), $"modularca-db-{Guid.NewGuid():N}.yaml");
        try
        {
            YamlDbConfigLoader.Write(temporary, new YamlDbConfigLoader.DbYamlConfig
            {
                App = Instance(options, options.TargetAppDatabase, options.TargetAppRole, appPassword),
                Audit = Instance(options, options.TargetAuditDatabase, options.TargetAuditRole, auditPassword),
            });
            return File.ReadAllText(temporary);
        }
        finally
        {
            try { File.Delete(temporary); } catch { /* best effort */ }
        }
    }

    private static YamlDbConfigLoader.DbInstanceConfig Instance(
        MigrationOptions options, string database, string username, string password) => new()
        {
            Host = options.TargetHost,
            Port = options.TargetPort,
            Database = database,
            Username = username,
            Password = password,
            // The mode the migration itself connected with, so what is written is known to work
            // against this server rather than assumed.
            SslMode = options.TargetSslMode,
        };
}
