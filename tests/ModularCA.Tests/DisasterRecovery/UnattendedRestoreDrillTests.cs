using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Database;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;
using Xunit.Abstractions;

namespace ModularCA.Tests.DisasterRecovery;

/// <summary>
/// The restore as an orchestrator runs it, with nobody at the instance: the built node, run as a
/// process, against one installed host. It reads an archive's manifest before anything is
/// stopped, and restores with <c>--unattended</c> from an archive it may only read, with standard
/// input closed. Each exit status is driven by a real case on each side of the point where a
/// restore starts to change things, and after each the host is looked at: what the status says
/// was not changed is compared with what was there before.
/// </summary>
/// <remarks>
/// Opt-in through <c>MODULARCA_TEST_PG</c> and in need of <c>pg_dump</c> and <c>pg_restore</c>,
/// as <see cref="RestoreDrillTests"/>, and run with the drills, after everything else. The node is
/// never started here: a restore runs with the node stopped, and the two other drills start a
/// node on what an unattended restore left.
/// </remarks>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(RestoreDrillCollection.Unattended)]
public sealed class UnattendedRestoreDrillTests(ITestOutputHelper output)
{
    private const string ServerVariable = "MODULARCA_TEST_PG";
    private const string AppMarker = "unattended-drill-marker";
    private const string FutureMigration = "99991231235959_FromTheFuture";

    /// <summary>The drill.</summary>
    [RequiresPostgresClientToolsTheory(ServerVariable)]
    [InlineData("an orchestrator")]
    public async Task A_restore_with_nobody_at_the_instance_says_whether_anything_was_changed(string runBy)
    {
        _ = runBy;
        await using var server = await DrillServer.CreateAsync(Environment.GetEnvironmentVariable(ServerVariable)!);
        var work = Path.Combine(Path.GetTempPath(), $"modularca-drill-{Guid.NewGuid():N}"[..40]);
        Directory.CreateDirectory(work);
        var mount = Path.Combine(work, "mount");
        try
        {
            // One host, installed unattended and backed up. Its processes get a temporary
            // directory of their own, so what a command staged and left can be seen.
            var host = DrillHost.Create(Path.Combine(work, "host"), server, output);
            host.Incarnation = "unattended-drill";
            host.TempDirectory = Path.Combine(work, "tmp");
            Directory.CreateDirectory(host.TempDirectory);
            host.WriteInstallFiles(server.NewLayout(), FreePort(), FreePort());
            await host.RunAsync("install", ["--bootstrap"]);
            await host.RunAsync("backup", ["--backup"]);
            var db = host.Databases();
            var instanceId = await TextAsync(db.App, "SELECT \"SigningCaSpkiSha256\" FROM \"Keystores\" WHERE \"SigningCaSpkiSha256\" IS NOT NULL ORDER BY \"Id\" LIMIT 1");
            Assert.Matches("^[0-9a-f]{64}$", instanceId);
            // No node has started on this install, so no identifier is stored yet: the archive
            // below names the instance by the derived fingerprint, as an archive of a build
            // before the identifier was stored does.
            Assert.Equal(0, await CountAsync(db.App, "SELECT count(*) FROM \"Settings\" WHERE \"Key\" = 'Instance_Id'"));
            var backups = Path.Combine(host.Directory, "backups");
            var archive = NewestArchive(backups);

            // What the runner mounts read-only beside the one-off container: the archive, under a
            // name of the runner's own, and key files as secrets.
            Directory.CreateDirectory(mount);
            var mounted = Path.Combine(mount, "archive");
            File.Copy(archive, mounted);
            var keyFile = Path.Combine(mount, "backup-key");
            File.Copy(Path.Combine(host.ConfigDirectory, "backup.key"), keyFile);
            var wrongKeyFile = Path.Combine(mount, "wrong-key");
            File.WriteAllBytes(wrongKeyFile, RandomNumberGenerator.GetBytes(BackupKeyManager.KeySize));
            var notAnArchive = Path.Combine(mount, "notes.txt");
            File.WriteAllText(notAnArchive, string.Concat(Enumerable.Repeat("This is not a backup archive. ", 40)));
            var tampered = Path.Combine(mount, "tampered.zip");
            File.WriteAllBytes(tampered, WithDamagedKeystores(Decrypt(archive, File.ReadAllBytes(keyFile))));

            // An archive a newer build took: the application database holds a migration this
            // build does not have while it is backed up.
            await ExecuteAsync(db.App, $"INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ('{FutureMigration}', '99.0.0')");
            await host.RunAsync("backup of a newer schema", ["--backup"]);
            await ExecuteAsync(db.App, $"DELETE FROM \"__EFMigrationsHistory\" WHERE \"MigrationId\" = '{FutureMigration}'");
            var newer = Path.Combine(mount, "from-a-newer-build");
            File.Move(NewestArchive(backups), newer);
            MakeReadOnly(mount);
            var mountBefore = Listing(mount);

            // ---- the manifest: one line of JSON, nothing changed, no database -------------------
            var logsBefore = Listing(Path.Combine(host.Directory, "logs"));
            var hostBefore = HostState(host);
            var manifest = await host.ExecuteAsync("manifest", ["--backup-manifest", mounted, "--key-file", keyFile]);
            Assert.True(manifest.ExitCode == 0, manifest.Text);
            Assert.Empty(manifest.Stderr);
            var json = JsonDocument.Parse(Assert.Single(manifest.Stdout)).RootElement;
            Assert.Equal(instanceId, json.GetProperty("instanceId").GetString());
            Assert.Equal(BackupManifestCommand.ProductVersion(), json.GetProperty("productVersion").GetString());
            Assert.StartsWith("tables:", json.GetProperty("schemaVersion").GetString());
            Assert.InRange(json.GetProperty("createdAtUtc").GetDateTime().ToUniversalTime(), DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddMinutes(1));
            Assert.Equal("RandomKey", json.GetProperty("encryption").GetString());
            Assert.True(json.GetProperty("hasAuditDatabase").GetBoolean());
            Assert.False(json.GetProperty("newerThanThisBuild").GetBoolean());
            Assert.Contains(json.GetProperty("latestMigration").GetString()!, BackupManifestCommand.KnownMigrations(audit: false));
            Assert.DoesNotContain("user", manifest.Stdout[0], StringComparison.OrdinalIgnoreCase);

            // Without a named key file it reads this host's own, and says the same.
            var manifestWithHostKey = await host.ExecuteAsync("manifest with the host's key", ["--backup-manifest", archive]);
            Assert.True(manifestWithHostKey.ExitCode == 0, manifestWithHostKey.Text);
            Assert.Equal(instanceId, JsonDocument.Parse(Assert.Single(manifestWithHostKey.Stdout)).RootElement.GetProperty("instanceId").GetString());

            var manifestOfNewer = await host.ExecuteAsync("manifest of a newer archive", ["--backup-manifest", newer, "--key-file", keyFile]);
            Assert.True(manifestOfNewer.ExitCode == 0, manifestOfNewer.Text);
            var newerJson = JsonDocument.Parse(Assert.Single(manifestOfNewer.Stdout)).RootElement;
            Assert.True(newerJson.GetProperty("newerThanThisBuild").GetBoolean());
            Assert.Equal(FutureMigration, newerJson.GetProperty("latestMigration").GetString());

            foreach (var (step, args) in new (string, string[])[]
                     {
                         ("manifest with a wrong key", ["--backup-manifest", mounted, "--key-file", wrongKeyFile]),
                         ("manifest of a file that is not an archive", ["--backup-manifest", notAnArchive, "--key-file", keyFile]),
                         ("manifest of a file that is not there", ["--backup-manifest", Path.Combine(mount, "absent")]),
                     })
            {
                var refused = await host.ExecuteAsync(step, args);
                Assert.True(refused.ExitCode == RestoreExit.Refused, $"{step}: {refused.Text}");
                Assert.Empty(refused.Stdout);
                Assert.NotEmpty(refused.Stderr);
            }
            Assert.Equal(mountBefore, Listing(mount));
            Assert.Empty(Staged(host));
            // It wrote nothing: not a log line, not a file in config/ or keystores/.
            Assert.Equal(logsBefore, Listing(Path.Combine(host.Directory, "logs")));
            Assert.Equal(hostBefore, HostState(host));

            // ---- refused: nothing was changed --------------------------------------------------
            // The host moves on after the backup: a change in the application database a restore
            // would undo, and an audit record a restore must keep.
            await MarkAsync(db.App);
            await AppendAuditMarkerAsync(db.Audit, "UnattendedDrillMarker");
            var stateBefore = HostState(host);
            var blocker = "CREATE VIEW drill_blocker AS SELECT \"Name\" FROM \"FeatureFlags\"";

            async Task RefusedAsync(string step, string[] args, int status, string marker, string? says = null, string? stdin = null)
            {
                var run = await host.ExecuteAsync(step, args, stdin);
                Assert.True(run.ExitCode == status, $"{step} exited {run.ExitCode}, not {status}:{Environment.NewLine}{run.Text}");
                Assert.StartsWith(marker, run.LastLine);
                Assert.EndsWith("Nothing was changed.", run.LastLine);
                if (says != null) Assert.Contains(says, run.LastLine);
                Assert.True(await MarkedAsync(db.App), $"{step}: the application database was changed");
                Assert.Equal(1, await CountAsync(db.Audit, "SELECT count(*) FROM \"AuditLogs\" WHERE \"ActionType\" = 'UnattendedDrillMarker'"));
                Assert.Equal(stateBefore, HostState(host));
                Assert.Equal(mountBefore, Listing(mount));
                Assert.Empty(Staged(host));
            }

            await RefusedAsync("restore with no archive named", ["--restore"], RestoreExit.Refused, RestoreExit.RefusedMarker);
            await RefusedAsync("restore of a file that is not there", ["--restore", Path.Combine(mount, "absent"), "--unattended"], RestoreExit.Refused, RestoreExit.RefusedMarker);
            await RefusedAsync("restore of a file that is not an archive", ["--restore", notAnArchive, "--unattended", "--key-file", keyFile], RestoreExit.Refused, RestoreExit.RefusedMarker);
            await RefusedAsync("restore with a wrong key", ["--restore", mounted, "--unattended", "--key-file", wrongKeyFile], RestoreExit.Refused, RestoreExit.RefusedMarker, "does not open with this key");
            await RefusedAsync("restore with the password as an argument", ["--restore", mounted, "--unattended", "--password", "on the command line"], RestoreExit.Refused, RestoreExit.RefusedMarker, "--password-file");
            await RefusedAsync("restore of an archive from a newer build", ["--restore", newer, "--unattended", "--key-file", keyFile], RestoreExit.Refused, RestoreExit.RefusedMarker, "newer than this build");
            // Not told it is unattended, and nobody answers: it is refused, and does not wait.
            await RefusedAsync("restore that nobody confirms", ["--restore", mounted, "--key-file", keyFile], RestoreExit.Refused, RestoreExit.RefusedMarker, "--unattended");
            await RefusedAsync("restore that somebody declines", ["--restore", mounted, "--key-file", keyFile], RestoreExit.Refused, RestoreExit.RefusedMarker, "not confirmed", stdin: "no\n");

            // The database server does not answer: another status, and still nothing changed.
            var dbYamlPath = Path.Combine(host.ConfigDirectory, "db.yaml");
            var dbYaml = File.ReadAllText(dbYamlPath);
            File.WriteAllText(dbYamlPath, Regex.Replace(dbYaml, @"(?m)^(\s*Port:\s*)\d+", "${1}" + FreePort()));
            try
            {
                var unreachable = await host.ExecuteAsync("restore while the database is unreachable", ["--restore", mounted, "--unattended", "--key-file", keyFile]);
                Assert.True(unreachable.ExitCode == RestoreExit.Unreachable, unreachable.Text);
                Assert.StartsWith(RestoreExit.UnreachableMarker, unreachable.LastLine);
                Assert.EndsWith("try again. Nothing was changed.", unreachable.LastLine);
            }
            finally
            {
                File.WriteAllText(dbYamlPath, dbYaml);
            }
            Assert.Equal(stateBefore, HostState(host));
            Assert.True(await MarkedAsync(db.App));

            // The restore of the database itself fails: a view of the host's own stands on a
            // table the restore replaces. It is one transaction, so the database is as it was,
            // and the status still says that nothing was changed. This is past the confirmation
            // and the pre-restore snapshot, which is written to backups/ and is not a change.
            await ExecuteAsync(db.App, blocker);
            var rolledBack = await host.ExecuteAsync("restore that the database rolls back", ["--restore", mounted, "--unattended", "--key-file", keyFile]);
            Assert.True(rolledBack.ExitCode == RestoreExit.Refused, rolledBack.Text);
            Assert.StartsWith(RestoreExit.RefusedMarker, rolledBack.LastLine);
            Assert.Contains("rolled back", rolledBack.LastLine);
            Assert.EndsWith("Nothing was changed.", rolledBack.LastLine);
            Assert.True(await MarkedAsync(db.App), "a rolled-back restore changed the application database");
            Assert.Equal(1, await CountAsync(db.App, "SELECT count(*) FROM pg_views WHERE viewname = 'drill_blocker'"));
            Assert.Equal(stateBefore, HostState(host));
            Assert.Single(Directory.GetFiles(backups, "pre-restore-*.zip"));
            Assert.Empty(Staged(host));

            // ---- failed after something was changed ----------------------------------------------
            // With --restore-audit the audit database goes first and commits; then the application
            // database is rolled back as above. Something was changed, and the status says so.
            var auditThenFailure = await host.ExecuteAsync("restore that fails after the audit database was replaced",
                ["--restore", mounted, "--unattended", "--restore-audit", "--key-file", keyFile]);
            Assert.True(auditThenFailure.ExitCode == RestoreExit.FailedAfterChanges, auditThenFailure.Text);
            Assert.StartsWith(RestoreExit.FailedAfterChangesMarker, auditThenFailure.LastLine);
            Assert.DoesNotContain("Nothing was changed", auditThenFailure.LastLine);
            Assert.Equal(0, await CountAsync(db.Audit, "SELECT count(*) FROM \"AuditLogs\" WHERE \"ActionType\" = 'UnattendedDrillMarker'"));
            Assert.True(await MarkedAsync(db.App), "the application database was rolled back, and must be as it was");
            await ExecuteAsync(db.App, "DROP VIEW drill_blocker");

            // The database is restored, then the signer refuses a keystore from the archive: the
            // application database now holds the archive's contents.
            var keystoreRefused = await host.ExecuteAsync("restore whose keystore the signer refuses", ["--restore", tampered, "--unattended"]);
            Assert.True(keystoreRefused.ExitCode == RestoreExit.FailedAfterChanges, keystoreRefused.Text);
            Assert.StartsWith(RestoreExit.FailedAfterChangesMarker, keystoreRefused.LastLine);
            Assert.DoesNotContain("Nothing was changed", keystoreRefused.LastLine);
            Assert.False(await MarkedAsync(db.App), "the application database was replaced before the keystore was refused");
            Assert.Empty(Staged(host));

            // ---- done -----------------------------------------------------------------------------
            // Unattended, standard input closed, the archive readable only, the key from a file.
            // The audit database is kept: a record written after the backup survives the restore.
            await MarkAsync(db.App);
            await AppendAuditMarkerAsync(db.Audit, "UnattendedDrillKept");
            var done = await host.ExecuteAsync("unattended restore from a read-only mount", ["--restore", mounted, "--unattended", "--key-file", keyFile]);
            Assert.True(done.ExitCode == RestoreExit.Done, done.Text);
            Assert.StartsWith(RestoreExit.DoneMarker, done.LastLine);
            Assert.Contains("the audit database was kept", done.LastLine);
            Assert.DoesNotContain("Type [RESTORE]", done.Text);
            Assert.DoesNotContain("Password:", done.Text);
            Assert.False(await MarkedAsync(db.App), "the restore did not replace the application database");
            Assert.Equal(1, await CountAsync(db.Audit, "SELECT count(*) FROM \"AuditLogs\" WHERE \"ActionType\" = 'UnattendedDrillKept'"));
            await using (var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql(PostgresConnection.Build(db.Audit)).Options))
                Assert.Empty((await new AuditHashChainService().VerifyAsync(audit, null, limit: 100_000)).Breaks);
            Assert.Equal(instanceId, await TextAsync(db.App, "SELECT \"SigningCaSpkiSha256\" FROM \"Keystores\" WHERE \"SigningCaSpkiSha256\" IS NOT NULL ORDER BY \"Id\" LIMIT 1"));
            // The restore itself stores no identifier: that is the first start's, which will
            // store the fingerprint the archive's manifest already names.
            Assert.Equal(0, await CountAsync(db.App, "SELECT count(*) FROM \"Settings\" WHERE \"Key\" = 'Instance_Id'"));
            // Nothing was written beside the archive, and nothing staged was left behind.
            Assert.Equal(mountBefore, Listing(mount));
            Assert.Empty(Staged(host));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            try
            {
                if (Directory.Exists(mount)) MakeWritable(mount);
                Directory.Delete(work, recursive: true);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static string NewestArchive(string backups) =>
        Directory.GetFiles(backups, "modularca-backup-*.enc").OrderBy(File.GetLastWriteTimeUtc).Last();

    /// <summary>The ZIP inside an archive a backup encrypted under a random key.</summary>
    private static byte[] Decrypt(string archive, byte[] key)
    {
        var file = File.ReadAllBytes(archive);
        Assert.True(file.AsSpan().StartsWith(BackupKeyManager.MagicBytes));
        Assert.Equal((byte)BackupEncryptionMode.RandomKey, file[5]);
        var plaintext = new byte[file.Length - 66];
        using var aes = new AesGcm(key, BackupKeyManager.TagSize);
        aes.Decrypt(file.AsSpan(38, BackupKeyManager.NonceSize), file.AsSpan(66), file.AsSpan(50, BackupKeyManager.TagSize), plaintext);
        return plaintext;
    }

    /// <summary>The same archive, as a plain ZIP, with every keystore file damaged in the middle.</summary>
    private static byte[] WithDamagedKeystores(byte[] zip)
    {
        using var result = new MemoryStream();
        var damaged = 0;
        using (var source = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read))
        using (var target = new ZipArchive(result, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in source.Entries)
            {
                using var content = new MemoryStream();
                using (var from = entry.Open())
                    from.CopyTo(content);
                var bytes = content.ToArray();
                if (entry.FullName.Replace('\\', '/').StartsWith("keystores/", StringComparison.Ordinal) && bytes.Length > 128)
                {
                    for (var i = bytes.Length / 2; i < bytes.Length / 2 + 48; i++)
                        bytes[i] ^= 0x5A;
                    damaged++;
                }
                using var to = target.CreateEntry(entry.FullName).Open();
                to.Write(bytes);
            }
        }
        Assert.True(damaged > 0, "the archive holds no keystore file to damage");
        return result.ToArray();
    }

    /// <summary>Every file of the host's config/ and keystores/ with a digest of its contents: what a refused restore must leave alone.</summary>
    private static List<string> HostState(DrillHost host)
    {
        var state = new List<string>();
        foreach (var directory in new[] { host.ConfigDirectory, Path.Combine(host.Directory, "keystores") })
        {
            if (!Directory.Exists(directory)) continue;
            foreach (var file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories))
                state.Add($"{Path.GetRelativePath(host.Directory, file)}|{Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)))}");
        }
        state.Sort(StringComparer.Ordinal);
        return state;
    }

    /// <summary>The entries of a directory with the length and last write time of each file; none when it is not there.</summary>
    private static List<string> Listing(string directory) =>
        !Directory.Exists(directory) ? [] : Directory.GetFileSystemEntries(directory, "*", SearchOption.AllDirectories)
            .Select(e => $"{Path.GetRelativePath(directory, e)}|{(File.Exists(e) ? $"{new FileInfo(e).Length}|{File.GetLastWriteTimeUtc(e):O}" : "dir")}")
            .Order(StringComparer.Ordinal).ToList();

    /// <summary>
    /// What a command of the product left in the temporary directory the host's processes were
    /// given: its staging directories and files are all named <c>modularca-...</c>. The runtime's
    /// own files there are not the product's.
    /// </summary>
    private static List<string> Staged(DrillHost host) =>
        Directory.GetFileSystemEntries(host.TempDirectory!, "modularca-*").Select(Path.GetFileName).ToList()!;

    /// <summary>Makes the directory and its files read-only, as far as the platform lets this account do it to itself.</summary>
    private static void MakeReadOnly(string directory)
    {
        foreach (var file in Directory.GetFiles(directory))
        {
            File.SetAttributes(file, File.GetAttributes(file) | FileAttributes.ReadOnly);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(file, UnixFileMode.UserRead);
        }
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserExecute);
    }

    private static void MakeWritable(string directory)
    {
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        foreach (var file in Directory.GetFiles(directory))
            File.SetAttributes(file, FileAttributes.Normal);
    }

    private static Task MarkAsync(DbInstance app) =>
        ExecuteAsync(app, $"UPDATE \"FeatureFlags\" SET \"Description\" = '{AppMarker}' WHERE \"Name\" = 'CRL.Enabled'");

    private static async Task<bool> MarkedAsync(DbInstance app) =>
        await CountAsync(app, $"SELECT count(*) FROM \"FeatureFlags\" WHERE \"Description\" = '{AppMarker}'") == 1;

    private static async Task AppendAuditMarkerAsync(DbInstance auditDatabase, string action)
    {
        await using var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql(PostgresConnection.Build(auditDatabase)).Options);
        await new AuditHashChainService().AppendAsync(audit, new ModularCA.Shared.Entities.AuditLogEntity
        {
            ActionType = action,
            ActorUsername = "restore-drill",
            TargetEntityType = "Drill",
            Success = true,
        });
    }

    private static async Task<NpgsqlConnection> OpenAsync(DbInstance instance)
    {
        var conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance)) { Pooling = false }.ConnectionString);
        await conn.OpenAsync();
        return conn;
    }

    private static async Task ExecuteAsync(DbInstance instance, string sql)
    {
        await using var conn = await OpenAsync(instance);
        await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
    }

    private static async Task<long> CountAsync(DbInstance instance, string sql)
    {
        await using var conn = await OpenAsync(instance);
        return Convert.ToInt64(await new NpgsqlCommand(sql, conn).ExecuteScalarAsync());
    }

    private static async Task<string> TextAsync(DbInstance instance, string sql)
    {
        await using var conn = await OpenAsync(instance);
        return (string)(await new NpgsqlCommand(sql, conn).ExecuteScalarAsync())!;
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }
}
