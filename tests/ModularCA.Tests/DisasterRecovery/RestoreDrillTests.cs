using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Database;
using Npgsql;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using ModularCA.Tests.TestUtils;
using Xunit;
using Xunit.Abstractions;

namespace ModularCA.Tests.DisasterRecovery;

/// <summary>How the host a backup is restored onto was prepared.</summary>
public enum NewHost
{
    /// <summary>Two roles and two empty databases made by hand, and a <c>db.yaml</c> naming them.</summary>
    EmptyDatabases,

    /// <summary>A complete new install with its own root, which the restore replaces.</summary>
    FreshInstall,
}

/// <summary>
/// The restore drill: the built node, run as an operator runs it. One host is installed
/// unattended, started and backed up; the host and its databases are then destroyed, and the
/// archive is restored onto a second host from nothing but what an operator keeps off the first
/// (the archive, the backup key and <c>keystore.yaml</c>). The second host must start, serve the
/// same root, sign with its key and carry the audit trail.
/// </summary>
/// <remarks>
/// Opt-in through <c>MODULARCA_TEST_PG</c>, as the other PostgreSQL harness tests, and it needs
/// <c>pg_dump</c> and <c>pg_restore</c>. Build ModularCA.API first: the drill runs a copy of its
/// output. The unattended install needs a superuser in <c>setup-database.yaml</c>; the drill
/// makes one for itself and drops it, so the harness's own credentials never reach a file or
/// another process.
/// <para>
/// It runs after everything else (<see cref="RestoreDrillCollection"/>): under the load of the
/// other test collections on the same PostgreSQL server, the unattended install's commands ran
/// past Npgsql's command timeout in every full-suite run, though the drill passed on its own.
/// The two new hosts are drilled by a class each, <see cref="RestoreDrillOntoEmptyDatabasesTests"/>
/// and <see cref="RestoreDrillOntoFreshInstallTests"/>, so the two drills run beside each other;
/// they share nothing but the server (each has its own roles, databases, directories and ports).
/// </para>
/// </remarks>
public abstract class RestoreDrillTests(ITestOutputHelper output)
{
    /// <summary>The environment variable naming the test server.</summary>
    protected const string ServerVariable = "MODULARCA_TEST_PG";
    private const string RootLabel = "drill-root";

    /// <summary>The drill, onto a new host prepared as <paramref name="newHost"/> says.</summary>
    protected async Task DrillAsync(NewHost newHost)
    {
        await using var server = await DrillServer.CreateAsync(Environment.GetEnvironmentVariable(ServerVariable)!);
        var (httpsPort, httpPort) = (FreePort(), FreePort());
        var work = Path.Combine(Path.GetTempPath(), $"modularca-drill-{Guid.NewGuid():N}"[..40]);
        Directory.CreateDirectory(work);
        DrillHost? old = null, restored = null;
        byte[]? rootDer = null;
        try
        {
            // The first host: installed unattended, started, used, stopped, backed up.
            var oldLayout = server.NewLayout();
            old = DrillHost.Create(Path.Combine(work, "old"), server, output);
            // What an orchestrator injects: each host of the drill is its own incarnation.
            old.Incarnation = "drill-first-host";
            old.WriteInstallFiles(oldLayout, httpsPort, httpPort);
            await old.RunAsync("install", ["--bootstrap"]);
            await old.StartAsync(httpPort);
            var root = await old.GetAsync(httpPort, $"/ca/{RootLabel}");
            rootDer = root;
            var crlBefore = ParseCrl(await old.GetUntilAsync(httpPort, $"/crl/{RootLabel}", TimeSpan.FromMinutes(3)));
            var rootCertificate = new X509CertificateParser().ReadCertificate(root);
            var leafBefore = await old.WithNodeLogOnFailureAsync(ServedUnderAsync(httpsPort, rootCertificate));
            await old.StopAsync();

            var dbYaml = old.Databases();
            // The first start stored the incarnation it was given and had nothing to report.
            Assert.Equal(1, await CountAsync(dbYaml.App, "SELECT count(*) FROM \"InstanceIncarnation\" WHERE \"Source\" = 'injected' AND \"RecordedBy\" = 'startup'"));
            Assert.Equal(0, await CountAsync(dbYaml.App, "SELECT count(*) FROM \"InstanceContinuityEvents\""));
            // The first start moved the instance-wide settings to the database: they are marked as
            // moved there, and the file the install wrote is down to this host's settings, with
            // the original kept beside it.
            Assert.Equal(1, await CountAsync(dbYaml.App, "SELECT count(*) FROM \"SettingsState\" WHERE \"ImportedAt\" IS NOT NULL"));
            Assert.StartsWith(ConfigYamlWriter.HostOnlyHeader.ReplaceLineEndings("\n"),
                File.ReadAllText(Path.Combine(old.ConfigDirectory, "config.yaml")).ReplaceLineEndings("\n"));
            var kept = Assert.Single(Directory.GetFiles(old.ConfigDirectory, "config.yaml.pre-settings-*.bak"));
            // The JWT secret went with them, wrapped by the signer: it is in the store, and in
            // neither the file nor the copy of the file as it was.
            Assert.Equal(1, await CountAsync(dbYaml.App, "SELECT count(*) FROM \"SettingsSecrets\" WHERE \"Key\" = 'JWT_Secret' AND \"Value\" IS NOT NULL"));
            Assert.DoesNotContain("JWT:", File.ReadAllText(Path.Combine(old.ConfigDirectory, "config.yaml")));
            // The copy keeps the rest of that section; the secret itself is gone from it.
            Assert.DoesNotMatch(@"(?m)^\s+Secret:\s*\S", File.ReadAllText(kept));
            // The first start stored the instance's identifier, with its data and in no file: the
            // fingerprint of the system signing CA as it was then.
            var pin = await TextAsync(dbYaml.App, PinSql) ?? string.Empty;
            Assert.Matches("^[0-9a-f]{64}$", pin);
            Assert.Equal($"\"{pin}\"", await TextAsync(dbYaml.App, InstanceIdSql));
            Assert.Contains("[INSTANCE] Identifier stored: " + pin, old.NodeLog);
            Assert.DoesNotContain(pin, File.ReadAllText(Path.Combine(old.ConfigDirectory, "config.yaml")));
            // From here on the stored identifier and the fingerprint differ, as they do once the
            // system signing CA has been re-keyed. The drill cannot re-key it (changing the pin
            // locks the keystore), so it changes the other side: what matters below is that
            // every reader and every later start takes the stored one and none derives it again.
            const string instanceId = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e";
            Assert.Equal(1, await CountAsync(dbYaml.App,
                $"WITH changed AS (UPDATE \"Settings\" SET \"ValueJson\" = '\"{instanceId}\"' WHERE \"Key\" = 'Instance_Id' RETURNING 1) SELECT count(*) FROM changed"));
            var unwrapsBefore = await CountAsync(dbYaml.App, "SELECT count(*) FROM \"SignerAudit\" WHERE \"Operation\" = 'UnwrapSecret' AND \"Purpose\" = 'Configuration' AND \"Outcome\" = 'allowed'");
            var certificates = await CountAsync(dbYaml.App, "SELECT count(*) FROM \"Certificates\"");
            var auditRecords = await CountAsync(dbYaml.Audit, "SELECT count(*) FROM \"AuditLogs\"");
            var keyRing = Directory.GetFiles(Path.Combine(old.ConfigDirectory, "dp-keys")).Select(Path.GetFileName).Order().ToList();
            Assert.NotEmpty(keyRing);

            var backup = await old.RunAsync("backup", ["--backup"]);
            // The node's scheduler may have taken a backup of its own while it ran; the drill restores the last one.
            var archive = Directory.GetFiles(Path.Combine(old.Directory, "backups"), "modularca-backup-*.enc")
                .OrderBy(File.GetLastWriteTimeUtc).Last();

            // The archive names the instance by its stored identifier, not by the fingerprint.
            var manifest = await old.ExecuteAsync("manifest", ["--backup-manifest", archive, "--key-file", Path.Combine(old.ConfigDirectory, "backup.key")]);
            Assert.True(manifest.ExitCode == 0, manifest.Text);
            Assert.Equal(instanceId, System.Text.Json.JsonDocument.Parse(Assert.Single(manifest.Stdout)).RootElement.GetProperty("instanceId").GetString());

            // What an operator keeps off the host, and nothing else.
            var kit = Path.Combine(work, "kit");
            Directory.CreateDirectory(kit);
            File.Copy(archive, Path.Combine(kit, Path.GetFileName(archive)));
            File.Copy(Path.Combine(old.ConfigDirectory, "backup.key"), Path.Combine(kit, "backup.key"));
            File.Copy(Path.Combine(old.ConfigDirectory, "keystore.yaml"), Path.Combine(kit, "keystore.yaml"));

            // The disaster: the host and both databases are gone.
            Directory.Delete(old.Directory, recursive: true);
            await server.DropAsync(oldLayout);

            // The second host.
            var newLayout = server.NewLayout();
            restored = DrillHost.Create(Path.Combine(work, "new"), server, output);
            restored.Incarnation = "drill-second-host";
            if (newHost == NewHost.FreshInstall)
            {
                restored.WriteInstallFiles(newLayout, httpsPort, httpPort);
                await restored.RunAsync("install on the new host", ["--bootstrap"]);
                await restored.StartAsync(httpPort);
                Assert.NotEqual(root, await restored.GetAsync(httpPort, $"/ca/{RootLabel}"));
                await restored.StopAsync();
                // Another install is another instance: it stored an identifier of its own.
                var others = await TextAsync(restored.Databases().App, InstanceIdSql);
                Assert.Matches("^\"[0-9a-f]{64}\"$", others);
                Assert.NotEqual($"\"{pin}\"", others);
                Assert.NotEqual($"\"{instanceId}\"", others);
            }
            else
            {
                await server.CreateEmptyDatabasesAsync(newLayout);
                restored.WriteDbYaml(newLayout);
            }

            Directory.CreateDirectory(Path.Combine(restored.Directory, "backups"));
            var archiveOnNewHost = Path.Combine(restored.Directory, "backups", Path.GetFileName(archive));
            File.Copy(Path.Combine(kit, Path.GetFileName(archive)), archiveOnNewHost);
            File.Copy(Path.Combine(kit, "backup.key"), Path.Combine(restored.ConfigDirectory, "backup.key"), overwrite: true);
            File.Copy(Path.Combine(kit, "keystore.yaml"), Path.Combine(restored.ConfigDirectory, "keystore.yaml"), overwrite: true);

            // The new host's audit database is empty, so it takes the archive's audit trail. Nobody
            // is at the terminal: --unattended, standard input closed, and nothing is asked.
            var restore = await restored.RunAsync("restore", ["--restore", archiveOnNewHost, "--restore-audit", "--unattended"]);

            var newDbYaml = restored.Databases();
            Assert.Equal(certificates, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"Certificates\""));
            Assert.True(await CountAsync(newDbYaml.Audit, "SELECT count(*) FROM \"AuditLogs\"") >= auditRecords);
            // The archive's database last saw the first host. The restore stored this host's
            // incarnation in it, so the start below is not taken for a rollback.
            Assert.Equal(1, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"InstanceIncarnation\" WHERE \"Source\" = 'injected' AND \"RecordedBy\" = 'restore'"));
            // The restore brought the archive's identifier with the database: this is the same
            // instance on another host, whatever identifier that host's database held before.
            Assert.Equal($"\"{instanceId}\"", await TextAsync(newDbYaml.App, InstanceIdSql));
            Assert.Equal(pin, await TextAsync(newDbYaml.App, PinSql));

            var start = await restored.StartAsync(httpPort);

            // The start after the restore found an identifier stored and left it: it did not
            // put the fingerprint, which differs, in its place.
            Assert.Equal($"\"{instanceId}\"", await TextAsync(newDbYaml.App, InstanceIdSql));
            Assert.Equal(1, await CountAsync(newDbYaml.App, "SELECT \"Version\" FROM \"Settings\" WHERE \"Key\" = 'Instance_Id'"));
            Assert.DoesNotContain("[INSTANCE] Identifier stored: " + pin, restored.NodeLog);

            // The same root, and a certificate the restored key signed after the restore.
            Assert.Equal(root, await restored.GetAsync(httpPort, $"/ca/{RootLabel}"));
            // The web certificate's key is in no backup, so the one served now is new.
            var leafAfter = await restored.WithNodeLogOnFailureAsync(ServedUnderAsync(httpsPort, rootCertificate));
            Assert.NotEqual(leafBefore.SerialNumber, leafAfter.SerialNumber);
            Assert.Equal(leafBefore.SubjectDN.ToString(), leafAfter.SubjectDN.ToString());
            Assert.Equal(SubjectAltNames(leafBefore), SubjectAltNames(leafAfter));

            // A CRL signed after the restore, numbered above every CRL the first host published.
            var crlAfter = await UntilAsync(TimeSpan.FromMinutes(3), async () =>
            {
                var crl = ParseCrl(await restored.GetAsync(httpPort, $"/crl/{RootLabel}"));
                return CrlNumber(crl) > CrlNumber(crlBefore) ? crl : null;
            }, "the restored node published no CRL numbered above the last one the first host published");
            crlAfter.Verify(rootCertificate.GetPublicKey());

            // The restored host had no JWT secret in any file. It read the stored one back through
            // the restored keystore; it did not fall back to a temporary one.
            Assert.DoesNotContain("JWT:", File.ReadAllText(Path.Combine(restored.ConfigDirectory, "config.yaml")));
            Assert.True(await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"SignerAudit\" WHERE \"Operation\" = 'UnwrapSecret' AND \"Purpose\" = 'Configuration' AND \"Outcome\" = 'allowed'") > unwrapsBefore);
            Assert.DoesNotContain("using a temporary one", restored.NodeLog);

            // The configuration secrets were unwrapped, and the audit trail is whole.
            Assert.False(Directory.Exists(Path.Combine(restored.ConfigDirectory, "restore-pending")));
            var restoredKeyRing = Directory.GetFiles(Path.Combine(restored.ConfigDirectory, "dp-keys")).Select(Path.GetFileName).ToList();
            Assert.All(keyRing, name => Assert.Contains(name, restoredKeyRing));
            await using (var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                             .UseNpgsql(PostgresConnection.Build(newDbYaml.Audit)).Options))
            {
                var chain = await new AuditHashChainService().VerifyAsync(audit, null, limit: 100_000);
                Assert.Empty(chain.Breaks);
                Assert.False(chain.Truncated);
            }

            // The restore was not reported as a rollback: the start found the incarnation current.
            Assert.Equal(0, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"InstanceContinuityEvents\""));
            Assert.Equal(1, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"InstanceIncarnation\" WHERE \"RecordedBy\" = 'restore'"));

            // A rollback the product is not told about: the same databases come up under another
            // incarnation, as after a snapshot revert or a volume restore. The node starts and
            // serves, raises the CRL numbers again, records the event, audits it once in a chain
            // that stays whole, and stores the new incarnation. One drill is enough to show it.
            if (newHost == NewHost.EmptyDatabases)
            {
                await restored.StopAsync();
                restored.Incarnation = "drill-after-a-rollback";
                await restored.StartAsync(httpPort);

                Assert.Equal(root, await restored.GetAsync(httpPort, $"/ca/{RootLabel}"));
                Assert.Contains("[CONTINUITY] This instance is running from an earlier or copied state", restored.NodeLog);
                Assert.Equal(1, await CountAsync(newDbYaml.App,
                    "SELECT count(*) FROM \"InstanceContinuityEvents\" WHERE \"Kind\" = 'IncarnationChanged' AND \"AcknowledgedAt\" IS NULL "
                    + "AND \"CrlNumberFloor\" IS NOT NULL AND \"EdgeOfMemoryUtc\" IS NOT NULL AND \"OldTag\" <> \"NewTag\""));
                Assert.Equal(1, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"InstanceIncarnation\" WHERE \"RecordedBy\" = 'startup'"));
                Assert.Equal(1, await CountAsync(newDbYaml.Audit, "SELECT count(*) FROM \"AuditLogs\" WHERE \"ActionType\" = 'InstanceIncarnationChanged'"));
                var crlAfterRollback = await UntilAsync(TimeSpan.FromMinutes(3), async () =>
                {
                    var crl = ParseCrl(await restored.GetAsync(httpPort, $"/crl/{RootLabel}"));
                    return CrlNumber(crl) > CrlNumber(crlAfter) ? crl : null;
                }, "the node published no CRL numbered above the last one after its incarnation changed");
                crlAfterRollback.Verify(rootCertificate.GetPublicKey());
            }

            // A later restore without --restore-audit keeps the audit history this host wrote
            // after the backup: a record appended now survives it, and the chain stays whole.
            await restored.StopAsync();
            await using (var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                             .UseNpgsql(PostgresConnection.Build(newDbYaml.Audit)).Options))
            {
                await new AuditHashChainService().AppendAsync(audit, new ModularCA.Shared.Entities.AuditLogEntity
                {
                    ActionType = "RestoreDrillMarker",
                    ActorUsername = "restore-drill",
                    TargetEntityType = "Drill",
                    Success = true,
                });
            }
            await restored.RunAsync("restore keeping the audit history", ["--restore", archiveOnNewHost], stdin: "RESTORE\n");
            Assert.Equal(1, await CountAsync(newDbYaml.Audit, "SELECT count(*) FROM \"AuditLogs\" WHERE \"ActionType\" = 'RestoreDrillMarker'"));
            Assert.Equal(certificates, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"Certificates\""));
            await using (var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                             .UseNpgsql(PostgresConnection.Build(newDbYaml.Audit)).Options))
            {
                Assert.Empty((await new AuditHashChainService().VerifyAsync(audit, null, limit: 100_000)).Breaks);
            }

            // A second restore of the same archive, under the incarnation this host already has
            // and with the audit database kept (the hub's question, Discussion 017 F3). The
            // restored database holds the first host's incarnation again; the restore stores this
            // host's, and the start after it finds the timeline current and reports nothing.
            Assert.Equal(1, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"InstanceIncarnation\" WHERE \"Source\" = 'injected' AND \"RecordedBy\" = 'restore'"));
            Assert.Equal(0, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"InstanceContinuityEvents\""));
            await restored.StartAsync(httpPort);
            Assert.Equal(root, await restored.GetAsync(httpPort, $"/ca/{RootLabel}"));
            Assert.Equal(0, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"InstanceContinuityEvents\""));
            Assert.DoesNotContain("running from an earlier or copied state", restored.NodeLog);

            // A restore and a running node keep each other out. One drill is enough to show it.
            if (newHost == NewHost.FreshInstall)
                await KeepEachOtherOutAsync(restored, httpPort, archiveOnNewHost, root);

            output.WriteLine($"backup {backup.TotalSeconds:F0}s, restore {restore.TotalSeconds:F0}s, start to serving {start.TotalSeconds:F0}s");
        }
        finally
        {
            if (old is not null) await old.StopAsync();
            if (restored is not null) await restored.StopAsync();
            NpgsqlConnection.ClearAllPools();
            if (rootDer is not null) RemoveFromWindowsCaStores(rootDer);
            try { Directory.Delete(work, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// The mutual exclusion, with the real program on both sides and <paramref name="host"/>'s
    /// node running when it begins: a restore started beside the running node is refused with 3
    /// and the node is untouched and still serving; a second restore is refused beside one that
    /// is running; the commands that are neither run beside both; and a node started while a
    /// restore holds the database exits 75 when the restore outlasts its wait, and otherwise
    /// waits and starts when the restore has ended. The restore that holds the database here is
    /// a real one, waiting at its confirmation prompt, which it reaches with the lock taken.
    /// </summary>
    private static async Task KeepEachOtherOutAsync(DrillHost host, int httpPort, string archive, byte[] root)
    {
        long certificates;
        var db = host.Databases();
        var backups = Path.Combine(host.Directory, "backups");
        var snapshots = Directory.GetFiles(backups, "pre-restore-*.zip").Length;
        // What a restore replaces on the host: the settings files and the keystores.
        var config = Directory.GetFiles(host.ConfigDirectory, "*.yaml")
            .Concat(Directory.GetFiles(Path.Combine(host.Directory, "keystores"), "*.keystore"))
            .ToDictionary(f => f, f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))));
        // The node issued its web certificate since the archive was taken: counted now.
        certificates = await CountAsync(db.App, "SELECT count(*) FROM \"Certificates\"");
        const string marker = "exclusion-drill-marker";
        await ExecuteAsync(db.App, $"UPDATE \"FeatureFlags\" SET \"Description\" = '{marker}' WHERE \"Name\" = 'CRL.Enabled'");

        // ---- a restore beside the running node -----------------------------------------------
        var refused = await host.ExecuteAsync("restore while the node is running", ["--restore", archive, "--unattended"]);
        Assert.True(refused.ExitCode == RestoreExit.Refused, refused.Text);
        Assert.StartsWith(RestoreExit.RefusedMarker, refused.LastLine);
        Assert.Contains("a node is serving from this application database", refused.LastLine);
        Assert.Contains("stop the node", refused.LastLine);
        Assert.EndsWith("Nothing was changed.", refused.LastLine);
        // Nothing was changed, and nothing was even staged: no snapshot, the database and the
        // files as they were, the node serving, and its lock never disturbed.
        Assert.Equal(snapshots, Directory.GetFiles(backups, "pre-restore-*.zip").Length);
        Assert.Equal(1, await CountAsync(db.App, $"SELECT count(*) FROM \"FeatureFlags\" WHERE \"Description\" = '{marker}'"));
        Assert.Equal(certificates, await CountAsync(db.App, "SELECT count(*) FROM \"Certificates\""));
        Assert.All(config, f => Assert.Equal(f.Value, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f.Key)))));
        Assert.Equal(root, await host.GetAsync(httpPort, "/ca/drill-root"));
        Assert.DoesNotContain("Restore lock:", host.NodeLog);
        // The node holds its key of the lock, shared, on its own connection.
        Assert.Equal(1, await CountAsync(db.App,
            $"SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.locktype = 'advisory' AND l.classid = {RestoreLock.LockClass} "
            + $"AND l.objid = {RestoreLock.NodeKey} AND l.mode = 'ShareLock' AND l.granted AND a.application_name = 'ModularCA restore lock'"));

        // The check an orchestrator runs beside a serving node still runs beside it.
        var beside = await host.ExecuteAsync("read-only upgrade check beside the node", ["--upgrade-check", "--read-only"]);
        Assert.True(beside.ExitCode == 0, beside.Text);

        await host.StopAsync();

        // ---- a restore holds the database ----------------------------------------------------
        using var holding = host.Begin("restore that waits to be confirmed", ["--restore", archive]);
        await holding.UntilWroteAsync("Restore lock taken", TimeSpan.FromMinutes(3));

        var second = await host.ExecuteAsync("second restore while one runs", ["--restore", archive, "--unattended"]);
        Assert.True(second.ExitCode == RestoreExit.Refused, second.Text);
        Assert.Contains("or another restore is running on it", second.LastLine);
        Assert.EndsWith("Nothing was changed.", second.LastLine);

        // The full upgrade check runs with the node stopped and the database up: also beside a restore.
        var check = await host.ExecuteAsync("upgrade check beside a restore", ["--upgrade-check"]);
        Assert.True(check.ExitCode == 0, check.Text);

        // A node started now, told to wait three seconds: it does not start, and exits 75.
        var configYaml = Path.Combine(host.ConfigDirectory, "config.yaml");
        var configBefore = File.ReadAllText(configYaml);
        // The host's own file carries the Schema section with the setting at its default.
        Assert.Matches(@"(?m)^Schema:\s*$", configBefore);
        Assert.Matches(@"(?m)^\s+RestoreWaitSeconds:\s*60\s*$", configBefore);
        File.WriteAllText(configYaml, System.Text.RegularExpressions.Regex.Replace(configBefore, @"(?m)^(\s+RestoreWaitSeconds:\s*)60", "${1}3"));
        DrillRun gaveUp;
        try
        {
            gaveUp = await host.ExecuteAsync("node started while a restore holds the database", []);
        }
        finally
        {
            File.WriteAllText(configYaml, configBefore);
        }
        Assert.True(gaveUp.ExitCode == 75, gaveUp.Text);
        Assert.Contains(gaveUp.Stdout, l => l.Contains("A restore is running on the application database") && l.Contains("waiting up to 3 s"));
        Assert.Contains(gaveUp.Stderr, l => l.Contains("was still running after 3 s (Schema.RestoreWaitSeconds), so this process did not start. Exiting with status 75"));
        Assert.DoesNotContain(gaveUp.Stdout, l => l.Contains("Schema check passed"));
        Assert.False(holding.Wrote("RESTORE:"), "the waiting restore ended while a node tried to start");

        // A node started now with the default wait: it waits, the restore ends, and it starts.
        var starting = host.StartAsync(httpPort);
        await UntilAsync(TimeSpan.FromMinutes(2), () => Task.FromResult(host.NodeLog.Contains("A restore is running on the application database") ? "waiting" : null),
            "the node did not say it waits for the restore");
        Assert.DoesNotContain("Schema check passed", host.NodeLog);
        var declined = await holding.FinishAsync("no\n");
        Assert.True(declined.ExitCode == RestoreExit.Refused, declined.Text);
        Assert.Contains("not confirmed", declined.LastLine);
        await starting;
        Assert.Contains("the start goes on", host.NodeLog);
        Assert.Equal(root, await host.GetAsync(httpPort, "/ca/drill-root"));
        // The declined restore changed nothing either.
        Assert.Equal(1, await CountAsync(db.App, $"SELECT count(*) FROM \"FeatureFlags\" WHERE \"Description\" = '{marker}'"));
    }

    private static async Task ExecuteAsync(DbInstance instance, string sql)
    {
        await using var conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance)) { Pooling = false }.ConnectionString);
        await conn.OpenAsync();
        await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
    }

    private static X509Crl ParseCrl(byte[] der) => new X509CrlParser().ReadCrl(der);

    private static long CrlNumber(X509Crl crl) =>
        DerInteger.GetInstance(Asn1Object.FromByteArray(crl.GetExtensionValue(X509Extensions.CrlNumber).GetOctets())).Value.LongValue;

    /// <summary>The fingerprint of the system signing CA, as the keystore rows pin it.</summary>
    private const string PinSql = "SELECT \"SigningCaSpkiSha256\" FROM \"Keystores\" WHERE \"SigningCaSpkiSha256\" IS NOT NULL ORDER BY \"Id\" LIMIT 1";

    /// <summary>The stored identifier, as the JSON the row holds.</summary>
    private const string InstanceIdSql = "SELECT \"ValueJson\" FROM \"Settings\" WHERE \"Key\" = 'Instance_Id'";

    private static async Task<string?> TextAsync(DbInstance instance, string sql)
    {
        await using var conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance)) { Pooling = false }.ConnectionString);
        await conn.OpenAsync();
        return await new NpgsqlCommand(sql, conn).ExecuteScalarAsync() as string;
    }

    private static async Task<long> CountAsync(DbInstance instance, string sql)
    {
        await using var conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance)) { Pooling = false }.ConnectionString);
        await conn.OpenAsync();
        return Convert.ToInt64(await new NpgsqlCommand(sql, conn).ExecuteScalarAsync());
    }

    /// <summary>Waits until the node serves, on its HTTPS port, a certificate <paramref name="root"/> signed.</summary>
    private static Task<Org.BouncyCastle.X509.X509Certificate> ServedUnderAsync(int httpsPort, Org.BouncyCastle.X509.X509Certificate root) =>
        UntilAsync(TimeSpan.FromMinutes(2), async () =>
        {
            var served = await ServedCertificateAsync(httpsPort);
            try
            {
                served.Verify(root.GetPublicKey());
                return served;
            }
            catch (Org.BouncyCastle.Security.GeneralSecurityException)
            {
                return null;
            }
        }, "the node never served a web certificate its root signed");

    private static string SubjectAltNames(Org.BouncyCastle.X509.X509Certificate certificate) =>
        string.Join(",", (certificate.GetSubjectAlternativeNames() ?? []).Select(n => $"{n[0]}:{n[1]}").Order());

    /// <summary>The certificate the node serves on its HTTPS port.</summary>
    private static async Task<Org.BouncyCastle.X509.X509Certificate> ServedCertificateAsync(int httpsPort)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, httpsPort);
        await using var tls = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync("localhost");
        return new X509CertificateParser().ReadCertificate(tls.RemoteCertificate!.GetRawCertData());
    }

    /// <summary>
    /// Removes the drill's root from the Windows intermediate ("CA") stores, best effort. When
    /// Kestrel builds its server certificate context on Windows, .NET puts the chain's extra
    /// certificates into the CA store so SChannel can send them: LocalMachine when the process is
    /// elevated, CurrentUser otherwise. Each drill makes a new root under the same name, so
    /// without this they pile up, and with about a hundred same-named candidates the chain engine
    /// fails every TLS handshake with "An unknown chain building error occurred".
    /// </summary>
    /// <param name="rootDer">The drill root, DER-encoded.</param>
    private static void RemoveFromWindowsCaStores(byte[] rootDer)
    {
        if (!OperatingSystem.IsWindows())
            return;
        using var root = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(rootDer);
        foreach (var location in new[] { System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new System.Security.Cryptography.X509Certificates.X509Store(System.Security.Cryptography.X509Certificates.StoreName.CertificateAuthority, location);
                store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite | System.Security.Cryptography.X509Certificates.OpenFlags.OpenExistingOnly);
                foreach (var cached in store.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, root.Thumbprint, validOnly: false))
                {
                    store.Remove(cached);
                    cached.Dispose();
                }
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                // Not elevated, or the store is not there: nothing this drill can clean.
            }
        }
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }

    /// <summary>Polls <paramref name="probe"/> until it returns a value; fails with <paramref name="failure"/> when it never does.</summary>
    internal static async Task<T> UntilAsync<T>(TimeSpan limit, Func<Task<T?>> probe, string failure) where T : class
    {
        var watch = Stopwatch.StartNew();
        Exception? last = null;
        while (watch.Elapsed < limit)
        {
            try
            {
                if (await probe() is { } value)
                    return value;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException or TaskCanceledException)
            {
                last = ex;
            }
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
        throw new Xunit.Sdk.XunitException($"{failure} (waited {limit.TotalSeconds:F0}s{(last is null ? "" : "; last error: " + last.Message)})");
    }
}

/// <summary>The drill onto two roles and two empty databases made by hand.</summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(RestoreDrillCollection.EmptyDatabases)]
public sealed class RestoreDrillOntoEmptyDatabasesTests(ITestOutputHelper output) : RestoreDrillTests(output)
{
    /// <summary>The drill.</summary>
    [RequiresPostgresClientToolsTheory(ServerVariable)]
    [InlineData(NewHost.EmptyDatabases)]
    public Task A_backup_restores_onto_a_new_host_and_the_ca_signs_again(NewHost newHost) => DrillAsync(newHost);
}

/// <summary>The drill onto a complete new install with a root of its own, which the restore replaces.</summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(RestoreDrillCollection.FreshInstall)]
public sealed class RestoreDrillOntoFreshInstallTests(ITestOutputHelper output) : RestoreDrillTests(output)
{
    /// <summary>The drill.</summary>
    [RequiresPostgresClientToolsTheory(ServerVariable)]
    [InlineData(NewHost.FreshInstall)]
    public Task A_backup_restores_onto_a_new_host_and_the_ca_signs_again(NewHost newHost) => DrillAsync(newHost);
}

/// <summary>
/// The collections of the two restore drills. They start when every other collection of the run
/// that may run in parallel has finished, the PostgreSQL lanes included, and run beside each
/// other (<see cref="PhasedTestFramework"/>): the drill installs, starts and restores whole
/// nodes, and with the rest of the suite loading the same PostgreSQL server, its install hit
/// Npgsql command timeouts.
/// </summary>
internal static class RestoreDrillCollection
{
    /// <summary>What both collection names start with.</summary>
    public const string Prefix = "Restore drill ";

    /// <summary>The collection of <see cref="RestoreDrillOntoEmptyDatabasesTests"/>.</summary>
    public const string EmptyDatabases = Prefix + "onto empty databases";

    /// <summary>The collection of <see cref="RestoreDrillOntoFreshInstallTests"/>.</summary>
    public const string FreshInstall = Prefix + "onto a fresh install";

    /// <summary>The collection of <see cref="UnattendedRestoreDrillTests"/>.</summary>
    public const string Unattended = Prefix + "with nobody at the instance";
}

/// <summary>One finished run of the node: its exit status and what it wrote, line by line.</summary>
/// <param name="ExitCode">The exit status.</param>
/// <param name="Stdout">Standard output.</param>
/// <param name="Stderr">Standard error.</param>
internal sealed record DrillRun(int ExitCode, IReadOnlyList<string> Stdout, IReadOnlyList<string> Stderr)
{
    /// <summary>The last line of standard output that is not empty.</summary>
    public string LastLine => Stdout.LastOrDefault(l => !string.IsNullOrWhiteSpace(l)) ?? string.Empty;

    /// <summary>All of standard output and standard error, for a failure message.</summary>
    public string Text => string.Join(Environment.NewLine, Stdout.Concat(Stderr.Select(l => "[stderr] " + l)));
}

/// <summary>
/// A run of the node that is still going, with its standard input open: what it has written so
/// far can be waited on, and it is finished by answering it or by closing its input.
/// </summary>
internal sealed class DrillProcess : IDisposable
{
    private readonly string _step;
    private readonly Process _process;
    private readonly ITestOutputHelper _output;
    private readonly Func<StringBuilder, string> _redact;
    private readonly List<string> _stdout = [];
    private readonly List<string> _stderr = [];
    private readonly Stopwatch _watch = Stopwatch.StartNew();

    public DrillProcess(string step, Process process, ITestOutputHelper output, Func<StringBuilder, string> redact)
    {
        (_step, _process, _output, _redact) = (step, process, output, redact);
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (_stdout) _stdout.Add(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (_stderr) _stderr.Add(e.Data); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    /// <summary>Whether a line of standard output written so far contains <paramref name="text"/>.</summary>
    public bool Wrote(string text)
    {
        lock (_stdout) return _stdout.Any(l => l.Contains(text, StringComparison.Ordinal));
    }

    /// <summary>Waits until it has written <paramref name="text"/>; fails when it exits or the time runs out first.</summary>
    public async Task UntilWroteAsync(string text, TimeSpan limit)
    {
        var waited = Stopwatch.StartNew();
        while (!Wrote(text))
        {
            if (_process.HasExited || waited.Elapsed > limit)
                Assert.Fail($"The {_step} {(_process.HasExited ? $"exited {_process.ExitCode}" : $"ran {limit.TotalSeconds:F0}s")} without writing '{text}':{Environment.NewLine}{Snapshot().Text}");
            await Task.Delay(200);
        }
    }

    /// <summary>Writes <paramref name="stdin"/>, when given, closes standard input and waits for the exit.</summary>
    public async Task<DrillRun> FinishAsync(string? stdin = null)
    {
        if (stdin is not null)
            await _process.StandardInput.WriteAsync(stdin);
        _process.StandardInput.Close();
        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        try
        {
            await _process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            _process.Kill(entireProcessTree: true);
            Assert.Fail($"The {_step} did not finish in 10 minutes:{Environment.NewLine}{Snapshot().Text}");
        }
        _process.WaitForExit();
        var run = Snapshot() with { ExitCode = _process.ExitCode };
        _output.WriteLine($"--- {_step} (exit {run.ExitCode}, {_watch.Elapsed.TotalSeconds:F0}s){Environment.NewLine}{_redact(new StringBuilder(run.Text))}");
        return run;
    }

    private DrillRun Snapshot()
    {
        lock (_stdout) lock (_stderr) return new DrillRun(-1, _stdout.ToList(), _stderr.ToList());
    }

    /// <summary>Ends it if it is still running.</summary>
    public void Dispose()
    {
        try
        {
            if (!_process.HasExited)
                _process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
        }
        _process.Dispose();
    }
}

/// <summary>The role and database names of one install on the drill's server.</summary>
internal sealed record DrillLayout(string AppRole, string AuditRole, string AppDatabase, string AuditDatabase)
{
    public string AppPassword { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    public string AuditPassword { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    public string AuditOwnerRole => AuditRole + PostgresLayoutNames.OwnerSuffix;
}

/// <summary>
/// The PostgreSQL server the drill uses: a superuser made for the drill, the layouts it handed
/// out, and their removal. Everything is dropped on dispose.
/// </summary>
internal sealed class DrillServer : IAsyncDisposable
{
    private readonly string _admin;
    private readonly List<DrillLayout> _layouts = [];

    private DrillServer(string admin)
    {
        _admin = new NpgsqlConnectionStringBuilder(admin) { Pooling = false }.ConnectionString;
        var b = new NpgsqlConnectionStringBuilder(admin);
        (Host, Port, SslMode) = (b.Host ?? "localhost", b.Port, b.SslMode.ToString());
        SetupRole = $"mcat_dr_su_{Guid.NewGuid().ToString("N")[..10]}";
        SetupPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    }

    public string Host { get; }
    public int Port { get; }
    public string SslMode { get; }

    /// <summary>The superuser the drill's unattended installs log in as.</summary>
    public string SetupRole { get; }
    public string SetupPassword { get; }

    public static async Task<DrillServer> CreateAsync(string admin)
    {
        var server = new DrillServer(admin);
        await server.ExecuteAsync($"CREATE ROLE {Q(server.SetupRole)} WITH LOGIN SUPERUSER PASSWORD '{server.SetupPassword}'");
        return server;
    }

    public DrillLayout NewLayout()
    {
        var suffix = Guid.NewGuid().ToString("N")[..10];
        var layout = new DrillLayout($"mcat_dr_app_{suffix}", $"mcat_dr_audit_{suffix}", $"mcat-dr-app-{suffix}", $"mcat-dr-audit-{suffix}");
        _layouts.Add(layout);
        return layout;
    }

    /// <summary>Two login roles and two empty databases, each owned by its role: a new host prepared by hand.</summary>
    public async Task CreateEmptyDatabasesAsync(DrillLayout layout)
    {
        await ExecuteAsync($"CREATE ROLE {Q(layout.AppRole)} WITH LOGIN PASSWORD '{layout.AppPassword}'");
        await ExecuteAsync($"CREATE ROLE {Q(layout.AuditRole)} WITH LOGIN PASSWORD '{layout.AuditPassword}'");
        await ExecuteAsync($"CREATE DATABASE {Q(layout.AppDatabase)} OWNER {Q(layout.AppRole)} ENCODING 'UTF8' TEMPLATE template0");
        await ExecuteAsync($"CREATE DATABASE {Q(layout.AuditDatabase)} OWNER {Q(layout.AuditRole)} ENCODING 'UTF8' TEMPLATE template0");
    }

    public async Task DropAsync(DrillLayout layout)
    {
        NpgsqlConnection.ClearAllPools();
        foreach (var database in new[] { layout.AppDatabase, layout.AuditDatabase })
            await TryAsync($"DROP DATABASE IF EXISTS {Q(database)} WITH (FORCE)");
        foreach (var role in new[] { layout.AppRole, layout.AuditRole, layout.AuditOwnerRole })
            await TryAsync($"DROP ROLE IF EXISTS {Q(role)}");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var layout in _layouts)
            await DropAsync(layout);
        await TryAsync($"DROP ROLE IF EXISTS {Q(SetupRole)}");
    }

    private async Task ExecuteAsync(string sql)
    {
        await using var conn = new NpgsqlConnection(_admin);
        await conn.OpenAsync();
        await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
    }

    private async Task TryAsync(string sql)
    {
        try { await ExecuteAsync(sql); }
        catch (PostgresException) { }
    }

    private static string Q(string identifier) => PostgresConnection.QuoteIdentifier(identifier);
}

/// <summary>
/// One host of the drill: a copy of the built node in its own directory, run as its own
/// processes. The harness's own connection string is taken out of their environment.
/// </summary>
internal sealed class DrillHost
{
    private static readonly string[] RuntimeDirectories = ["config", "keystores", "logs", "backups", "BuildHost-net472", "BuildHost-netcore"];

    private readonly DrillServer _server;
    private readonly ITestOutputHelper _output;
    private readonly StringBuilder _nodeLog = new();

    /// <summary>What the node has written since it was last started.</summary>
    public string NodeLog { get { lock (_nodeLog) return _nodeLog.ToString(); } }

    /// <summary>
    /// The incarnation every process of this host is started with, as an orchestrator injects it
    /// (<c>MODULARCA__INSTANCE__INCARNATION</c>); null for a host that reports none.
    /// </summary>
    public string? Incarnation { get; set; }

    /// <summary>
    /// The temporary directory every process of this host is given (<c>TMP</c>, <c>TEMP</c>,
    /// <c>TMPDIR</c>), so a drill can see what a command staged and whether it cleaned up; null
    /// for the account's own.
    /// </summary>
    public string? TempDirectory { get; set; }

    private Process? _node;

    private DrillHost(string directory, DrillServer server, ITestOutputHelper output)
    {
        (Directory, _server, _output) = (directory, server, output);
    }

    public string Directory { get; }
    public string ConfigDirectory => Path.Combine(Directory, "config");

    /// <summary>Copies the built node into <paramref name="directory"/> with the example files a distribution ships, and nothing a run left behind.</summary>
    public static DrillHost Create(string directory, DrillServer server, ITestOutputHelper output)
    {
        var repo = RepoRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).Parent!.Name;
        var build = Path.Combine(repo, "ModularCA.API", "bin", configuration, "net10.0");
        Assert.True(File.Exists(Path.Combine(build, "ModularCA.API.dll")), $"Build ModularCA.API ({configuration}) before the drill: {build} holds no node.");

        Copy(build, directory, top: true);
        var host = new DrillHost(directory, server, output);
        System.IO.Directory.CreateDirectory(host.ConfigDirectory);
        foreach (var example in System.IO.Directory.GetFiles(Path.Combine(repo, "config"), "*.example"))
            File.Copy(example, Path.Combine(host.ConfigDirectory, Path.GetFileName(example)));
        return host;
    }

    /// <summary>The two files an unattended install reads.</summary>
    public void WriteInstallFiles(DrillLayout layout, int httpsPort, int httpPort)
    {
        File.WriteAllText(Path.Combine(ConfigDirectory, "bootstrap.yaml"), $"""
            CA:
              Subject:
                CN: "Drill Root"
                O: "ModularCA Drill"
                C: "US"
              Algorithm: ECDSA
              KeySize: 384
              ValidityYears: 10
            SigningProfile:
              Name: "default"
              IsCa: true
              KeyUsages:
                - digitalSignature
                - keyCertSign
                - crlSign
              ExtendedKeyUsages:
                - 1.3.6.1.5.5.7.3.1
            Features:
              CRL: true
              OCSP: true
              ACME: false
              EST: false
              SCEP: false
              CMP: false
              MSAE: false
            Administration:
              MultipleAdministrators: false
            HttpsApi:
              CN: "localhost"
              PublicDomain: "localhost"
              SANs:
                - "DNS:localhost"
                - "IP:127.0.0.1"
              Port: {httpsPort}
              HttpPort: {httpPort}
              ValidityDays: 397
            """);
        File.WriteAllText(Path.Combine(ConfigDirectory, "setup-database.yaml"), $"""
            SqlRoot:
              Host: {_server.Host}
              Port: {_server.Port}
              Username: {_server.SetupRole}
              Password: "{_server.SetupPassword}"
              SslMode: {_server.SslMode}
            SqlApp:
              Database: {layout.AppDatabase}
              Username: {layout.AppRole}
              SslMode: {_server.SslMode}
            SqlAudit:
              Database: {layout.AuditDatabase}
              Username: {layout.AuditRole}
              SslMode: {_server.SslMode}
            """);
    }

    /// <summary>A <c>db.yaml</c> written by hand, as on a host whose databases the operator created.</summary>
    public void WriteDbYaml(DrillLayout layout) =>
        File.WriteAllText(Path.Combine(ConfigDirectory, "db.yaml"), $"""
            App:
              Host: {_server.Host}
              Port: {_server.Port}
              Database: {layout.AppDatabase}
              Username: {layout.AppRole}
              Password: "{layout.AppPassword}"
              SslMode: {_server.SslMode}
            Audit:
              Host: {_server.Host}
              Port: {_server.Port}
              Database: {layout.AuditDatabase}
              Username: {layout.AuditRole}
              Password: "{layout.AuditPassword}"
              SslMode: {_server.SslMode}
            """);

    /// <summary>The databases this host's <c>db.yaml</c> names, with its runtime roles' credentials.</summary>
    public (DbInstance App, DbInstance Audit) Databases()
    {
        var yaml = YamlDbConfigLoader.Load(Path.Combine(ConfigDirectory, "db.yaml"))!;
        static DbInstance From(YamlDbConfigLoader.DbInstanceConfig c) => new()
        {
            Host = c.Host, Port = c.Port, Database = c.Database, Username = c.Username, Password = c.Password, SslMode = c.SslMode,
        };
        return (From(yaml.App), From(yaml.Audit));
    }

    /// <summary>Runs the node with <paramref name="arguments"/> to completion and requires exit code 0.</summary>
    public async Task<TimeSpan> RunAsync(string step, string[] arguments, string? stdin = null)
    {
        var watch = Stopwatch.StartNew();
        using var process = Start(arguments);
        var log = new StringBuilder();
        Capture(process, log);
        if (stdin is not null)
            await process.StandardInput.WriteAsync(stdin);
        process.StandardInput.Close();

        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        try
        {
            await process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail($"The {step} did not finish in 10 minutes:{Environment.NewLine}{Redact(log)}");
        }
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"The {step} exited {process.ExitCode}:{Environment.NewLine}{Redact(log)}");
        _output.WriteLine($"--- {step} ({watch.Elapsed.TotalSeconds:F0}s){Environment.NewLine}{Redact(log)}");
        return watch.Elapsed;
    }

    /// <summary>
    /// Runs the node with <paramref name="arguments"/> to completion and returns its exit status
    /// with standard output and standard error apart, whatever the status. Standard input is
    /// closed at once unless <paramref name="stdin"/> is given.
    /// </summary>
    public async Task<DrillRun> ExecuteAsync(string step, string[] arguments, string? stdin = null)
    {
        var watch = Stopwatch.StartNew();
        using var process = Start(arguments);
        var (stdout, stderr) = (new List<string>(), new List<string>());
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (stdout) stdout.Add(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (stderr) stderr.Add(e.Data); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        if (stdin is not null)
            await process.StandardInput.WriteAsync(stdin);
        process.StandardInput.Close();

        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        try
        {
            await process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail($"The {step} did not finish in 10 minutes:{Environment.NewLine}{Redact(new StringBuilder(string.Join(Environment.NewLine, stdout)))}");
        }
        process.WaitForExit();
        var run = new DrillRun(process.ExitCode, stdout, stderr);
        _output.WriteLine($"--- {step} (exit {run.ExitCode}, {watch.Elapsed.TotalSeconds:F0}s){Environment.NewLine}{Redact(new StringBuilder(run.Text))}");
        return run;
    }

    /// <summary>
    /// Starts the node with <paramref name="arguments"/> and leaves its standard input open, for a
    /// command that waits to be answered: the caller answers, or closes it, through the result.
    /// </summary>
    public DrillProcess Begin(string step, string[] arguments) => new(step, Start(arguments), _output, Redact);

    /// <summary>
    /// Awaits <paramref name="wait"/>, and when it fails, fails with the running node's log
    /// (redacted) appended, so a node that starts but never gets as far as the check says why.
    /// </summary>
    /// <param name="wait">A wait on something the running node should do.</param>
    public async Task<T> WithNodeLogOnFailureAsync<T>(Task<T> wait)
    {
        try
        {
            return await wait;
        }
        catch (Xunit.Sdk.XunitException ex)
        {
            throw new Xunit.Sdk.XunitException($"{ex.Message}{Environment.NewLine}{Redact(_nodeLog)}");
        }
    }

    /// <summary>Starts the node and waits until it serves its root over plain HTTP.</summary>
    public async Task<TimeSpan> StartAsync(int httpPort)
    {
        var watch = Stopwatch.StartNew();
        _nodeLog.Clear();
        _node = Start([]);
        Capture(_node, _nodeLog);
        _node.StandardInput.Close();
        try
        {
            await RestoreDrillTests.UntilAsync<byte[]>(TimeSpan.FromMinutes(4), async () =>
            {
                if (_node.HasExited)
                    throw new Xunit.Sdk.XunitException($"The node exited {_node.ExitCode} while starting.");
                return await GetAsync(httpPort, "/ca/drill-root");
            }, "the node never served its root");
        }
        catch (Xunit.Sdk.XunitException ex)
        {
            throw new Xunit.Sdk.XunitException($"{ex.Message}{Environment.NewLine}{Redact(_nodeLog)}");
        }
        return watch.Elapsed;
    }

    public async Task StopAsync()
    {
        if (_node is null)
            return;
        try
        {
            if (!_node.HasExited)
            {
                _node.Kill(entireProcessTree: true);
                await _node.WaitForExitAsync();
            }
        }
        catch (InvalidOperationException)
        {
        }
        _node.Dispose();
        _node = null;
    }

    public async Task<byte[]> GetAsync(int httpPort, string path)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        using var response = await http.GetAsync($"http://127.0.0.1:{httpPort}{path}");
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"GET {path} answered {(int)response.StatusCode}");
        return await response.Content.ReadAsByteArrayAsync();
    }

    public Task<byte[]> GetUntilAsync(int httpPort, string path, TimeSpan limit) =>
        RestoreDrillTests.UntilAsync<byte[]>(limit, async () => await GetAsync(httpPort, path), $"GET {path} never succeeded");

    private Process Start(string[] arguments)
    {
        var executable = Path.Combine(Directory, OperatingSystem.IsWindows() ? "ModularCA.API.exe" : "ModularCA.API");
        var start = File.Exists(executable)
            ? new ProcessStartInfo(executable)
            : new ProcessStartInfo("dotnet") { ArgumentList = { Path.Combine(Directory, "ModularCA.API.dll") } };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        start.WorkingDirectory = Directory;
        start.RedirectStandardInput = start.RedirectStandardOutput = start.RedirectStandardError = true;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.StandardOutputEncoding = start.StandardErrorEncoding = Encoding.UTF8;
        foreach (var name in start.Environment.Keys.Where(k => k.StartsWith("MODULARCA", StringComparison.OrdinalIgnoreCase)).ToList())
            start.Environment.Remove(name);
        if (Incarnation is not null)
            start.Environment[ModularCA.Core.Services.Continuity.InjectedIncarnationSource.Variable] = Incarnation;
        start.Environment["PATH"] = PostgresClientTools.Directory + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        if (TempDirectory is not null)
            foreach (var name in new[] { "TMP", "TEMP", "TMPDIR" })
                start.Environment[name] = TempDirectory;
        return Process.Start(start)!;
    }

    private static void Capture(Process process, StringBuilder log)
    {
        void Append(string? line)
        {
            if (line is null) return;
            lock (log) log.AppendLine(line);
        }
        process.OutputDataReceived += (_, e) => Append(e.Data);
        process.ErrorDataReceived += (_, e) => Append(e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    /// <summary>A log with the server's address and the drill's passwords taken out.</summary>
    private string Redact(StringBuilder log)
    {
        string text;
        lock (log) text = log.ToString();
        return text.Replace(_server.Host, "<db-host>", StringComparison.OrdinalIgnoreCase)
            .Replace(_server.SetupPassword, "<password>", StringComparison.Ordinal);
    }

    private static void Copy(string source, string destination, bool top)
    {
        System.IO.Directory.CreateDirectory(destination);
        foreach (var file in System.IO.Directory.GetFiles(source))
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        foreach (var directory in System.IO.Directory.GetDirectories(source))
        {
            var name = Path.GetFileName(directory);
            if (top && RuntimeDirectories.Contains(name, StringComparer.OrdinalIgnoreCase))
                continue;
            Copy(directory, Path.Combine(destination, name), top: false);
        }
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
