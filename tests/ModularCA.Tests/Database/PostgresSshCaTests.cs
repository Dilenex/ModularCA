using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// <see cref="SshCaService"/> and the signer's reading of its rows against a real PostgreSQL
/// database migrated to the latest migration. The in-memory provider has no transaction and no
/// foreign key, so only here is it shown that a failed creation leaves no row behind and that
/// the rows are written and removed in an order the schema accepts. Opt-in through
/// <c>MODULARCA_TEST_PG</c>, as <see cref="PostgresUpgradeHarnessTests"/>.
/// </summary>
[Trait("Category", "PostgreSQL")]
public class PostgresSshCaTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    private static readonly SshCaActor Actor = new(null, "ssh-operator", "192.0.2.7");

    private static async Task<(int Cas, int Groups, int Roles, int Grants, int Keys, int Profiles)> RowCountsAsync(Func<ModularCADbContext> open)
    {
        await using var db = open();
        return (await db.CertificateAuthorities.IgnoreQueryFilters().CountAsync(), await db.CaGroups.CountAsync(),
            await db.RoleAssignments.CountAsync(), await db.CapabilityGrants.CountAsync(),
            await db.SshCaKeys.CountAsync(), await db.SshSigningProfiles.CountAsync());
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public Task An_ssh_ca_is_created_signs_revokes_and_lists_its_revocations() =>
        OnPostgresAsync(async (open, service, _) =>
        {
            var ca = await service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, true, 48, actor: Actor);

            var user = await service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), ["alice"], 2, "alice-laptop",
                ["permit-pty", "force-command=/usr/bin/true"], Actor);
            var host = await service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey("ECDSA", "P-256", "host1"), ["host1.example.com"], 4, null, Actor);

            Assert.True(SshCertificate.ParseOpenSsh(user.SignedCertificate).VerifySignature());
            Assert.True(SshCertificate.ParseOpenSsh(host.SignedCertificate).VerifySignature());

            var empty = await service.GenerateKrlAsync(ca.Id);
            Assert.True(await service.RevokeCertificateAsync(user.Id, ca.Id, Actor));
            var revoking = await service.GenerateKrlAsync(ca.Id);
            Assert.True(revoking.Length > empty.Length);

            await using var db = open();
            Assert.Equal(1, await db.CertificateAuthorities.CountAsync(c => c.IsSshCa));
            Assert.Equal(4, await db.CaGroups.CountAsync(g => g.CertificateAuthorityId == ca.CertificateAuthorityId));
            Assert.Equal(2, await db.SshSigningProfiles.CountAsync(p => p.SshCaKeyId == ca.Id));
            Assert.Equal(2, await db.SshCertificates.CountAsync(c => c.SshCaKeyId == ca.Id));
            Assert.Equal(1, await db.SshCertificates.CountAsync(c => c.IsRevoked));

            var signed = await db.SignerAudit.Where(a => a.Operation == "SignSsh").ToListAsync();
            Assert.Equal(2, signed.Count);
            Assert.All(signed, a => Assert.False(string.IsNullOrEmpty(a.Summary)));

            await service.DisableAsync(ca.Id, Actor);
            await Assert.ThrowsAsync<ConfigurationValidationException>(() =>
                service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["host2.example.com"], 1, null, Actor));
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_commit_the_signer_refuses_removes_every_row_it_was_written_for() =>
        OnPostgresAsync(async (open, service, relay) =>
        {
            var before = await RowCountsAsync(open);
            relay.OnCommit = (_, _, _) => throw new SigningRefusedException(SigningRefusalReason.CertificateMismatch, "The row does not carry the key.");

            await Assert.ThrowsAsync<SigningRefusedException>(() =>
                service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, true, 48, actor: Actor));

            Assert.Equal(before, await RowCountsAsync(open));
            Assert.Equal(KeyRef.SshKeystore, Assert.Single(relay.Retired).Key.Keystore);

            relay.OnCommit = null;
            var created = await service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, true, 48, actor: Actor);
            Assert.Equal(SshCaKeyStorage.Signer, created.KeyStorage);
        });

    /// <summary>
    /// Another request takes the label after this one checked it was free and before it saved:
    /// the relay inserts the other CA while the key is being generated.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_label_taken_while_the_ssh_ca_is_saved_is_a_conflict_and_leaves_nothing_behind() =>
        OnPostgresAsync(async (open, service, relay) =>
        {
            var before = await RowCountsAsync(open);
            relay.RewriteSpec = spec =>
            {
                using var other = open();
                other.CertificateAuthorities.Add(new CertificateAuthorityEntity
                {
                    Name = "Fleet SSH", Label = "fleet-ssh", Type = "SSH", IsSshCa = true, IsEnabled = true, SpaceId = null,
                });
                other.SaveChanges();
                return spec;
            };

            await Assert.ThrowsAsync<ResourceConflictException>(() =>
                service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, true, 48, actor: Actor));

            Assert.Equal(before with { Cas = before.Cas + 1 }, await RowCountsAsync(open));
            Assert.Single(relay.Retired);
            Assert.Empty(relay.Committed);

            // The same context saves again: nothing of the rolled-back attempt is still tracked.
            relay.RewriteSpec = null;
            var created = await service.GenerateKeyPairAsync("Other SSH", "ed25519", true, false, 24, actor: Actor);
            var after = await RowCountsAsync(open);
            Assert.Equal(before.Cas + 2, after.Cas);
            Assert.Equal(before.Keys + 1, after.Keys);
            Assert.Equal(SshCaKeyStorage.Signer, created.KeyStorage);
        });

    /// <summary>
    /// The one transaction of the key file import (stage 4): the row's storage becomes
    /// <c>Signer</c>, its path is cleared and the import record is written together or not at
    /// all. A trigger refuses the record: the row update made in the same transaction is rolled
    /// back, the file is untouched, and the next pass, with the trigger gone, finishes the import
    /// with a signer that already holds the key. Also what a backup reads to find key files.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_key_file_import_switches_the_row_and_writes_its_record_in_one_transaction() =>
        OnPostgresAsync(async (open, service, relay) =>
        {
            var install = Path.Combine(Path.GetTempPath(), $"mca-pg-ssh-import-{Guid.NewGuid():N}");
            var keys = Path.Combine(install, "config", "ssh-ca-keys");
            Directory.CreateDirectory(keys);
            try
            {
                var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Old SSH", Label = "old-ssh", Type = "SSH", IsSshCa = true, IsEnabled = true, SpaceId = null };
                var key = new SshCaKeyEntity
                {
                    Id = Guid.NewGuid(), Name = "Old SSH", KeyType = "ecdsa", KeySize = 256, CertificateAuthorityId = ca.Id,
                    PublicKey = ModularCA.Tests.Ssh.SshFixtures.Text("ca-p256.pub").Trim(), KeyStorage = SshCaKeyStorage.LegacyFile,
                    IsUserCa = true, IsHostCa = true, MaxValidityHours = 24,
                };
                // Relative, as the upgrade harness seeds it.
                key.PrivateKeyPath = $"config/ssh-ca-keys/{key.Id}";
                var file = Path.Combine(keys, key.Id.ToString());
                File.Copy(ModularCA.Tests.Ssh.SshFixtures.PathOf("ca-p256.testkey"), file);
                File.Copy(ModularCA.Tests.Ssh.SshFixtures.PathOf("ca-p256.pub"), file + ".pub");
                var original = File.ReadAllBytes(file);
                await using (var seed = open())
                {
                    seed.CertificateAuthorities.Add(ca);
                    seed.SshCaKeys.Add(key);
                    await seed.SaveChangesAsync();
                }
                string connection;
                await using (var db = open())
                    connection = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable(ServerVariable)!)
                    {
                        Database = db.Database.GetDbConnection().Database, Pooling = false,
                    }.ConnectionString;
                Assert.Equal(new[] { key.PrivateKeyPath }, await ModularCA.Bootstrap.BackupRestore.LegacySshKeyFilesAsync(connection));

                var state = new SshKeyImportState();
                var audit = new SshAuditLog();
                SshKeyFileImport Import() => new(open(), relay, audit, state, NullLogger<SshKeyFileImport>.Instance, install);
                async Task<long> CountAsync(string sql)
                {
                    await using var db = open();
                    return await PostgresUpgradeHarnessTests.ScalarAsync(db, sql);
                }

                await using (var db = open())
                    await PostgresUpgradeHarnessTests.ExecAsync(db,
                        "CREATE FUNCTION refuse_ssh_import() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'the record is refused'; END $$ LANGUAGE plpgsql; "
                        + "CREATE TRIGGER refuse_ssh_import BEFORE INSERT ON \"SshKeyImports\" FOR EACH ROW EXECUTE FUNCTION refuse_ssh_import();");

                var refused = await Import().RunAsync();

                // The signer took the key; the transaction did not commit, so the row is as it was, with its path, and no file was touched.
                Assert.Empty(refused.Imported);
                Assert.Equal(SshKeyImportReasons.Failed, Assert.Single(refused.Awaiting).Code);
                Assert.Equal(1, await CountAsync($"SELECT count(*) FROM \"SshCaKeys\" WHERE \"Id\" = '{key.Id}' AND \"KeyStorage\" = 'LegacyFile' AND \"PrivateKeyPath\" = '{key.PrivateKeyPath}'"));
                Assert.Equal(0, await CountAsync("SELECT count(*) FROM \"SshKeyImports\""));
                Assert.Equal(original, File.ReadAllBytes(file));
                Assert.Equal(1, await CountAsync("SELECT count(*) FROM \"SignerAudit\" WHERE \"Operation\" = 'ImportKey' AND \"Purpose\" = 'SshKeyMigration' AND \"Outcome\" = 'allowed'"));
                Assert.Empty(audit.Of(ModularCA.Shared.Enums.AuditActionType.SshCaKeyImported));

                await using (var db = open())
                    await PostgresUpgradeHarnessTests.ExecAsync(db, "DROP TRIGGER refuse_ssh_import ON \"SshKeyImports\"; DROP FUNCTION refuse_ssh_import();");

                var done = await Import().RunAsync();

                Assert.Equal(new[] { key.Id }, done.Imported);
                Assert.False(done.WorkRemains);
                Assert.Equal(1, await CountAsync($"SELECT count(*) FROM \"SshCaKeys\" WHERE \"Id\" = '{key.Id}' AND \"KeyStorage\" = 'Signer' AND \"PrivateKeyPath\" IS NULL"));
                Assert.Equal(1, await CountAsync($"SELECT count(*) FROM \"SshKeyImports\" WHERE \"SshCaKeyId\" = '{key.Id}' AND \"FileRemovedAt\" IS NOT NULL AND \"AuditedAt\" IS NOT NULL"));
                Assert.False(File.Exists(file));
                Assert.False(File.Exists(file + ".pub"));
                Assert.Single(audit.Of(ModularCA.Shared.Enums.AuditActionType.SshCaKeyImported));
                // The second import was answered "already held": two allowed rows, one key in the keystore.
                Assert.Equal(2, await CountAsync("SELECT count(*) FROM \"SignerAudit\" WHERE \"Operation\" = 'ImportKey' AND \"Outcome\" = 'allowed'"));
                Assert.Empty(await ModularCA.Bootstrap.BackupRestore.LegacySshKeyFilesAsync(connection));

                // The imported key signs, and what the readiness page reads says it is held.
                var signed = await service.SignUserKeyAsync(key.Id, SshNode.SubjectKey(), ["alice"], 1, "alice-laptop", ["permit-pty"], Actor);
                var certificate = SshCertificate.ParseOpenSsh(signed.SignedCertificate);
                Assert.True(certificate.VerifySignature());
                Assert.Equal(ModularCA.Tests.Ssh.SshFixtures.CaPublic("p256"), certificate.SignatureKey);
                await using (var db = open())
                {
                    var custody = await SshKeyCustody.ReadAsync(db, relay, state);
                    Assert.Equal(SshKeyCustody.Held, custody.Keys.Single(k => k.Id == key.Id).State);
                    Assert.True((await SshPlaintextNotices.ReadAsync(db, null)).Applies);
                }

                // An imported key whose file was not removed yet is still a file a backup must know of.
                await using (var db = open())
                    await PostgresUpgradeHarnessTests.ExecAsync(db, $"UPDATE \"SshKeyImports\" SET \"FileRemovedAt\" = NULL WHERE \"SshCaKeyId\" = '{key.Id}'");
                Assert.Equal(new[] { file }, await ModularCA.Bootstrap.BackupRestore.LegacySshKeyFilesAsync(connection));
            }
            finally
            {
                try { Directory.Delete(install, true); } catch (IOException) { }
            }
        });

    /// <summary>
    /// Creates a database on the <c>MODULARCA_TEST_PG</c> server, applies every application
    /// migration, seeds the built-in roles and an instance that waives key ceremonies, runs
    /// <paramref name="scenario"/> with a way to open contexts, the service over the real
    /// in-process signer and the relay between them, and drops the database, whatever the outcome.
    /// </summary>
    private static async Task OnPostgresAsync(Func<Func<ModularCADbContext>, SshCaService, RelayingSigner, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = $"modularca_sshca_{Guid.NewGuid():N}"[..32];
        await ExecAsync(server, $"CREATE DATABASE \"{name}\"");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            ModularCADbContext Open() => new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
            await using (var db = Open())
            {
                await db.Database.MigrateAsync();
                ModularCA.Bootstrap.BootstrapProfileSeeder.SeedBuiltInRoles(db);
                if (!await db.SecurityPolicies.AnyAsync())
                    db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = false, CeremonyRequiredApprovals = 1 });
                await db.SaveChangesAsync();
            }

            var services = new ServiceCollection();
            services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(connection));
            await using var provider = services.BuildServiceProvider();
            var scopes = provider.GetRequiredService<IServiceScopeFactory>();
            var signer = new InProcessSigningService(new TestKeystore(), scopes, new DatabaseSignerAuditSink(scopes),
                new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance, unlocked: true);
            var relay = new RelayingSigner(signer);

            await using var serviceDb = Open();
            await scenario(Open, new SshCaService(serviceDb, relay, new SshAuditLog(), NullLogger<SshCaService>.Instance), relay);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await ExecAsync(server, $"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");
        }
    }

    private static async Task ExecAsync(string server, string sql)
    {
        await using var connection = new NpgsqlConnection(server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
