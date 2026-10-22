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

            var user = await service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 2,
                ["permit-pty", "force-command=/usr/bin/true"], Actor);
            var host = await service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey("ECDSA", "P-256", "host1"), ["host1.example.com"], 4, Actor);

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
                service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["host2.example.com"], 1, Actor));
        });

    /// <summary>
    /// KRL delivery (<c>docs/architecture/ssh-krl-delivery.md</c>) on PostgreSQL, where the
    /// state is one query with two sub-selects over the partial index and a time is stored in
    /// microseconds: a revocation records when, the state read without building the list is the
    /// state of the built list, from this context and from another, the bytes do not change
    /// between revocations, and a row revoked with no time dates nothing.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_krl_s_state_is_read_without_building_it_and_its_bytes_change_only_with_a_revocation() =>
        OnPostgresAsync(async (open, service, relay) =>
        {
            var ca = await service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, true, 48, actor: Actor);
            var lab = await service.GenerateKeyPairAsync("Lab SSH", "ecdsa", true, false, 48, 256, actor: Actor);
            var untimed = await service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 2, null, Actor);
            var timed = await service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["bob"], 2, null, Actor);
            var host = await service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["host1.example.com"], 2, Actor);
            await service.SignUserKeyAsync(lab.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 2, null, Actor);
            SshCaService Other() => SshServices.Ca(open(), relay, new SshAuditLog());
            await using var db = open();
            var created = (await db.SshCaKeys.AsNoTracking().SingleAsync(k => k.Id == ca.Id)).CreatedAt;

            var empty = await service.BuildKrlAsync(ca.Id);
            Assert.Equal(empty.State, await service.GetKrlStateAsync(ca.Id));
            Assert.Equal(empty.State, await Other().GetKrlStateAsync(ca.Id));
            Assert.Equal(0UL, empty.State!.Version);
            Assert.Null(empty.State.LastRevokedAt);
            Assert.Equal(SshCaService.KrlGeneratedAt(null, created).UtcDateTime, empty.State.GeneratedAt);

            // A certificate revoked before the column: revoked, and no time.
            await PostgresUpgradeHarnessTests.ExecAsync(db, $"UPDATE \"SshCertificates\" SET \"IsRevoked\" = true WHERE \"Id\" = '{untimed.Id}'");
            var noTime = await service.BuildKrlAsync(ca.Id);
            Assert.Equal(1UL, noTime.State!.Version);
            Assert.Null(noTime.State.LastRevokedAt);
            Assert.Equal(empty.State.GeneratedAt, noTime.State.GeneratedAt);
            Assert.NotEqual(empty.State.ETag, noTime.State.ETag);
            Assert.Equal(noTime.State, await service.GetKrlStateAsync(ca.Id));

            var before = DateTime.UtcNow.AddSeconds(-1);
            Assert.True(await service.RevokeCertificateAsync(timed.Id, ca.Id, Actor));
            var stored = (await db.SshCertificates.AsNoTracking().SingleAsync(c => c.Id == timed.Id)).RevokedAt;
            Assert.InRange(Assert.NotNull(stored), before, DateTime.UtcNow.AddSeconds(1));

            var one = await service.BuildKrlAsync(ca.Id);
            Assert.Equal(2UL, one.State!.Version);
            Assert.Equal(stored, one.State.LastRevokedAt);
            Assert.Equal(SshCaService.KrlGeneratedAt(stored, created).UtcDateTime, one.State.GeneratedAt);
            Assert.Equal(one.State, await service.GetKrlStateAsync(ca.Id));
            Assert.Equal(one.State, await Other().GetKrlStateAsync(ca.Id));
            Assert.Equal(one.Bytes, (await Other().BuildKrlAsync(ca.Id)).Bytes);
            Assert.Equal(one.Bytes, await service.GenerateKrlAsync(ca.Id));

            // Asked again, the revocation keeps its time, so the list keeps its bytes.
            Assert.True(await Other().RevokeCertificateAsync(timed.Id, ca.Id, Actor));
            Assert.Equal(stored, (await db.SshCertificates.AsNoTracking().SingleAsync(c => c.Id == timed.Id)).RevokedAt);
            Assert.Equal(one.Bytes, (await Other().BuildKrlAsync(ca.Id)).Bytes);

            var states = await service.GetKrlStatesAsync([ca.Id, lab.Id, Guid.NewGuid()]);
            Assert.Equal(2, states.Count);
            Assert.Equal(one.State, states[ca.Id]);
            Assert.Equal(0UL, states[lab.Id].Version);
            Assert.NotEqual(states[ca.Id].ETag, states[lab.Id].ETag);

            // Disabling the key revokes what is left at one time, which becomes the newest.
            await Other().DisableAsync(ca.Id, Actor);
            var hostRevokedAt = (await db.SshCertificates.AsNoTracking().SingleAsync(c => c.Id == host.Id)).RevokedAt;
            var all = await service.GetKrlStateAsync(ca.Id);
            Assert.Equal(3UL, all.Version);
            Assert.Equal(hostRevokedAt, all.LastRevokedAt);
            Assert.Equal(1, await db.SshCertificates.CountAsync(c => c.SshCaKeyId == ca.Id && c.IsRevoked && c.RevokedAt == null));
            Assert.Equal(all, (await service.BuildKrlAsync(ca.Id)).State);
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
                var signed = await service.SignUserKeyAsync(key.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, ["permit-pty"], Actor);
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

    private static UserEntity NewUser(string username)
        => new() { Id = Guid.NewGuid(), Username = username, Email = $"{username}@example.test", PasswordHash = "x" };

    private const string GrantColumns = "\"Id\",\"SshCaKeyId\",\"LoginName\",\"UserId\",\"GroupId\",\"CreatedAt\"";

    private static string GrantRow(Guid key, string name, Guid? user, Guid? group)
        => $"('{Guid.NewGuid()}','{key}','{name}',{(user is Guid u ? $"'{u}'" : "NULL")},{(group is Guid g ? $"'{g}'" : "NULL")},now())";

    /// <summary>
    /// The schema of login name grants (<c>docs/architecture/ssh-login-names.md</c>, "The
    /// tables"), which the in-memory provider does not have: a grant names a user or a group and
    /// never both or neither, and one target has a name once per key. Names differ by case.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_login_name_grant_names_exactly_one_target_and_a_target_has_a_name_once_per_key() =>
        OnPostgresAsync(async (open, service, _) =>
        {
            var ca = await service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, false, 48, actor: Actor);
            var lab = await service.GenerateKeyPairAsync("Lab SSH", "ed25519", true, false, 48, actor: Actor);
            var alice = NewUser("alice");
            var ops = new CaGroupEntity { Id = Guid.NewGuid(), Name = "web-ops", DisplayName = "Web operators", SpaceId = null };
            await using (var seed = open())
            {
                seed.Users.Add(alice);
                seed.CaGroups.Add(ops);
                await seed.SaveChangesAsync();
            }

            await using var db = open();
            Task Insert(string row) => PostgresUpgradeHarnessTests.ExecAsync(db, $"INSERT INTO \"SshLoginNameGrants\" ({GrantColumns}) VALUES {row};");
            async Task<string> RefusedAsync(string row) => (await Assert.ThrowsAsync<PostgresException>(() => Insert(row))).ConstraintName ?? string.Empty;

            Assert.Equal(SshLoginNameGrantConstraints.ExactlyOneTarget, await RefusedAsync(GrantRow(ca.Id, "root", null, null)));
            Assert.Equal(SshLoginNameGrantConstraints.ExactlyOneTarget, await RefusedAsync(GrantRow(ca.Id, "root", alice.Id, ops.Id)));

            await Insert(GrantRow(ca.Id, "root", alice.Id, null));
            await Insert(GrantRow(ca.Id, "root", null, ops.Id));
            await Insert(GrantRow(ca.Id, "Root", alice.Id, null));
            await Insert(GrantRow(lab.Id, "root", alice.Id, null));
            Assert.Equal("IX_SshLoginNameGrants_SshCaKeyId_LoginName_UserId", await RefusedAsync(GrantRow(ca.Id, "root", alice.Id, null)));
            Assert.Equal("IX_SshLoginNameGrants_SshCaKeyId_LoginName_GroupId", await RefusedAsync(GrantRow(ca.Id, "root", null, ops.Id)));
            Assert.Equal(4, await PostgresUpgradeHarnessTests.ScalarAsync(db, "SELECT count(*) FROM \"SshLoginNameGrants\""));

            // The service answers the same collision as a conflict, before the index has to.
            var names = SshServices.LoginNames(open(), new SshAuditLog());
            await Assert.ThrowsAsync<ResourceConflictException>(() => names.GrantAsync(ca.Id, new SshLoginNameGrantRequest(["deploy", "root"], null, ops.Id, null, null, null), Actor));
            Assert.Equal(4, await PostgresUpgradeHarnessTests.ScalarAsync(db, "SELECT count(*) FROM \"SshLoginNameGrants\""));
            Assert.Equal(128, await PostgresUpgradeHarnessTests.ScalarAsync(db,
                "SELECT character_maximum_length FROM information_schema.columns WHERE table_name = 'SshLoginNameGrants' AND column_name = 'LoginName'"));
            Assert.Equal(256, await PostgresUpgradeHarnessTests.ScalarAsync(db,
                "SELECT character_maximum_length FROM information_schema.columns WHERE table_name = 'SshLoginNameGrants' AND column_name = 'Note'"));
        });

    /// <summary>
    /// Deleting a user or a group deletes its grants; deleting whoever made a grant leaves the
    /// grant, with the name kept as text; and a certificate outlives its subject, with none.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task Deleting_a_user_or_a_group_removes_its_grants_and_leaves_the_certificates() =>
        OnPostgresAsync(async (open, service, _) =>
        {
            var ca = await service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, false, 48, actor: Actor);
            var alice = NewUser("alice");
            var bob = NewUser("bob");
            var edward = NewUser("edward");
            var ops = new CaGroupEntity { Id = Guid.NewGuid(), Name = "web-ops", DisplayName = "Web operators", SpaceId = null };
            await using (var seed = open())
            {
                var requesters = await seed.CaGroups.SingleAsync(g => g.Name == "fleet-ssh-user");
                seed.Users.AddRange(alice, bob, edward);
                seed.CaGroups.Add(ops);
                seed.CaGroupMembers.AddRange(
                    new CaGroupMemberEntity { GroupId = requesters.Id, UserId = alice.Id }, new CaGroupMemberEntity { GroupId = requesters.Id, UserId = bob.Id },
                    new CaGroupMemberEntity { GroupId = ops.Id, UserId = bob.Id });
                await seed.SaveChangesAsync();
            }
            var granter = new SshCaActor(edward.Id, "edward");
            var names = SshServices.LoginNames(open(), new SshAuditLog());
            await names.GrantAsync(ca.Id, new SshLoginNameGrantRequest(["root"], alice.Id, null, null, null, null), granter);
            await names.GrantAsync(ca.Id, new SshLoginNameGrantRequest(["root"], bob.Id, null, null, null, null), granter);
            await names.GrantAsync(ca.Id, new SshLoginNameGrantRequest(["deploy"], null, ops.Id, 8, null, null), granter);
            var certificate = await service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(alice.Id), ["alice", "root"], 1, null, Actor);
            var throughGroup = await service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(bob.Id), ["deploy"], null, null, Actor);
            Assert.Equal(TimeSpan.FromHours(8), throughGroup.ValidBefore - throughGroup.ValidAfter);

            await using var db = open();
            async Task<long> CountAsync(string where) => await PostgresUpgradeHarnessTests.ScalarAsync(db, $"SELECT count(*) FROM \"SshLoginNameGrants\" WHERE {where}");
            Assert.Equal(1, (await names.ListAsync(ca.Id))!.Grants.Single(g => g.User?.Id == alice.Id).LiveCertificates);
            Assert.Equal(1, (await names.ListAsync(ca.Id))!.Grants.Single(g => g.Group != null).Group!.MemberCount);

            // The granter goes: the grants stay, by name.
            await PostgresUpgradeHarnessTests.ExecAsync(db, $"DELETE FROM \"Users\" WHERE \"Id\" = '{edward.Id}';");
            Assert.Equal(3, await CountAsync("\"GrantedByUserId\" IS NULL AND \"GrantedByUsername\" = 'edward'"));

            // The user goes: their grant goes, the others stay, and the certificate stays with no subject.
            await PostgresUpgradeHarnessTests.ExecAsync(db, $"DELETE FROM \"Users\" WHERE \"Id\" = '{alice.Id}';");
            Assert.Equal(0, await CountAsync($"\"UserId\" = '{alice.Id}'"));
            Assert.Equal(2, await CountAsync("true"));
            Assert.Equal(1, await PostgresUpgradeHarnessTests.ScalarAsync(db,
                $"SELECT count(*) FROM \"SshCertificates\" WHERE \"Id\" = '{certificate.Id}' AND \"SubjectUserId\" IS NULL AND \"LoginNameGrounds\" IS NOT NULL"));

            // The group goes: its grant goes, and what is left is bob's own.
            await PostgresUpgradeHarnessTests.ExecAsync(db, $"DELETE FROM \"CaGroups\" WHERE \"Id\" = '{ops.Id}';");
            Assert.Equal(1, await CountAsync("true"));
            Assert.Equal(1, await CountAsync($"\"UserId\" = '{bob.Id}'"));

            // And the reconciliation sees what the database now says: bob no longer holds deploy.
            Assert.Equal(1, await SshServices.LoginNames(open(), new SshAuditLog()).ReconcileUsersAsync([bob.Id], "a group was deleted"));
            Assert.Equal(1, await PostgresUpgradeHarnessTests.ScalarAsync(db, $"SELECT count(*) FROM \"SshCertificates\" WHERE \"Id\" = '{throughGroup.Id}' AND \"IsRevoked\""));

            // The key goes: its grants go with it.
            await PostgresUpgradeHarnessTests.ExecAsync(db, $"DELETE FROM \"SshCertificates\"; DELETE FROM \"SshSigningProfiles\"; DELETE FROM \"SshCaKeys\" WHERE \"Id\" = '{ca.Id}';");
            Assert.Equal(0, await CountAsync("true"));
        });

    /// <summary>
    /// The periodic sweep (<c>docs/architecture/ssh-login-names.md</c>, "The sweep") over
    /// PostgreSQL, where the foreign key takes the subject off a deleted user's certificate and
    /// the rules run as SQL. Each change is made straight in the database, as a node that stopped
    /// before its hook ran leaves it.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_sweep_revokes_what_a_change_made_past_the_hooks_left_live() =>
        OnPostgresAsync(async (open, service, _) =>
        {
            var ca = await service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, true, 48, actor: Actor);
            var alice = NewUser("alice");
            var bob = NewUser("bob");
            var carol = NewUser("carol");
            var dave = NewUser("dave");
            var erin = NewUser("erin");
            await using (var seed = open())
            {
                var requesters = await seed.CaGroups.SingleAsync(g => g.Name == "fleet-ssh-user");
                seed.Users.AddRange(alice, bob, carol, dave, erin);
                seed.CaGroupMembers.AddRange(new[] { alice, bob, carol, dave, erin }.Select(u => new CaGroupMemberEntity { GroupId = requesters.Id, UserId = u.Id }));
                await seed.SaveChangesAsync();
            }
            await SshServices.LoginNames(open(), new SshAuditLog())
                .GrantAsync(ca.Id, new SshLoginNameGrantRequest(["root"], carol.Id, null, null, null, null), Actor);
            Task<SshCertificateEntity> SignFor(UserEntity user, params string[] names)
                => service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(user.Id), names.ToList(), 1, null, Actor);
            var ofDeleted = await SignFor(alice, "alice");
            var ofDisabled = await SignFor(bob, "bob");
            var lostName = await SignFor(carol, "carol", "root");
            var held = await SignFor(dave, "dave");
            var ofNoRight = await SignFor(erin, "erin");
            var typed = await service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["root"], 1, null, Actor);
            var host = await service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["web01.example.com"], 1, Actor);

            await using var db = open();
            await PostgresUpgradeHarnessTests.ExecAsync(db,
                $"DELETE FROM \"Users\" WHERE \"Id\" = '{alice.Id}'; UPDATE \"Users\" SET \"IsActive\" = false WHERE \"Id\" = '{bob.Id}'; "
                + $"DELETE FROM \"SshLoginNameGrants\" WHERE \"UserId\" = '{carol.Id}'; DELETE FROM \"CaGroupMembers\" WHERE \"UserId\" = '{erin.Id}';");

            var audit = new SshAuditLog();
            var swept = await SshServices.LoginNames(open(), audit).SweepAsync();

            Assert.Equal(new SshLoginNameSweep(UserNotActive: 1, UserDeleted: 1, LoginNameLost: 1, RequestRightLost: 1), swept);
            async Task<bool> RevokedAsync(SshCertificateEntity certificate)
                => await PostgresUpgradeHarnessTests.ScalarAsync(db, $"SELECT count(*) FROM \"SshCertificates\" WHERE \"Id\" = '{certificate.Id}' AND \"IsRevoked\"") == 1;
            Assert.True(await RevokedAsync(ofDeleted));
            Assert.True(await RevokedAsync(ofDisabled));
            Assert.True(await RevokedAsync(lostName));
            Assert.True(await RevokedAsync(ofNoRight));
            Assert.False(await RevokedAsync(held));
            Assert.False(await RevokedAsync(typed));
            Assert.False(await RevokedAsync(host));
            Assert.Equal(4, audit.Entries.Count);

            Assert.Equal(0, (await SshServices.LoginNames(open(), audit).SweepAsync()).Total);
            Assert.Equal(4, audit.Entries.Count);
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
            await scenario(Open, SshServices.Ca(serviceDb, relay, new SshAuditLog()), relay);
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
