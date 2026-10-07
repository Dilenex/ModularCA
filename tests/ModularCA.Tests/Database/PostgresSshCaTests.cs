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
