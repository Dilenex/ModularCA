using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Tests.Core.Services.Acme;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// An EAB key binds one ACME account when several new-account requests present it at once, on a
/// real PostgreSQL database migrated to the latest migration, each request with its own context
/// and connection as in production. The deterministic interleaving is shown on SQLite by
/// <see cref="AcmeEabSingleUseTests"/>. Opt-in through <c>MODULARCA_TEST_PG</c>, as
/// <see cref="PostgresUpgradeHarnessTests"/>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresAcmeEabTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";
    private const int Requests = 12;

    /// <summary>
    /// The finding: concurrent new-account requests with the same EAB key, each for its own account
    /// key, all passed the unused check and all got an account. Exactly one does now; the rest are
    /// refused with <c>unauthorized</c>, and the key names the one account created.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Concurrent_new_accounts_with_one_eab_key_create_one_account()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, "modularca_eab");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, MaxPoolSize = Requests + 4 }.ConnectionString;
            ModularCADbContext Open() => new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);

            ModularCA.Shared.Entities.CertificateAuthorityEntity ca;
            byte[] hmac;
            await using (var db = Open())
            {
                ca = await AcmeEabHarness.SeedCaAsync(db);
                hmac = await AcmeEabHarness.SeedEabKeyAsync(db, "eab-race");
            }

            var keys = Enumerable.Range(0, Requests).Select(_ => AcmeEabHarness.NewKey()).ToList();
            using var start = new Barrier(Requests);
            var statuses = await Task.WhenAll(keys.Select(key => Task.Run(async () =>
            {
                await using var db = Open();
                await db.Database.OpenConnectionAsync();
                start.SignalAndWait();
                var result = await AcmeEabHarness.NewAccountAsync(db, ca, key.Jwk, key.Thumbprint,
                    AcmeEabHarness.Binding(hmac, "eab-race", key.Jwk));
                return result.StatusCode;
            })));

            Assert.Equal(1, statuses.Count(s => s == 201));
            Assert.Equal(Requests - 1, statuses.Count(s => s == 403));
            await using var read = Open();
            var account = await read.AcmeAccounts.SingleAsync();
            var eab = await read.AcmeEabKeys.SingleAsync();
            Assert.True(eab.IsUsed);
            Assert.Equal(account.Id, eab.UsedByAccountId);

            // The one claim that won queued one fact for the signer's journal, in a statement of
            // its own beside the bulk update: the binding was spent, by its row id.
            var fact = await read.SignerFacts.SingleAsync();
            Assert.Equal(ModularCA.Journal.RecordType.SpentWithoutCertificate, fact.Type);
            var spent = ModularCA.Journal.SpentWithoutCertificatePayload.Decode(fact.Payload);
            Assert.Equal((ModularCA.Journal.TokenKind.AcmeExternalAccountBinding, eab.Id.ToString("D")), (spent.Kind, spent.Id));

            // A restore leaves its marker in the same queue, and the queue is handed to the signer in order.
            Assert.True(await ModularCA.Bootstrap.BackupRestore.QueueRestoreMarkerAsync(connection, "modularca-backup-test.enc",
                "{\"Version\":\"1.0\",\"Timestamp\":\"2026-11-12T01:00:07Z\",\"InstanceId\":\"" + new string('9', 64) + "\"}"));
            using var sandbox = new ModularCA.Tests.Journal.JournalSandbox();
            await using var journal = new ModularCA.Keystore.Signing.SignerJournal(() => sandbox.Options(),
                new ModularCA.Keystore.Signing.SignerJournalSettings(sandbox.Home, true, "test", new byte[32]), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
            var world = ModularCA.Tests.Signer.SignerTestWorld.Create();
            var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);
            await using (var drain = Open())
                Assert.Equal(2, await ModularCA.Core.Services.Journal.SignerFactDrain.DrainOnceAsync(drain, signer, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance));
            await using (var after = Open())
                Assert.Empty(await after.SignerFacts.ToListAsync());
            var asserted = sandbox.Records().Where(r => r.Record.NodeAsserted).Select(r => r.Record).ToList();
            Assert.Equal(new[] { ModularCA.Journal.RecordType.SpentWithoutCertificate, ModularCA.Journal.RecordType.RestoreMarker }, asserted.Select(r => r.Type));
            Assert.Equal("modularca-backup-test.enc", ModularCA.Journal.RestoreMarkerPayload.Decode(asserted[1].Payload).Archive);
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
