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
