using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services.Settings;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;
using static ModularCA.Tests.Database.PostgresCaFixture;

namespace ModularCA.Tests.Database;

/// <summary>
/// The instance's identifier on a real PostgreSQL database, where the statements that write and
/// read it run: the first start stores the fingerprint the instance has then, no later start
/// replaces it whatever the fingerprint has become, nodes starting together end with one value,
/// and the reader a backup's manifest and <c>hello</c> share gives the stored value. Opt-in
/// through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresInstanceIdentityTests
{
    private const string First = "9f2c4a1b8e7d6350f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708";
    private const string Rekeyed = "00aa11bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899";

    /// <summary>Pins every keystore row to <paramref name="spki"/>, adding the two rows an install has when there are none.</summary>
    private static async Task PinAsync(string connection, string? spki)
    {
        await using var db = Open(connection);
        if (!await db.Keystores.AnyAsync())
        {
            foreach (var name in new[] { "ca-certs.keystore", "ssh.keystore" })
                db.Keystores.Add(new KeystoreEntryEntity { Name = name, Salt = string.Empty, CreatedAt = DateTime.UtcNow, Enabled = true });
        }
        await db.SaveChangesAsync();
        await db.Keystores.ExecuteUpdateAsync(k => k.SetProperty(r => r.SigningCaSpkiSha256, spki));
    }

    private static async Task<List<SettingEntity>> RowsAsync(string connection)
    {
        await using var db = Open(connection);
        return await db.Settings.AsNoTracking().Where(s => s.Key == InstanceIdentity.Key).ToListAsync();
    }

    private static async Task ExecuteAsync(string connection, string sql)
    {
        await using var conn = new NpgsqlConnection(connection);
        await conn.OpenAsync();
        await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_first_start_stores_the_fingerprint_the_instance_has_then()
        => WithDatabaseAsync("modularca_instanceid", async connection =>
        {
            // The pin as bootstrap writes it is lower case already; one written otherwise is stored as the manifest always gave it.
            await PinAsync(connection, First.ToUpperInvariant());

            // Before the start: nothing is stored, and the one reader gives the derived fingerprint.
            Assert.Equal(new InstanceIdReading(First, false), await InstanceIdentity.ReadAsync(connection));
            Assert.Equal(First, await BackupRestore.ReadInstanceIdAsync(connection));
            Assert.Empty(await RowsAsync(connection));

            var result = await InstanceIdentity.EnsureStoredAsync(connection);

            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.StoredNow, First, First), result);
            var row = Assert.Single(await RowsAsync(connection));
            Assert.Equal($"\"{First}\"", row.ValueJson);
            Assert.Equal(1, row.Version);
            Assert.Equal(SettingsSource.Startup, row.Source);
            Assert.Equal(InstanceIdentity.StartActor, row.ActorName);
            Assert.Equal(new InstanceIdReading(First, true), await InstanceIdentity.ReadAsync(connection));
            Assert.Equal(First, await BackupRestore.ReadInstanceIdAsync(connection));
            // It is not a change to a setting: no revision was taken and the settings are not marked as moved by it.
            await using var db = Open(connection);
            Assert.Empty(await db.SettingsHistory.AsNoTracking().ToListAsync());
            Assert.False(await db.SettingsState.AsNoTracking().AnyAsync(s => s.Revision != 0 || s.ImportedAt != null));
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_later_start_with_a_re_keyed_system_ca_keeps_the_stored_identifier()
        => WithDatabaseAsync("modularca_instanceid", async connection =>
        {
            await PinAsync(connection, First);
            await InstanceIdentity.EnsureStoredAsync(connection);
            var before = Assert.Single(await RowsAsync(connection));

            // The system signing CA is re-keyed: every keystore row is pinned to the new key.
            await PinAsync(connection, Rekeyed);
            var later = await InstanceIdentity.EnsureStoredAsync(connection);
            var again = await InstanceIdentity.EnsureStoredAsync(connection);

            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.AlreadyStored, First, Rekeyed), later);
            Assert.Equal(later, again);
            var after = Assert.Single(await RowsAsync(connection));
            Assert.Equal(before.ValueJson, after.ValueJson);
            Assert.Equal(before.UpdatedAt, after.UpdatedAt);
            Assert.Equal(1, after.Version);
            // What a backup taken now writes into its manifest, and what hello answers: the stored one.
            Assert.Equal(First, await BackupRestore.ReadInstanceIdAsync(connection));
            Assert.Equal(new InstanceIdReading(First, true), await InstanceIdentity.ReadAsync(connection));

            // And with the pins gone altogether.
            await PinAsync(connection, null);
            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.AlreadyStored, First, null), await InstanceIdentity.EnsureStoredAsync(connection));
            Assert.Equal(First, await BackupRestore.ReadInstanceIdAsync(connection));
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task Nodes_starting_together_end_with_one_identifier()
        => WithDatabaseAsync("modularca_instanceid", async connection =>
        {
            await PinAsync(connection, First);
            // The fingerprint changes under the starting nodes, so they do not all derive the same
            // one: whichever insert is first decides, and every node reads that value.
            using var stop = new CancellationTokenSource();
            var flipping = Task.Run(async () =>
            {
                for (var i = 0; !stop.IsCancellationRequested; i++)
                    await PinAsync(connection, i % 2 == 0 ? Rekeyed : First);
            });

            var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => InstanceIdentity.EnsureStoredAsync(connection))));
            stop.Cancel();
            await flipping;

            Assert.Single(results, r => r.Case == InstanceIdStoreCase.StoredNow);
            Assert.Equal(11, results.Count(r => r.Case == InstanceIdStoreCase.AlreadyStored));
            var id = Assert.Single(results.Select(r => r.Id).Distinct());
            Assert.Contains(id, new[] { First, Rekeyed });
            Assert.Equal($"\"{id}\"", Assert.Single(await RowsAsync(connection)).ValueJson);
            Assert.Equal(id, (await InstanceIdentity.ReadAsync(connection)).Id);
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task With_no_fingerprint_nothing_is_stored_and_a_later_start_stores_it()
        => WithDatabaseAsync("modularca_instanceid", async connection =>
        {
            // No keystore row at all, then rows from before the pin.
            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.NothingToStore, null, null), await InstanceIdentity.EnsureStoredAsync(connection));
            await PinAsync(connection, null);
            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.NothingToStore, null, null), await InstanceIdentity.EnsureStoredAsync(connection));
            await PinAsync(connection, "");
            Assert.Equal(InstanceIdStoreCase.NothingToStore, (await InstanceIdentity.EnsureStoredAsync(connection)).Case);
            // A pin that is not a SHA-256 in hex is not made the identifier.
            await PinAsync(connection, "not-a-fingerprint");
            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.NothingToStore, null, "not-a-fingerprint"), await InstanceIdentity.EnsureStoredAsync(connection));

            Assert.Empty(await RowsAsync(connection));
            await PinAsync(connection, null);
            Assert.Equal(new InstanceIdReading(null, false), await InstanceIdentity.ReadAsync(connection));
            Assert.Null(await BackupRestore.ReadInstanceIdAsync(connection));

            // The pins are backfilled; the next start stores the identifier.
            await PinAsync(connection, First);
            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.StoredNow, First, First), await InstanceIdentity.EnsureStoredAsync(connection));
            Assert.Equal(new InstanceIdReading(First, true), await InstanceIdentity.ReadAsync(connection));
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_settings_store_cannot_change_it_and_the_move_out_of_the_file_leaves_it()
        => WithDatabaseAsync("modularca_instanceid", async connection =>
        {
            await PinAsync(connection, First);
            await InstanceIdentity.EnsureStoredAsync(connection);
            var audit = new RecordingAuditService();
            SettingsStore Store() => new(Open(connection), audit, new NoSecretsSigner(), NullLogger<SettingsStore>.Instance);
            var actor = new SettingsActor(null, "alice");

            foreach (var change in new[]
                     {
                         new SettingsChange { Set = new Dictionary<string, JsonNode?> { [InstanceIdentity.Key] = JsonValue.Create(Rekeyed) }, Actor = actor, Source = SettingsSource.Api },
                         new SettingsChange { Clear = [InstanceIdentity.Key], Actor = actor, Source = SettingsSource.Cli },
                         new SettingsChange { Set = new Dictionary<string, JsonNode?> { [InstanceIdentity.Key] = JsonValue.Create(First) }, Actor = actor, Source = SettingsSource.Import },
                     })
            {
                var refusal = await Assert.ThrowsAsync<SettingsRefusedException>(() => Store().WriteAsync(change));
                Assert.Equal(SettingsRefusal.WrittenOnce, refusal.Reason);
            }
            Assert.Empty(audit.Entries);

            // The control role's settings step on a database that already holds the identifier:
            // the settings move, a save follows, and the row is as the first start left it.
            var directory = Path.Combine(Path.GetTempPath(), $"mca-instance-id-pg-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            try
            {
                var path = Path.Combine(directory, "config.yaml");
                var config = new SystemConfig();
                config.Acme.Http01.MaxAddresses = 8;
                ConfigYamlWriter.Write(path, config);
                var persistence = new SettingsPersistence(config, new EnvVarConfigOverlay(), path);

                var start = await SettingsRuntime.StartAsync(Store(), config, persistence, new HashSet<string>(), mayMove: true);
                Assert.True(start.Import!.Ran);
                Assert.Empty(start.Load.Problems);
                config.Acme.Http01.MaxAddresses = 9;
                await persistence.SaveAsync(Store(), actor);

                Assert.True(persistence.StoreInUse);
                Assert.DoesNotContain(First, File.ReadAllText(path));
                Assert.DoesNotMatch(@"(?mi)^\s*Instance(Id)?\s*:", File.ReadAllText(path));
            }
            finally
            {
                try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
            }

            var row = Assert.Single(await RowsAsync(connection));
            Assert.Equal($"\"{First}\"", row.ValueJson);
            Assert.Equal(1, row.Version);
            Assert.Equal(SettingsSource.Startup, row.Source);
            Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.AlreadyStored, First, First), await InstanceIdentity.EnsureStoredAsync(connection));
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_stored_row_that_holds_nothing_usable_is_not_known_and_is_never_replaced()
        => WithDatabaseAsync("modularca_instanceid", async connection =>
        {
            await PinAsync(connection, First);
            foreach (var value in new[] { "NULL", "'\"\"'", "'42'", "'not json'" })
            {
                await ExecuteAsync(connection, "DELETE FROM \"Settings\" WHERE \"Key\" = 'Instance_Id'");
                await ExecuteAsync(connection, "INSERT INTO \"Settings\" (\"Key\", \"ValueJson\", \"Version\", \"Revision\", \"UpdatedAt\", \"ActorName\", \"Source\") "
                    + $"VALUES ('Instance_Id', {value}, 1, 0, now(), 'someone', 'Api')");

                // Not the derived fingerprint in its place: that could be a different instance's answer.
                Assert.Equal(new InstanceIdReading(null, true), await InstanceIdentity.ReadAsync(connection));
                Assert.Null(await BackupRestore.ReadInstanceIdAsync(connection));
                Assert.Equal(new InstanceIdStoreResult(InstanceIdStoreCase.Unusable, null, First), await InstanceIdentity.EnsureStoredAsync(connection));
                Assert.Equal("someone", Assert.Single(await RowsAsync(connection)).ActorName);
            }
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_database_from_before_the_settings_store_and_one_that_cannot_be_reached()
        => WithDatabaseAsync("modularca_instanceid", async connection =>
        {
            await PinAsync(connection, First);
            // A host command (a backup) over a database no build with a settings store has migrated.
            await ExecuteAsync(connection, "DROP TABLE \"Settings\"");
            Assert.Equal(new InstanceIdReading(First, false), await InstanceIdentity.ReadAsync(connection));

            // A database that is not there: not known, and no exception for the caller to handle.
            var missing = new NpgsqlConnectionStringBuilder(connection) { Database = "modularca_no_such_database_" + Guid.NewGuid().ToString("N"), Timeout = 5 }.ConnectionString;
            Assert.Equal(new InstanceIdReading(null, false), await InstanceIdentity.ReadAsync(missing));
            Assert.Null(await BackupRestore.ReadInstanceIdAsync(missing));
        });
}
