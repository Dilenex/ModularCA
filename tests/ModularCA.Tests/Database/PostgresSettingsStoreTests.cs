using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Settings;
using ModularCA.Tests.Api;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The settings store against a real PostgreSQL database migrated to the latest migration. What
/// two writers do to each other can only be shown here: a write is one transaction on
/// PostgreSQL and a row-by-row save on the in-memory provider. Opt-in through
/// <c>MODULARCA_TEST_PG</c>, as <see cref="PostgresUpgradeHarnessTests"/>.
/// </summary>
[Trait("Category", "PostgreSQL")]
public class PostgresSettingsStoreTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    private static SettingsChange Set(string actor, string key, JsonNode? value) => new()
    {
        Set = new Dictionary<string, JsonNode?> { [key] = value },
        Actor = new SettingsActor(null, actor),
        Source = SettingsSource.Api,
    };

    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_migration_creates_tables_a_write_and_a_read_go_through() =>
        OnPostgresAsync(async open =>
        {
            var audit = new RecordingAuditService();
            await using (var db = open())
            {
                var result = await Store(db, audit).WriteAsync(new SettingsChange
                {
                    Set = new Dictionary<string, JsonNode?>
                    {
                        ["Acme_Http01_MaxAddresses"] = JsonValue.Create(8),
                        ["Scheduler_JobTimeouts"] = JsonNode.Parse("{\"Zeta\":5,\"Alpha\":9}"),
                    },
                    Actor = new SettingsActor(null, "alice"), Source = SettingsSource.Api, Reason = "first",
                });
                Assert.Equal(1, result.Revision);
            }

            await using var fresh = open();
            var snapshot = await Store(fresh, audit).LoadAsync();
            Assert.Equal(1, snapshot.Revision);
            Assert.Equal("8", snapshot.Settings["Acme_Http01_MaxAddresses"].ValueJson);
            Assert.Equal("{\"Alpha\":9,\"Zeta\":5}", snapshot.Settings["Scheduler_JobTimeouts"].ValueJson);
            Assert.Equal("first", Assert.Single(await Store(fresh, audit).HistoryAsync("Acme_Http01_MaxAddresses")).Reason);
        });

    /// <summary>Writes a competing change the first time it is asked to audit, which is between a write's read and its save.</summary>
    private sealed class RacingAudit(Func<ModularCADbContext> open, string key) : IAuditService
    {
        private bool _raced;
        public List<(string Action, string? TargetId, bool Success)> Entries { get; } = [];

        public async Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
        {
            Entries.Add((actionType, targetEntityId, success));
            if (_raced) return;
            _raced = true;
            await using var db = open();
            await Store(db, new RecordingAuditService()).WriteAsync(Set("bob", key, JsonValue.Create(3)));
        }
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public Task Two_writes_never_take_the_same_revision() =>
        OnPostgresAsync(async open =>
        {
            await using (var db = open())
                await Store(db, new RecordingAuditService()).WriteAsync(Set("alice", "Acme_Http01_MaxAddresses", JsonValue.Create(8)));

            // Bob changes another setting while Alice's write is between its read and its save.
            var racing = new RacingAudit(open, "Tokens_RefreshTokenDays");
            SettingsWriteResult result;
            await using (var db = open())
                result = await Store(db, racing).WriteAsync(Set("alice", "Acme_Http01_TimeoutSeconds", JsonValue.Create(20)));

            // Bob took revision 2. Alice's save failed whole, was tried again and took 3.
            Assert.Equal(3, result.Revision);
            Assert.Equal(
                [(AuditActionType.ConfigUpdated, "2", true), (AuditActionType.ConfigUpdateAborted, "2", false), (AuditActionType.ConfigUpdated, "3", true)],
                racing.Entries);

            await using var check = open();
            var snapshot = await Store(check, new RecordingAuditService()).LoadAsync();
            Assert.Equal(3, snapshot.Revision);
            Assert.Equal(2, snapshot.Settings["Tokens_RefreshTokenDays"].Revision);
            Assert.Equal((3L, 1), (snapshot.Settings["Acme_Http01_TimeoutSeconds"].Revision, snapshot.Settings["Acme_Http01_TimeoutSeconds"].Version));
            Assert.Equal(
                ["Acme_Http01_MaxAddresses@1", "Tokens_RefreshTokenDays@2", "Acme_Http01_TimeoutSeconds@3"],
                await check.SettingsHistory.OrderBy(h => h.Revision).Select(h => h.Key + "@" + h.Revision).ToListAsync());
        });

    /// <summary>The same setting written by both: the later writer finds it moved, when it said what it expected.</summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_write_that_lost_the_race_for_its_own_setting_is_refused_when_it_named_a_version() =>
        OnPostgresAsync(async open =>
        {
            var racing = new RacingAudit(open, "Tokens_RefreshTokenDays");
            await using var db = open();

            var refused = await Assert.ThrowsAsync<SettingsRefusedException>(() => Store(db, racing).WriteAsync(new SettingsChange
            {
                Set = new Dictionary<string, JsonNode?> { ["Tokens_RefreshTokenDays"] = JsonValue.Create(14) },
                ExpectedVersions = new Dictionary<string, int> { ["Tokens_RefreshTokenDays"] = 0 },
                Actor = new SettingsActor(null, "alice"), Source = SettingsSource.Api,
            }));

            Assert.Equal(SettingsRefusal.VersionConflict, refused.Reason);
            await using var check = open();
            var stored = (await Store(check, new RecordingAuditService()).LoadAsync()).Settings["Tokens_RefreshTokenDays"];
            Assert.Equal(("3", 1, "bob"), (stored.ValueJson, stored.Version, stored.ActorName));
        });

    private static SettingsStore Store(ModularCADbContext db, IAuditService audit) =>
        new(db, audit, NullLogger<SettingsStore>.Instance);

    /// <summary>
    /// Creates a database on the <c>MODULARCA_TEST_PG</c> server, applies every application
    /// migration, runs <paramref name="scenario"/> with a way to open contexts over it, and drops
    /// it, whatever the outcome.
    /// </summary>
    private static async Task OnPostgresAsync(Func<Func<ModularCADbContext>, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = $"modularca_settings_{Guid.NewGuid():N}"[..32];
        await ExecAsync(server, $"CREATE DATABASE \"{name}\"");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            ModularCADbContext Open() => new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
            await using (var db = Open())
                await db.Database.MigrateAsync();
            await scenario(Open);
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
