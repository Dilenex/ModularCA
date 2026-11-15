using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services.Continuity;
using ModularCA.Shared.Enums;
using ModularCA.Tests.TestUtils;
using Xunit;
using static ModularCA.Tests.Database.PostgresCaFixture;

namespace ModularCA.Tests.Database;

/// <summary>
/// The incarnation comparison on a real PostgreSQL database, for what the in-memory provider
/// cannot show: the floor reaches the counter the CRL service really allocates from, two nodes
/// starting together report one event behind the advisory lock, and the restore stores the
/// incarnation over a connection of its own. Opt-in through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresRollbackContinuityTests
{
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_changed_incarnation_raises_the_counters_the_crl_service_allocates_from()
        => WithDatabaseAsync("modularca_incarnation", async connection =>
        {
            await using var db = Open(connection);
            var ca = await SeedCaAsync(db, "incarnation-ca");
            var crls = Crls(db, connection, ca.Material);
            var audit = new RecordingAuditService();
            var a = IncarnationReading.From("injected", "a");
            var b = IncarnationReading.From("injected", "b");

            Assert.Equal(IncarnationCase.FirstSeen, (await InstanceContinuity.CheckIncarnationAsync(db, null, audit, a, DateTimeOffset.UtcNow, NullLogger.Instance)).Case);
            Assert.Equal(1, CrlNumberOf(ParseCrl(await crls.GenerateCrlAsync(ca.CaCertificateId))));

            var now = DateTimeOffset.UtcNow;
            var changed = await InstanceContinuity.CheckIncarnationAsync(db, null, audit, b, now, NullLogger.Instance);
            Assert.Equal(IncarnationCase.Changed, changed.Case);
            Assert.Single(changed.Raised);
            // The newest thing the database knew: the CRL it had just generated.
            Assert.NotNull(changed.Event!.EdgeOfMemoryUtc);

            // The first CRL after the change is numbered above the floor, so above anything the
            // lost timeline can have published.
            db.ChangeTracker.Clear();
            Assert.Equal(now.ToUnixTimeSeconds() + 1, CrlNumberOf(ParseCrl(await crls.GenerateCrlAsync(ca.CaCertificateId))));
            Assert.Equal(AuditActionType.InstanceIncarnationChanged, Assert.Single(audit.Entries).Action);
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task Two_nodes_starting_together_against_one_database_report_one_event()
        => WithDatabaseAsync("modularca_twonodes", async connection =>
        {
            await using (var seed = Open(connection))
            {
                await SeedCaAsync(seed, "two-node-ca");
                await InstanceContinuity.CheckIncarnationAsync(seed, null, new RecordingAuditService(), IncarnationReading.From("injected", "a"),
                    DateTimeOffset.UtcNow, NullLogger.Instance);
            }

            var b = IncarnationReading.From("injected", "b");
            var audit = new RecordingAuditService();
            async Task<IncarnationCase> Node()
            {
                await using var db = Open(connection);
                return (await InstanceContinuity.CheckIncarnationAsync(db, null, audit, b, DateTimeOffset.UtcNow, NullLogger.Instance)).Case;
            }

            var cases = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(Node)));

            Assert.Single(cases, c => c == IncarnationCase.Changed);
            Assert.Equal(5, cases.Count(c => c == IncarnationCase.Same));
            await using var check = Open(connection);
            Assert.Single(await check.InstanceContinuityEvents.AsNoTracking().ToListAsync());
            Assert.Single(await check.InstanceIncarnation.AsNoTracking().ToListAsync());
            Assert.Single(audit.Entries);
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task Two_nodes_first_starting_together_store_one_incarnation()
        => WithDatabaseAsync("modularca_firststart", async connection =>
        {
            var a = IncarnationReading.From("injected", "a");
            async Task<IncarnationCase> Node()
            {
                await using var db = Open(connection);
                return (await InstanceContinuity.CheckIncarnationAsync(db, null, new RecordingAuditService(), a, DateTimeOffset.UtcNow, NullLogger.Instance)).Case;
            }

            var cases = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(Node)));

            Assert.Single(cases, c => c == IncarnationCase.FirstSeen);
            Assert.Equal(5, cases.Count(c => c == IncarnationCase.Same));
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_restore_stores_the_incarnation_so_the_next_start_reports_nothing()
        => WithDatabaseAsync("modularca_restoreinc", async connection =>
        {
            var audit = new RecordingAuditService();
            var backupMachine = IncarnationReading.From("injected", "machine-of-the-backup");
            var thisMachine = IncarnationReading.From("injected", "machine-restored-onto");
            await using (var db = Open(connection))
            {
                await SeedCaAsync(db, "restore-ca");
                // The archive's database: it last saw the machine the backup was taken on.
                await InstanceContinuity.CheckIncarnationAsync(db, null, audit, backupMachine, DateTimeOffset.UtcNow, NullLogger.Instance);
            }

            // What --restore does once it has restored the database and raised the CRL numbers.
            Assert.True(await BackupRestore.StoreIncarnationAfterRestoreAsync(connection, thisMachine));

            await using var after = Open(connection);
            var stored = await after.InstanceIncarnation.AsNoTracking().SingleAsync();
            Assert.Equal(thisMachine.ValueHash, stored.ValueHash);
            Assert.Equal("restore", stored.RecordedBy);
            var next = await InstanceContinuity.CheckIncarnationAsync(after, null, audit, thisMachine, DateTimeOffset.UtcNow, NullLogger.Instance);
            Assert.Equal(IncarnationCase.Same, next.Case);
            Assert.Empty(await after.InstanceContinuityEvents.AsNoTracking().ToListAsync());
            Assert.Empty(audit.Entries);
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_restore_that_cannot_store_the_incarnation_says_so_and_does_not_fail()
    {
        // A database that is not there: the restore reports it and goes on.
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var missing = new Npgsql.NpgsqlConnectionStringBuilder(server) { Database = $"modularca_absent_{Guid.NewGuid():N}", Pooling = false }.ConnectionString;

        Assert.False(await BackupRestore.StoreIncarnationAfterRestoreAsync(missing, IncarnationReading.None));
    }
}
