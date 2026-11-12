using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Concurrent decisions on one ceremony against a real PostgreSQL database, where the
/// <c>xmin</c> concurrency token on <see cref="KeyCeremonyEntity"/> is enforced (the in-memory
/// provider ignores it). Key ceremonies and controlled-user ceremonies are the same rows and go
/// through the same <see cref="KeyCeremonyService"/> decisions, so each case runs for both. Each
/// race is interleaved by hand: the second decision's context reads the ceremony first, the first
/// decision then runs to completion, and only then does the second decide on what it read, as a
/// request that read before the other committed would. The loser's
/// <see cref="DbUpdateConcurrencyException"/> is what the API answers 409. Opt-in through
/// <c>MODULARCA_TEST_PG</c>, as <see cref="PostgresLifecycleQueryTests"/>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Six)]
public class PostgresCeremonyRaceTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    private static readonly Guid Initiator = Guid.NewGuid();
    private static readonly Guid Alice = Guid.NewGuid();
    private static readonly Guid Bob = Guid.NewGuid();

    public static TheoryData<string, bool> Decisions => new()
    {
        { "RevokeCa", false },
        { "RevokeCa", true },
        { "ControlledUserChange", false },
        { "ControlledUserChange", true },
    };

    /// <summary>
    /// An approval that reaches the quorum and a rejection that both read the ceremony as Pending:
    /// whichever saves first decides it, the other is refused with a concurrency conflict, and the
    /// stored ceremony carries only the winner's decision.
    /// </summary>
    [RequiresEnvironmentTheory(ServerVariable)]
    [MemberData(nameof(Decisions))]
    public Task An_approval_and_a_rejection_that_race_leave_one_outcome(string operationType, bool rejectionFirst) =>
        OnPostgresAsync(async open =>
        {
            var id = await SeedAsync(open, operationType, requiredApprovals: 1);

            await using var winnerDb = open();
            await using var loserDb = open();
            await loserDb.KeyCeremonies.FindAsync(id);

            var winner = new KeyCeremonyService(winnerDb, new RecordingAuditService());
            var loser = new KeyCeremonyService(loserDb, new RecordingAuditService());
            if (rejectionFirst)
            {
                await winner.RejectAsync(id, Bob, "bob");
                await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => loser.ApproveAsync(id, Alice, "alice"));
            }
            else
            {
                await winner.ApproveAsync(id, Alice, "alice");
                await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => loser.RejectAsync(id, Bob, "bob"));
            }

            await using var check = open();
            var stored = await check.KeyCeremonies.AsNoTracking().SingleAsync(c => c.Id == id);
            var decision = Assert.Single(Approvals(stored));
            Assert.Equal(rejectionFirst ? "Rejected" : "Approved", stored.Status);
            Assert.Equal(rejectionFirst ? (Bob, "Rejected") : (Alice, "Approved"), (decision.UserId, decision.Decision));
            Assert.Equal(rejectionFirst ? 0 : 1, stored.CurrentApprovals);
        });

    /// <summary>
    /// Two approvals of a ceremony needing two, both read before either saved: the second does not
    /// overwrite the first's approval with a list that lacks it (which would leave the ceremony one
    /// approval short, or past the quorum on a count that misses an approver); it is refused, and
    /// once retried both approvals are counted and the ceremony is Approved.
    /// </summary>
    [RequiresEnvironmentTheory(ServerVariable)]
    [InlineData("RevokeCa")]
    [InlineData("ControlledUserChange")]
    public Task Two_approvals_that_race_are_both_counted(string operationType) =>
        OnPostgresAsync(async open =>
        {
            var id = await SeedAsync(open, operationType, requiredApprovals: 2);

            await using (var firstDb = open())
            await using (var staleDb = open())
            {
                await staleDb.KeyCeremonies.FindAsync(id);
                var first = await new KeyCeremonyService(firstDb, new RecordingAuditService()).ApproveAsync(id, Alice, "alice");
                Assert.Equal("Pending", first.Status);
                await Assert.ThrowsAsync<DbUpdateConcurrencyException>(
                    () => new KeyCeremonyService(staleDb, new RecordingAuditService()).ApproveAsync(id, Bob, "bob"));
            }

            await using (var retryDb = open())
                await new KeyCeremonyService(retryDb, new RecordingAuditService()).ApproveAsync(id, Bob, "bob");

            await using var check = open();
            var stored = await check.KeyCeremonies.AsNoTracking().SingleAsync(c => c.Id == id);
            Assert.Equal("Approved", stored.Status);
            Assert.Equal(2, stored.CurrentApprovals);
            Assert.Equal([Alice, Bob], Approvals(stored).Select(a => a.UserId).ToArray());
        });

    private static List<ApprovalRecord> Approvals(KeyCeremonyEntity ceremony)
        => JsonSerializer.Deserialize<List<ApprovalRecord>>(ceremony.ApprovalsJson, SafeJsonOptions.Stored) ?? [];

    /// <summary>Stores a pending ceremony of <paramref name="operationType"/> opened by <see cref="Initiator"/>.</summary>
    private static async Task<Guid> SeedAsync(Func<ModularCADbContext> open, string operationType, int requiredApprovals)
    {
        var ceremony = new KeyCeremonyEntity
        {
            OperationType = operationType,
            Description = "race",
            TargetEntityId = Guid.NewGuid().ToString(),
            InitiatedByUserId = Initiator,
            InitiatedByUsername = "initiator",
            RequiredApprovals = requiredApprovals,
            Status = "Pending",
            ExpiresAt = DateTime.UtcNow.AddHours(24),
        };
        await using var db = open();
        db.KeyCeremonies.Add(ceremony);
        await db.SaveChangesAsync();
        return ceremony.Id;
    }

    /// <summary>
    /// Copies the run's migrated template to a new database on the <c>MODULARCA_TEST_PG</c> server (every application
    /// migration applied), runs <paramref name="scenario"/> with a way to open contexts over it, and drops
    /// it, whatever the outcome.
    /// </summary>
    private static async Task OnPostgresAsync(Func<Func<ModularCADbContext>, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, "modularca_ceremony");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            ModularCADbContext Open() => new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
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
