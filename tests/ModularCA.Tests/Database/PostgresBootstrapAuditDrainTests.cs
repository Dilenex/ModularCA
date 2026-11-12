using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The bootstrap's audit drain against PostgreSQL, in the layout a new install has: the records
/// are written as the audit runtime role, on the hash chain, and the lookup that keeps a second
/// replay from writing them again runs on the real provider. Opt-in through
/// <c>MODULARCA_TEST_PG</c>.
/// </summary>
/// <remarks>
/// It points <see cref="BootstrapAuditLog.LogDirectory"/>, which is one for the process, at a
/// directory of its own, as the classes of <see cref="BootstrapAuditLogCollection"/> do. It is
/// not in that collection but in a PostgreSQL lane: the lanes start only after every other
/// parallel collection has finished (<see cref="PhasedTestFramework"/>), so it never runs beside
/// those classes, and no other PostgreSQL test writes the bootstrap audit log.
/// </remarks>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Six)]
public sealed class PostgresBootstrapAuditDrainTests : IDisposable
{
    private const string ServerVariable = "MODULARCA_TEST_PG";
    private readonly string _logs = Path.Combine(Path.GetTempPath(), $"mca-audit-drain-pg-{Guid.NewGuid():N}");

    public PostgresBootstrapAuditDrainTests() => BootstrapAuditLog.LogDirectory = _logs;

    public void Dispose()
    {
        BootstrapAuditLog.LogDirectory = null;
        if (Directory.Exists(_logs))
            Directory.Delete(_logs, recursive: true);
    }

    [RequiresEnvironmentTheory(ServerVariable)]
    [InlineData(OwnershipLayout.Fresh)]
    public async Task The_drain_writes_as_the_audit_role_and_a_second_replay_writes_nothing(OwnershipLayout layout)
    {
        await using var f = await OwnershipFixture.CreateAsync(Environment.GetEnvironmentVariable(ServerVariable)!, layout);
        AuditDbContext AuditDb() => new(new DbContextOptionsBuilder<AuditDbContext>()
            .UseNpgsql(f.RuntimeConnectionString(f.Audit, f.AuditDatabase)).Options);

        BootstrapAuditLog.LogKeystoreWrite("ca-certs.keystore", AuditActionType.KeystoreKeyAdded, "CN=System Signing CA", "abcd");
        BootstrapAuditLog.LogSetupDecision(AuditActionType.SecurityPolicyUpdated, "SecurityPolicy", "instance",
            new { SetupChoice = "MultipleAdministrators", MultipleAdministrators = false });
        var output = new StringWriter();

        Assert.True(await BootstrapAuditDrain.RunAsync(AuditDb, output), output.ToString());
        Assert.Contains("2 setup record(s) written to the audit trail", output.ToString());

        await using var auditDb = AuditDb();
        var rows = await auditDb.AuditLogs.AsNoTracking()
            .Where(r => r.ActorUsername == BootstrapAuditReplayService.Actor).OrderBy(r => r.Timestamp).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.False(string.IsNullOrEmpty(r.RecordHash)));
        Assert.Contains(rows, r => r.ActionType == AuditActionType.KeystoreKeyAdded && r.TargetEntityId == "ca-certs.keystore");
        Assert.Contains(rows, r => r.ActionType == AuditActionType.SecurityPolicyUpdated && r.TargetEntityId == "instance");
        var chain = await new AuditHashChainService().VerifyAsync(auditDb, null);
        Assert.Empty(chain.Breaks);

        // The file comes back (its rename did not hold): the node's replay finds both lines recorded.
        var replayed = Assert.Single(Directory.GetFiles(_logs, "*.replayed"));
        File.Move(replayed, replayed[..^".replayed".Length]);
        var again = await new BootstrapAuditReplayService(
            new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService()),
            NullLogger<BootstrapAuditReplayService>.Instance, auditDb).ReplayPendingAsync(_logs);

        Assert.Empty(again.Failures);
        Assert.Equal((1, 0, 2), (again.FilesReplayed, again.Recorded, again.AlreadyRecorded));
        Assert.Equal(2, await auditDb.AuditLogs.CountAsync(r => r.ActorUsername == BootstrapAuditReplayService.Actor));
    }

    /// <summary>
    /// A remote signer's keystore events on the real provider: written as the audit runtime
    /// role, on the hash chain in the journal's order, each looked up after it is logged, and a
    /// second delivery of the same events writes nothing.
    /// </summary>
    [RequiresEnvironmentTheory(ServerVariable)]
    [InlineData(OwnershipLayout.Fresh)]
    public async Task A_signers_keystore_events_are_written_as_the_audit_role_in_order_and_not_twice(OwnershipLayout layout)
    {
        await using var f = await OwnershipFixture.CreateAsync(Environment.GetEnvironmentVariable(ServerVariable)!, layout);
        await using var auditDb = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
            .UseNpgsql(f.RuntimeConnectionString(f.Audit, f.AuditDatabase)).Options);
        var replay = new BootstrapAuditReplayService(
            new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService()),
            NullLogger<BootstrapAuditReplayService>.Instance, auditDb);
        ModularCA.Shared.Signing.SignerJournalEntry[] events =
        [
            new("keystore-audit-20261109.jsonl", 0, "{\"timestamp\":\"2026-11-09T08:00:00Z\",\"action\":\"KeystoreLoaded\",\"keystoreName\":\"ca-certs.keystore\",\"success\":true,\"detail\":\"entries=4 format=v4\"}"),
            new("keystore-audit-20261109.jsonl", 1, "{\"timestamp\":\"2026-11-09T08:00:01Z\",\"action\":\"KeystoreAppended\",\"keystoreName\":\"ca-certs.keystore\",\"success\":true,\"detail\":\"added=1 total=5\"}"),
            new("keystore-audit-20261110.jsonl", 0, "{\"timestamp\":\"2026-11-10T08:00:00Z\",\"action\":\"KeystoreSignatureFailed\",\"keystoreName\":\"ca-trust.keystore\",\"success\":false,\"detail\":\"File signature is invalid\"}"),
        ];

        var first = await replay.RecordSignerEventsAsync(events);

        Assert.Null(first.Failure);
        Assert.Equal((3, 0), (first.Written, first.Skipped));
        Assert.Equal(events[2], first.Last);
        var rows = await auditDb.AuditLogs.AsNoTracking()
            .Where(r => r.ActorUsername == BootstrapAuditReplayService.SignerActor).OrderBy(r => r.Timestamp).ToListAsync();
        Assert.Equal(
            [AuditActionType.KeystoreLoaded, AuditActionType.KeystoreAppended, AuditActionType.KeystoreSignatureFailed],
            rows.Select(r => r.ActionType));
        Assert.All(rows, r => Assert.Contains("\"DeliveredBySigner\":true", r.DetailsJson));
        Assert.False(rows[2].Success);
        Assert.Empty((await new AuditHashChainService().VerifyAsync(auditDb, null)).Breaks);

        var again = await replay.RecordSignerEventsAsync(events);
        Assert.Equal((0, 3), (again.Written, again.Skipped));
        Assert.Equal(3, await auditDb.AuditLogs.CountAsync(r => r.ActorUsername == BootstrapAuditReplayService.SignerActor));
        Assert.Equal(0, await auditDb.AuditLogs.CountAsync(r => r.ActorUsername == BootstrapAuditReplayService.Actor));
    }
}
