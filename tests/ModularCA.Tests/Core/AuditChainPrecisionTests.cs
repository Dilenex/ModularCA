using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// Whether the audit hash chain survives being stored.
/// <para>
/// The chain is computed over <c>Timestamp.ToString("O")</c>, which renders seven fractional
/// digits — .NET ticks are 100 nanoseconds. Both MySQL's <c>datetime(6)</c> and PostgreSQL's
/// <c>timestamptz</c> keep six. So the hash is computed against a value with more precision than
/// the column it is about to be written to, and the seventh digit is gone by the time anything
/// reads the row back.
/// </para>
/// <para>
/// This never surfaced in the suite because the in-memory provider stores a .NET object and
/// truncates nothing, so every existing chain test round-trips a value the database never would.
/// </para>
/// </summary>
public class AuditChainPrecisionTests
{
    private static AuditLogEntity Entry(DateTime timestamp) => new()
    {
        Id = Guid.Parse("b0d8cbc5-b05b-477e-8468-8590c338a46f"),
        Timestamp = timestamp,
        ActorUsername = "admin",
        ActionType = "CertificateIssued",
        Success = true,
    };

    /// <summary>What a column with microsecond resolution gives back.</summary>
    private static DateTime AsStored(DateTime value) =>
        new(value.Ticks - (value.Ticks % 10), value.Kind);

    private static async Task<string> HashAsync(AuditLogEntity entry)
    {
        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseInMemoryDatabase($"chain-{Guid.NewGuid():N}")
            .Options;
        await using var db = new AuditDbContext(options);

        using (await new AuditHashChainService().AcquireAndComputeAsync(db, entry))
        {
        }

        return entry.RecordHash!;
    }

    [Fact]
    public async Task A_hash_computed_before_storage_does_not_survive_the_column()
    {
        // A timestamp whose seventh fractional digit is not zero — which is most of them, since
        // DateTime.UtcNow is read at tick resolution.
        var written = new DateTime(2026, 9, 19, 10, 59, 12, DateTimeKind.Utc).AddTicks(3_456_789);
        Assert.NotEqual(0, written.Ticks % 10);

        var hashedBeforeWriting = await HashAsync(Entry(written));
        var hashedAfterReading = await HashAsync(Entry(AsStored(written)));

        Assert.NotEqual(hashedBeforeWriting, hashedAfterReading);
    }

    [Fact]
    public async Task A_timestamp_the_column_can_hold_exactly_round_trips_intact()
    {
        // The other half: when the seventh digit is already zero there is nothing to lose, and
        // the chain verifies. That is why this is intermittent-looking rather than obviously
        // broken — a record written on a whole microsecond verifies fine.
        var written = new DateTime(2026, 9, 19, 10, 59, 12, DateTimeKind.Utc).AddTicks(3_456_780);
        Assert.Equal(0, written.Ticks % 10);

        Assert.Equal(
            await HashAsync(Entry(written)),
            await HashAsync(Entry(AsStored(written))));
    }

    [Fact]
    public async Task The_kind_of_the_timestamp_also_changes_the_hash()
    {
        // Recorded because it was the first suspect and is a real sharp edge, even though it is
        // not what broke here: "O" renders a trailing Z for UTC and nothing for Unspecified, and
        // no database stores which one it was. It only stays harmless while every reader labels
        // the value the same way the writer did.
        var instant = new DateTime(2026, 9, 19, 10, 59, 12, DateTimeKind.Utc);

        Assert.NotEqual(
            await HashAsync(Entry(instant)),
            await HashAsync(Entry(DateTime.SpecifyKind(instant, DateTimeKind.Unspecified))));
    }
}
