using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// Whether the audit hash chain survives being stored.
/// <para>
/// It did not. The chain hashed <c>Timestamp.ToString("O")</c>, which renders seven fractional
/// digits — .NET ticks are 100 nanoseconds — while both MySQL's <c>datetime(6)</c> and
/// PostgreSQL's <c>timestamptz</c> keep six. The hash was computed against a value with more
/// precision than the column it was about to be written to, so the seventh digit was gone by the
/// time anything read the row back and the recomputation could never match. The chain had never
/// verified against a real database on either engine.
/// </para>
/// <para>
/// It never surfaced in the suite because the in-memory provider stores a .NET object and
/// truncates nothing, so every chain test round-tripped a value no database would return. These
/// tests therefore truncate explicitly, which is what a column does.
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

    private static AuditDbContext Context() =>
        new(new DbContextOptionsBuilder<AuditDbContext>()
            .UseInMemoryDatabase($"chain-{Guid.NewGuid():N}")
            .Options);

    private static async Task<AuditLogEntity> WrittenAsync(DateTime timestamp)
    {
        var entry = Entry(timestamp);
        await using var db = Context();
        using (await new AuditHashChainService().AcquireAndComputeAsync(db, entry))
        {
        }
        return entry;
    }

    /// <summary>The timestamp with a non-zero seventh digit — which is most of them.</summary>
    private static DateTime Awkward =>
        new DateTime(2026, 9, 19, 10, 59, 12, DateTimeKind.Utc).AddTicks(3_456_789);

    [Fact]
    public async Task A_record_is_stored_at_a_precision_its_column_can_hold()
    {
        // The fix. The timestamp is truncated before it is hashed and before it is saved, so the
        // value that was hashed is the value that comes back — whether the engine would have
        // rounded or truncated what it was given no longer matters, because it is handed
        // something it can hold exactly.
        var written = await WrittenAsync(Awkward);

        Assert.Equal(0, written.Timestamp.Ticks % 10);
        Assert.Equal(AsStored(Awkward), written.Timestamp);
    }

    [Fact]
    public async Task The_hash_survives_the_round_trip_that_used_to_break_it()
    {
        var written = await WrittenAsync(Awkward);

        // Re-hashing the row as a database would return it now reproduces the stored hash.
        var reread = await WrittenAsync(AsStored(written.Timestamp));

        Assert.Equal(written.RecordHash, reread.RecordHash);
    }

    [Fact]
    public async Task The_hash_no_longer_depends_on_a_kind_no_database_stores()
    {
        // The second sharp edge in the same line. "O" renders a trailing Z for UTC and nothing for
        // Unspecified, and which one a value carries depends on how a driver labelled it on the
        // way out, not on anything stored. The canonical form now writes a literal Z.
        var utc = await WrittenAsync(Awkward);
        var unspecified = await WrittenAsync(DateTime.SpecifyKind(Awkward, DateTimeKind.Unspecified));

        Assert.Equal(utc.RecordHash, unspecified.RecordHash);
    }

    [Fact]
    public async Task A_written_record_records_which_canonical_form_it_used()
    {
        var written = await WrittenAsync(Awkward);

        Assert.Equal(AuditHashChainService.CurrentHashVersion, written.HashVersion);
    }

    [Fact]
    public async Task A_record_from_before_the_fix_is_unverifiable_rather_than_tampered()
    {
        // The distinction the endpoint depends on. A null HashVersion means the hash was taken
        // from a value the column destroyed, so it cannot be reproduced — and calling that
        // tampering puts every existing deployment permanently in the alarm state, which is
        // exactly how a real tamper goes unnoticed.
        await using var db = Context();
        db.AuditLogs.Add(new AuditLogEntity
        {
            Id = Guid.NewGuid(),
            Timestamp = AsStored(Awkward),
            ActionType = "Legacy",
            Success = true,
            RecordHash = new string('a', 64),
            PreviousRecordHash = null,
            HashVersion = null,
        });
        await db.SaveChangesAsync();

        var result = await new AuditHashChainService().VerifyAsync(db, tenantId: null);

        Assert.Equal(1, result.UnverifiableRecords);
        Assert.Empty(result.Breaks);
        Assert.Equal(0, result.RecordsVerified);
    }

    [Fact]
    public async Task A_legacy_record_with_a_broken_link_is_still_a_break()
    {
        // Only the recomputation is skipped for a legacy record. PreviousRecordHash is a stored
        // value, so the chain linkage is checked for every row regardless of version — otherwise
        // a deletion from the middle of the old history would pass unnoticed.
        await using var db = Context();
        db.AuditLogs.Add(new AuditLogEntity
        {
            Id = Guid.NewGuid(),
            Timestamp = AsStored(Awkward),
            ActionType = "Legacy",
            Success = true,
            RecordHash = new string('a', 64),
            PreviousRecordHash = new string('b', 64),   // nothing precedes it
            HashVersion = null,
        });
        await db.SaveChangesAsync();

        var result = await new AuditHashChainService().VerifyAsync(db, tenantId: null);

        Assert.Single(result.Breaks);
        Assert.Contains("PreviousRecordHash", result.Breaks[0].Issue);
    }

    [Fact]
    public async Task A_tampered_current_record_is_still_caught()
    {
        // The fix must not soften detection for records it applies to.
        var written = await WrittenAsync(Awkward);

        await using var db = Context();
        written.ActorUsername = "someone-else";
        db.AuditLogs.Add(written);
        await db.SaveChangesAsync();

        var result = await new AuditHashChainService().VerifyAsync(db, tenantId: null);

        Assert.Single(result.Breaks);
        Assert.Contains("tampered", result.Breaks[0].Issue);
    }
}
