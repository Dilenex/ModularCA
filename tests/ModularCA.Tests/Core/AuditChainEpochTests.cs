using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// Drawing a line under records that can never verify.
/// <para>
/// After the canonical form was versioned, every deployment carried a prefix of records hashed
/// under the old one — recomputable by nobody, since the values they were hashed from no longer
/// exist. A report that says "1,698 unverifiable, 40 verified" forever is a report nobody reads.
/// A restart is a record that links to nothing and from which everything verifies, so the report
/// can say what is intact and since when.
/// </para>
/// <para>
/// The restart is a normal audited record, hashed and chained forward, naming its actor and
/// reason. That is what makes it visible rather than a way to hide something: a restart the
/// operator did not make is a finding in its own right, and the report counts them.
/// </para>
/// </summary>
public class AuditChainEpochTests
{
    private static AuditDbContext Context() =>
        new(new DbContextOptionsBuilder<AuditDbContext>()
            .UseInMemoryDatabase($"epoch-{Guid.NewGuid():N}")
            .Options);

    private static DateTime At(int minute) =>
        new DateTime(2026, 9, 19, 12, minute, 0, DateTimeKind.Utc);

    /// <summary>A record from before the fix: a stored hash nobody can reproduce.</summary>
    private static AuditLogEntity Legacy(int minute, string? previous) => new()
    {
        Id = Guid.NewGuid(),
        Timestamp = At(minute),
        ActionType = "Legacy",
        Success = true,
        RecordHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"legacy-{minute}"))).ToLowerInvariant(),
        PreviousRecordHash = previous,
        HashVersion = null,
    };

    private static async Task<AuditLogEntity> WriteAsync(
        AuditDbContext db, AuditHashChainService chain, DateTime at, string action = "Issued")
    {
        var entry = new AuditLogEntity
        {
            Timestamp = at,
            ActionType = action,
            ActorUsername = "admin",
            Success = true,
        };
        using (await chain.AcquireAndComputeAsync(db, entry))
        {
            db.AuditLogs.Add(entry);
            await db.SaveChangesAsync();
        }
        return entry;
    }

    [Fact]
    public async Task A_restart_links_to_nothing_and_is_not_a_break()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();

        db.AuditLogs.AddRange(Legacy(1, null), Legacy(2, "not-what-came-before"));
        await db.SaveChangesAsync();

        var marker = await chain.RestartChainAsync(db, null, null, "admin", "test");

        Assert.Null(marker.PreviousRecordHash);
        Assert.Equal(AuditHashChainService.ChainRestartAction, marker.ActionType);
        Assert.Equal(AuditHashChainService.CurrentHashVersion, marker.HashVersion);

        var result = await chain.VerifyAsync(db, tenantId: null);

        // The legacy pair has a broken link between them, which is still reported; the restart
        // after them is not.
        Assert.Single(result.Breaks);
        Assert.Equal(1, result.Epochs);
        Assert.Equal(marker.Timestamp, result.VerifiableSince);
    }

    [Fact]
    public async Task Everything_after_a_restart_verifies_fully()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();

        db.AuditLogs.Add(Legacy(1, null));
        await db.SaveChangesAsync();

        // A restart stamps the moment it happens, so what follows it has to be later than that
        // — as it always is in a live system, and as a fixed wall-clock minute in a test is not.
        var marker = await chain.RestartChainAsync(db, null, null, "admin", "test");
        await WriteAsync(db, chain, marker.Timestamp.AddSeconds(1));
        await WriteAsync(db, chain, marker.Timestamp.AddSeconds(2));

        var result = await chain.VerifyAsync(db, tenantId: null);

        Assert.Empty(result.Breaks);
        Assert.Equal(1, result.UnverifiableRecords);
        Assert.Equal(3, result.RecordsVerified);   // the marker and two records
    }

    [Fact]
    public async Task The_restart_itself_must_recompute()
    {
        // A marker is a genesis by declaration, not an exemption from hashing. Tamper with it and
        // it is caught like any other record.
        await using var db = Context();
        var chain = new AuditHashChainService();

        var marker = await chain.RestartChainAsync(db, null, null, "admin", "test");
        marker.ActorUsername = "someone-else";
        await db.SaveChangesAsync();

        var result = await chain.VerifyAsync(db, tenantId: null);

        Assert.Single(result.Breaks);
        Assert.Contains("tampered", result.Breaks[0].Issue);
    }

    [Fact]
    public async Task A_record_after_a_restart_that_links_past_it_is_a_break()
    {
        // The epoch boundary is real: a record after the marker has to chain from the marker,
        // not from whatever came before it.
        await using var db = Context();
        var chain = new AuditHashChainService();

        var marker = await chain.RestartChainAsync(db, null, null, "admin", "test");
        var next = await WriteAsync(db, chain, marker.Timestamp.AddSeconds(1));
        next.PreviousRecordHash = "something-older";
        await db.SaveChangesAsync();

        var result = await chain.VerifyAsync(db, tenantId: null);

        Assert.Contains(result.Breaks, b => b.RecordId == next.Id && b.Issue.Contains("PreviousRecordHash"));
    }

    [Fact]
    public async Task The_marker_says_who_and_why_and_how_much_it_leaves_behind()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        var actor = Guid.NewGuid();

        db.AuditLogs.AddRange(Legacy(1, null), Legacy(2, null));
        await db.SaveChangesAsync();

        var marker = await chain.RestartChainAsync(db, null, actor, "edward", "after the incident");

        Assert.Equal(actor, marker.ActorUserId);
        Assert.Equal("edward", marker.ActorUsername);
        Assert.Contains("after the incident", marker.DetailsJson);
        Assert.Contains("\"recordsBefore\":2", marker.DetailsJson);
        Assert.Contains("\"unverifiableBefore\":2", marker.DetailsJson);
    }

    [Fact]
    public async Task Legacy_chains_are_restarted_once_at_startup_and_not_again()
    {
        var tenantA = Guid.NewGuid();

        await using var db = Context();
        var chain = new AuditHashChainService();

        // Two chains with legacy rows, one chain that was always current.
        db.AuditLogs.Add(Legacy(1, null));
        var a = Legacy(1, null); a.TenantId = tenantA; db.AuditLogs.Add(a);
        await db.SaveChangesAsync();
        var fresh = Guid.NewGuid();
        var entry = new AuditLogEntity { Timestamp = At(1), ActionType = "X", Success = true, TenantId = fresh };
        using (await chain.AcquireAndComputeAsync(db, entry)) { db.AuditLogs.Add(entry); await db.SaveChangesAsync(); }

        var first = await chain.RestartLegacyChainsAsync(db);
        var second = await chain.RestartLegacyChainsAsync(db);

        Assert.Equal(2, first.Count);
        Assert.Contains(null, first);
        Assert.Contains(tenantA, first);
        Assert.DoesNotContain(fresh, first);
        Assert.Empty(second);

        var markers = await db.AuditLogs.CountAsync(x => x.ActionType == AuditHashChainService.ChainRestartAction);
        Assert.Equal(2, markers);
        Assert.All(await db.AuditLogs.Where(x => x.ActionType == AuditHashChainService.ChainRestartAction).ToListAsync(),
            m => Assert.Equal(AuditHashChainService.SystemActor, m.ActorUsername));
    }

    [Fact]
    public async Task Without_legacy_rows_verifiable_since_is_the_first_current_record()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();

        var first = await WriteAsync(db, chain, At(5));
        await WriteAsync(db, chain, At(6));

        var result = await chain.VerifyAsync(db, tenantId: null);

        Assert.Equal(0, result.Epochs);
        Assert.Equal(first.Timestamp, result.VerifiableSince);
        Assert.Empty(result.Breaks);
    }
}
