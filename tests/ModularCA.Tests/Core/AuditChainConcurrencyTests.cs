using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// The audit chain under concurrency, failure, pruning and truncated verification.
/// <para>
/// The entry used to be stamped before the chain lock was taken while the chain is ordered by
/// timestamp, so two concurrent writers could link in one order and sort in the other. The entry
/// is now re-stamped under the lock, after the chain head. A failed save used to leave its entity
/// Added in the scoped context, failing every later write in the scope and eventually committing
/// with a stale link. Retention deleted the oldest rows and left a break at the new oldest record.
/// Verification of a long chain reported "valid" for rows it never looked at.
/// </para>
/// </summary>
public class AuditChainConcurrencyTests
{
    private static AuditDbContext Context(string name, params IInterceptor[] interceptors) =>
        new(new DbContextOptionsBuilder<AuditDbContext>()
            .UseInMemoryDatabase(name)
            .AddInterceptors(interceptors)
            .Options);

    private static AuditLogEntity Entry(Guid? spaceId = null, string action = "Issued") => new()
    {
        ActionType = action,
        ActorUsername = "admin",
        Success = true,
        TenantId = spaceId,
    };

    [Fact]
    public async Task Concurrent_writers_in_one_process_produce_a_valid_chain()
    {
        var name = $"conc-{Guid.NewGuid():N}";
        var chain = new AuditHashChainService();

        await Task.WhenAll(Enumerable.Range(0, 40).Select(async _ =>
        {
            await using var db = Context(name);
            await chain.AppendAsync(db, Entry());
        }));

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, tenantId: null);

        Assert.Empty(result.Breaks);
        Assert.Equal(40, result.RecordsVerified);
        var stamps = await verifyDb.AuditLogs.OrderBy(a => a.Timestamp).Select(a => a.Timestamp).ToListAsync();
        Assert.Equal(stamps.Count, stamps.Distinct().Count());
    }

    [Fact]
    public async Task Writers_on_a_stalled_clock_still_link_in_timestamp_order()
    {
        var name = $"stall-{Guid.NewGuid():N}";
        var chain = new AuditHashChainService(new FixedTimeProvider(DateTimeOffset.UtcNow));

        for (var i = 0; i < 5; i++)
        {
            await using var db = Context(name);
            await chain.AppendAsync(db, Entry());
        }

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, tenantId: null);
        Assert.Empty(result.Breaks);
        Assert.Equal(5, result.RecordsVerified);
    }

    [Fact]
    public async Task A_chain_head_later_than_now_is_followed_rather_than_undercut()
    {
        var name = $"future-{Guid.NewGuid():N}";
        var future = DateTimeOffset.UtcNow.AddHours(2);
        await using (var db = Context(name))
            await new AuditHashChainService(new FixedTimeProvider(future)).AppendAsync(db, Entry());

        var chain = new AuditHashChainService();
        var next = Entry();
        await using (var db = Context(name))
            await chain.AppendAsync(db, next);

        Assert.Equal(AuditHashChainService.ToStorablePrecision(future.UtcDateTime).AddTicks(10), next.Timestamp);
        await using var verifyDb = Context(name);
        Assert.Empty((await chain.VerifyAsync(verifyDb, tenantId: null)).Breaks);
    }

    [Fact]
    public void The_next_timestamp_is_now_when_the_head_is_older()
    {
        var now = new DateTime(2026, 9, 26, 12, 0, 0, DateTimeKind.Utc).AddTicks(1234567);
        var stamped = AuditHashChainService.NextTimestamp(now, now.AddMinutes(-1));

        Assert.Equal(AuditHashChainService.ToStorablePrecision(now), stamped);
        Assert.Equal(0, stamped.Ticks % 10);
    }

    /// <summary>Throws from the first SaveChanges it sees, and lets every later one through.</summary>
    private sealed class FailOnce : SaveChangesInterceptor
    {
        private int _calls;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
            => Interlocked.Increment(ref _calls) == 1
                ? throw new DbUpdateException("simulated audit write failure")
                : base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    [Fact]
    public async Task A_failed_save_does_not_poison_the_next_write_in_the_scope()
    {
        var name = $"fail-{Guid.NewGuid():N}";
        await using var db = Context(name, new FailOnce());
        var audit = new AuditService(NullLogger<AuditService>.Instance, db, hashChain: new AuditHashChainService());

        await audit.LogAsync("First", null, "admin");
        await audit.LogAsync("Second", null, "admin");

        Assert.DoesNotContain(db.ChangeTracker.Entries(), e => e.State != EntityState.Unchanged);
        await using var readDb = Context(name);
        var rows = await readDb.AuditLogs.ToListAsync();
        Assert.Equal("Second", Assert.Single(rows).ActionType);
        Assert.Null(rows[0].PreviousRecordHash);
        Assert.Empty((await new AuditHashChainService().VerifyAsync(readDb, tenantId: null)).Breaks);
    }

    [Fact]
    public async Task A_failed_append_detaches_its_entry()
    {
        await using var db = Context($"detach-{Guid.NewGuid():N}", new FailOnce());
        var chain = new AuditHashChainService();
        var failed = Entry();

        await Assert.ThrowsAsync<DbUpdateException>(() => chain.AppendAsync(db, failed));

        Assert.Equal(EntityState.Detached, db.Entry(failed).State);
    }

    [Fact]
    public async Task Over_long_fields_are_cut_to_their_columns_before_hashing()
    {
        var name = $"fit-{Guid.NewGuid():N}";
        var chain = new AuditHashChainService();
        var entry = Entry();
        entry.ErrorMessage = new string('e', 2000);
        entry.TargetEntityId = new string('i', 300);
        entry.TargetEntityType = new string('t', 80);
        entry.ActorUsername = new string('u', 300);

        await using (var db = Context(name))
            await chain.AppendAsync(db, entry);

        Assert.Equal(500, entry.ErrorMessage!.Length);
        Assert.Equal(255, entry.TargetEntityId!.Length);
        Assert.Equal(50, entry.TargetEntityType!.Length);
        Assert.Equal(255, entry.ActorUsername!.Length);
        await using var verifyDb = Context(name);
        Assert.Empty((await chain.VerifyAsync(verifyDb, tenantId: null)).Breaks);
    }

    [Fact]
    public async Task A_pruned_chain_verifies_from_its_oldest_survivor()
    {
        var name = $"prune-{Guid.NewGuid():N}";
        var space = Guid.NewGuid();
        var chain = new AuditHashChainService();
        for (var i = 0; i < 6; i++)
        {
            await using var db = Context(name);
            await chain.AppendAsync(db, Entry(space));
        }

        await using (var db = Context(name))
        {
            var ordered = await db.AuditLogs.OrderBy(a => a.Timestamp).ToListAsync();
            var cutoff = ordered[3].Timestamp;
            db.AuditLogs.RemoveRange(ordered.Take(3));
            await db.SaveChangesAsync();

            var broken = await chain.VerifyAsync(db, space);
            Assert.Single(broken.Breaks);

            var marker = await chain.RecordPruneAsync(db, space, cutoff);
            Assert.Equal(AuditHashChainService.ChainPrunedAction, marker.ActionType);
            Assert.NotNull(marker.PreviousRecordHash);
        }

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, space);
        Assert.Empty(result.Breaks);
        Assert.True(result.Pruned);
        Assert.Equal(1, result.Epochs);
        Assert.Equal(4, result.RecordsVerified);
    }

    /// <summary>Six records in a space chain with the oldest three deleted; returns the new oldest.</summary>
    private static async Task<AuditLogEntity> SeedPrunedAsync(string name, Guid space, AuditHashChainService chain)
    {
        for (var i = 0; i < 6; i++)
        {
            await using var db = Context(name);
            await chain.AppendAsync(db, Entry(space));
        }
        await using var del = Context(name);
        var ordered = await del.AuditLogs.OrderBy(a => a.Timestamp).ToListAsync();
        del.AuditLogs.RemoveRange(ordered.Take(3));
        await del.SaveChangesAsync();
        return ordered[3];
    }

    /// <summary>A hand-built, correctly hashed prune marker declaring <paramref name="anchor"/>.</summary>
    private static async Task<AuditLogEntity> ForgeMarkerAsync(
        string name, Guid space, AuditHashChainService chain, AuditLogEntity anchor, DateTime cutoff)
    {
        var marker = Entry(space, AuditHashChainService.ChainPrunedAction);
        marker.DetailsJson = System.Text.Json.JsonSerializer.Serialize(new
        {
            Reason = "forged",
            Cutoff = cutoff,
            AnchorRecordId = (Guid?)anchor.Id,
            AnchorPreviousHash = anchor.PreviousRecordHash,
        });
        await using var db = Context(name);
        await chain.AppendAsync(db, marker);
        return marker;
    }

    [Fact]
    public async Task A_marker_beyond_the_verification_limit_is_not_honoured()
    {
        var name = $"beyond-{Guid.NewGuid():N}";
        var space = Guid.NewGuid();
        var chain = new AuditHashChainService();
        var anchor = await SeedPrunedAsync(name, space, chain);
        await ForgeMarkerAsync(name, space, chain, anchor, anchor.Timestamp);

        await using var verifyDb = Context(name);
        var partial = await chain.VerifyAsync(verifyDb, space, limit: 3);

        Assert.False(partial.Pruned);
        Assert.Contains(partial.Breaks, b => b.RecordId == anchor.Id && b.Issue.Contains("PreviousRecordHash"));
    }

    [Fact]
    public async Task A_marker_whose_hash_is_tampered_is_not_honoured()
    {
        var name = $"tampered-{Guid.NewGuid():N}";
        var space = Guid.NewGuid();
        var chain = new AuditHashChainService();
        var anchor = await SeedPrunedAsync(name, space, chain);
        await using (var db = Context(name))
        {
            var marker = await chain.RecordPruneAsync(db, space, anchor.Timestamp);
            marker.ActorUsername = "someone-else";
            await db.SaveChangesAsync();
        }

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, space);

        Assert.False(result.Pruned);
        Assert.Contains(result.Breaks, b => b.RecordId == anchor.Id && b.Issue.Contains("PreviousRecordHash"));
        Assert.Contains(result.Breaks, b => b.Issue.Contains("tampered"));
    }

    [Fact]
    public async Task A_marker_whose_cutoff_is_after_its_anchor_is_not_honoured_and_is_reported()
    {
        var name = $"cutoff-{Guid.NewGuid():N}";
        var space = Guid.NewGuid();
        var chain = new AuditHashChainService();
        var anchor = await SeedPrunedAsync(name, space, chain);
        var marker = await ForgeMarkerAsync(name, space, chain, anchor, anchor.Timestamp.AddDays(1));

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, space);

        Assert.False(result.Pruned);
        Assert.Contains(result.Breaks, b => b.RecordId == anchor.Id && b.Issue.Contains("PreviousRecordHash"));
        Assert.Contains(result.Breaks, b => b.RecordId == marker.Id && b.Issue.Contains("not honoured"));
    }

    [Fact]
    public async Task A_legitimate_prune_marker_is_honoured_within_the_limit()
    {
        var name = $"legit-{Guid.NewGuid():N}";
        var space = Guid.NewGuid();
        var chain = new AuditHashChainService();
        var anchor = await SeedPrunedAsync(name, space, chain);
        await using (var db = Context(name))
            await chain.RecordPruneAsync(db, space, anchor.Timestamp.AddDays(-1));

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, space, limit: 4);

        Assert.True(result.Pruned);
        Assert.Empty(result.Breaks);
    }

    [Fact]
    public async Task A_prune_that_stopped_short_records_the_anchor_as_its_cutoff()
    {
        var name = $"short-{Guid.NewGuid():N}";
        var space = Guid.NewGuid();
        var chain = new AuditHashChainService();
        var anchor = await SeedPrunedAsync(name, space, chain);
        await using (var db = Context(name))
        {
            var marker = await chain.RecordPruneAsync(db, space, anchor.Timestamp.AddDays(1));
            var recorded = System.Text.Json.JsonDocument.Parse(marker.DetailsJson!).RootElement.GetProperty("Cutoff").GetDateTime();
            Assert.Equal(AuditHashChainService.ToStorablePrecision(anchor.Timestamp), recorded);
        }

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, space);
        Assert.True(result.Pruned);
        Assert.Empty(result.Breaks);
    }

    [Fact]
    public async Task A_prefix_deleted_without_a_prune_marker_is_still_a_break()
    {
        var name = $"unmarked-{Guid.NewGuid():N}";
        var chain = new AuditHashChainService();
        for (var i = 0; i < 4; i++)
        {
            await using var db = Context(name);
            await chain.AppendAsync(db, Entry());
        }

        await using (var db = Context(name))
        {
            var ordered = await db.AuditLogs.OrderBy(a => a.Timestamp).ToListAsync();
            db.AuditLogs.RemoveRange(ordered.Take(2));
            await db.SaveChangesAsync();
            await chain.RestartChainAsync(db, null, null, "admin", "unrelated");
        }

        await using var verifyDb = Context(name);
        var result = await chain.VerifyAsync(verifyDb, tenantId: null);
        Assert.False(result.Pruned);
        Assert.Single(result.Breaks);
    }

    [Fact]
    public async Task A_verification_that_stops_short_says_so()
    {
        var name = $"trunc-{Guid.NewGuid():N}";
        var chain = new AuditHashChainService();
        for (var i = 0; i < 5; i++)
        {
            await using var db = Context(name);
            await chain.AppendAsync(db, Entry());
        }

        await using var verifyDb = Context(name);
        var partial = await chain.VerifyAsync(verifyDb, tenantId: null, limit: 3);
        var full = await chain.VerifyAsync(verifyDb, tenantId: null);

        Assert.True(partial.Truncated);
        Assert.Equal(5, partial.TotalRecords);
        Assert.Equal(3, partial.RecordsVerified);
        Assert.False(full.Truncated);
    }
}
