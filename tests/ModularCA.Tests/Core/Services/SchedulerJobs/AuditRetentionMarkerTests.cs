using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.SchedulerJobs;

/// <summary>
/// Retention prunes one audit chain at a time and marks each chain as soon as its rows are gone,
/// so a failure or shutdown partway through the run never leaves a chain pruned without a marker.
/// </summary>
public class AuditRetentionMarkerTests
{
    private static AuditDbContext Context(string name) =>
        new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase(name).Options);

    /// <summary>
    /// The real job with its batch delete done through EF, since the in-memory provider has no
    /// ctid. <see cref="BeforeBatch"/> runs before every AuditLogs batch and may throw or cancel.
    /// </summary>
    private sealed class TestJob(
        IServiceProvider sp, SystemConfig config, SchedulerJobRunner runner, AuditDbContext db, AuditHashChainService chain)
        : AuditRetentionJob(sp, config, NullLogger<AuditRetentionJob>.Instance, runner, db, chain)
    {
        public List<Guid?> BatchSpaces { get; } = [];
        public Action<int, Guid?>? BeforeBatch { get; set; }

        protected override Task<int> DeleteBatchAsync(
            string table, DateTime cutoff, bool bySpace, Guid? spaceId, int batchSize, CancellationToken ct)
        {
            if (table != "AuditLogs")
                return Task.FromResult(0);
            Assert.True(bySpace);
            BatchSpaces.Add(spaceId);
            BeforeBatch?.Invoke(BatchSpaces.Count, spaceId);
            var rows = db.AuditLogs.Where(a => a.Timestamp < cutoff && a.TenantId == spaceId)
                .OrderBy(a => a.Timestamp).Take(batchSize).ToList();
            db.AuditLogs.RemoveRange(rows);
            db.SaveChanges();
            return Task.FromResult(rows.Count);
        }

        /// <summary>The AuditLogs rows archiving asked for, read through EF.</summary>
        protected override async IAsyncEnumerable<IReadOnlyDictionary<string, object?>> ReadDueRowsAsync(
            string table, IReadOnlyList<DueRange> ranges, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            if (table != "AuditLogs")
                yield break;
            foreach (var range in ranges)
            {
                Assert.True(range.BySpace);
                var rows = await db.AuditLogs.AsNoTracking()
                    .Where(a => a.Timestamp < range.Cutoff && a.TenantId == range.SpaceId).ToListAsync(ct);
                foreach (var row in rows)
                    yield return new Dictionary<string, object?> { ["Id"] = row.Id, ["TenantId"] = row.TenantId, ["ActionType"] = row.ActionType };
            }
        }
    }

    private static readonly Guid SpaceA = Guid.Parse("aaaaaaaa-0000-0000-0000-00000000000a");
    private static readonly Guid SpaceB = Guid.Parse("bbbbbbbb-0000-0000-0000-00000000000b");

    /// <summary>Three records older than the 30-day window and two inside it, for each space.</summary>
    private static async Task SeedAsync(string name)
    {
        var old = new AuditHashChainService(new FixedTimeProvider(DateTimeOffset.UtcNow.AddDays(-60)));
        var fresh = new AuditHashChainService(new FixedTimeProvider(DateTimeOffset.UtcNow.AddDays(-1)));
        foreach (var space in new[] { SpaceA, SpaceB })
        {
            for (var i = 0; i < 3; i++)
            {
                await using var db = Context(name);
                await old.AppendAsync(db, new AuditLogEntity { ActionType = "Old", ActorUsername = "a", Success = true, TenantId = space });
            }
            for (var i = 0; i < 2; i++)
            {
                await using var db = Context(name);
                await fresh.AppendAsync(db, new AuditLogEntity { ActionType = "New", ActorUsername = "a", Success = true, TenantId = space });
            }
        }
    }

    private static TestJob Build(string name, AuditDbContext db, string? archiveDir = null)
    {
        var config = new SystemConfig();
        config.Audit.Retention = new AuditRetentionConfig
        {
            Enabled = true, GeneralRetentionDays = 30, NetworkRetentionDays = 0, DeleteBatchSize = 2,
            ArchiveBeforeDelete = archiveDir != null, ArchivePath = archiveDir ?? "backups/audit-archive",
        };
        var sp = new ServiceCollection().BuildServiceProvider();
        var runner = new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test");
        return new TestJob(sp, config, runner, db, new AuditHashChainService());
    }

    private static async Task<int> MarkersAsync(string name, Guid space)
    {
        await using var db = Context(name);
        return await db.AuditLogs.CountAsync(a => a.TenantId == space && a.ActionType == AuditHashChainService.ChainPrunedAction);
    }

    private static async Task<HashChainVerificationResult> VerifyAsync(string name, Guid space)
    {
        await using var db = Context(name);
        return await new AuditHashChainService().VerifyAsync(db, space);
    }

    [Fact]
    public async Task Each_chain_is_marked_as_soon_as_it_is_pruned()
    {
        var name = $"ret-{Guid.NewGuid():N}";
        await SeedAsync(name);
        await using var db = Context(name);
        var job = Build(name, db);

        await job.RunAsync(CancellationToken.None);

        foreach (var space in new[] { SpaceA, SpaceB })
        {
            Assert.Equal(1, await MarkersAsync(name, space));
            var result = await VerifyAsync(name, space);
            Assert.Empty(result.Breaks);
            Assert.True(result.Pruned);
        }
        // One space's batches all run before the other's begin.
        var order = job.BatchSpaces;
        Assert.Equal(new[] { order[0], order[0], order[2], order[2] }, order);
        Assert.NotEqual(order[0], order[2]);
    }

    [Fact]
    public async Task A_failure_between_batches_of_the_second_space_leaves_both_chains_marked()
    {
        var name = $"ret-fail-{Guid.NewGuid():N}";
        await SeedAsync(name);
        await using (var db = Context(name))
        {
            var job = Build(name, db);
            // Batches 1-2 finish the first space (2 + a short 1); batch 3 deletes two of the
            // second space's rows; batch 4 fails before deleting its last one.
            job.BeforeBatch = (n, _) => { if (n == 4) throw new InvalidOperationException("simulated DB failure"); };

            await job.RunAsync(CancellationToken.None);

            var first = job.BatchSpaces[0]!.Value;
            var second = job.BatchSpaces[2]!.Value;
            Assert.NotEqual(first, second);
            Assert.Equal(1, await MarkersAsync(name, first));
            Assert.Equal(1, await MarkersAsync(name, second));
            foreach (var space in new[] { first, second })
            {
                var result = await VerifyAsync(name, space);
                Assert.Empty(result.Breaks);
                Assert.True(result.Pruned);
            }
        }

        // The next run finishes the partly pruned chain and marks it again; the other chain has
        // nothing left to prune and gets no new marker.
        await using (var db = Context(name))
        {
            var job = Build(name, db);
            await job.RunAsync(CancellationToken.None);
            var markers = new[] { await MarkersAsync(name, SpaceA), await MarkersAsync(name, SpaceB) };
            Assert.Equal(3, markers.Sum());
            foreach (var space in new[] { SpaceA, SpaceB })
                Assert.Empty((await VerifyAsync(name, space)).Breaks);
        }
    }

    /// <summary>
    /// A retired chain sealed long ago, and an instance chain whose oldest records include the
    /// seal's succession record, both past the retention window: retention prunes the retired chain
    /// up to its seal and keeps the seal, prunes the instance chain and anchors the seal there
    /// again, so the chain reads Sealed throughout, nothing is sealed again at the next start, and
    /// a second run changes nothing.
    /// </summary>
    [Fact]
    public async Task A_retired_chain_keeps_its_seal_and_stays_sealed_through_retention()
    {
        var name = $"ret-seal-{Guid.NewGuid():N}";
        var old = new AuditHashChainService(new FixedTimeProvider(DateTimeOffset.UtcNow.AddDays(-60)));
        foreach (var chain in new Guid?[] { SpaceA, null, SpaceA, null, SpaceA })
        {
            await using var db = Context(name);
            await old.AppendAsync(db, new AuditLogEntity { ActionType = "Old", ActorUsername = "a", Success = true, TenantId = chain });
        }
        await using (var db = Context(name))
            Assert.Equal([SpaceA], await old.SealRetiredChainsAsync(db));
        var fresh = new AuditHashChainService(new FixedTimeProvider(DateTimeOffset.UtcNow.AddDays(-1)));
        for (var i = 0; i < 2; i++)
        {
            await using var db = Context(name);
            await fresh.AppendAsync(db, new AuditLogEntity { ActionType = "New", ActorUsername = "a", Success = true });
        }
        Guid sealId;
        await using (var db = Context(name))
            sealId = (await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction)).Id;

        async Task AssertSealedAsync()
        {
            await using var db = Context(name);
            var chains = new AuditHashChainService();
            Assert.Equal(RetiredChainState.Sealed, (await chains.CheckRetiredChainAsync(db, SpaceA)).State);
            var retired = await chains.VerifyAsync(db, SpaceA);
            Assert.Empty(retired.Breaks);
            Assert.True(retired.Sealed);
            Assert.Empty((await chains.VerifyAsync(db, null)).Breaks);
            Assert.Equal(sealId, (await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction)).Id);
            Assert.Empty(await chains.SealRetiredChainsAsync(db));
        }

        await using (var db = Context(name))
            await Build(name, db).RunAsync(CancellationToken.None);

        await using (var db = Context(name))
        {
            Assert.Equal(0, await db.AuditLogs.CountAsync(a => a.ActionType == "Old"));
            Assert.Equal(1, await MarkersAsync(name, SpaceA));
            Assert.Equal(1, await db.AuditLogs.CountAsync(a => a.TenantId == null && a.ActionType == AuditHashChainService.ChainPrunedAction));
            Assert.Equal(1, await db.AuditLogs.CountAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction));
        }
        await AssertSealedAsync();

        int before;
        await using (var db = Context(name))
            before = await db.AuditLogs.CountAsync();
        await using (var db = Context(name))
            await Build(name, db).RunAsync(CancellationToken.None);
        await using (var db = Context(name))
            Assert.Equal(before, await db.AuditLogs.CountAsync());
        await AssertSealedAsync();
    }

    [Fact]
    public async Task A_shutdown_after_a_spaces_delete_still_writes_its_marker()
    {
        var name = $"ret-cancel-{Guid.NewGuid():N}";
        await SeedAsync(name);
        await using var db = Context(name);
        var job = Build(name, db);
        using var cts = new CancellationTokenSource();
        // The first space's final (short) batch runs with cancellation already requested.
        job.BeforeBatch = (n, _) => { if (n == 2) cts.Cancel(); };

        await job.RunAsync(cts.Token);

        var first = job.BatchSpaces[0]!.Value;
        var second = first == SpaceA ? SpaceB : SpaceA;
        Assert.Equal(1, await MarkersAsync(name, first));
        Assert.Empty((await VerifyAsync(name, first)).Breaks);
        Assert.Equal(0, await MarkersAsync(name, second));
        Assert.DoesNotContain(second, job.BatchSpaces);
    }

    /// <summary>
    /// SpaceA's retired chain and the instance chain, 60 days old: SpaceA sealed then, three more
    /// old instance records after its succession, and two fresh instance records. Returns the seal.
    /// </summary>
    private static async Task<AuditLogEntity> SeedSealedAsync(string name)
    {
        var old = new AuditHashChainService(new FixedTimeProvider(DateTimeOffset.UtcNow.AddDays(-60)));
        foreach (var chain in new Guid?[] { SpaceA, null, SpaceA, null, SpaceA })
        {
            await using var db = Context(name);
            await old.AppendAsync(db, new AuditLogEntity { ActionType = "Old", ActorUsername = "a", Success = true, TenantId = chain });
        }
        await using (var db = Context(name))
            Assert.Equal([SpaceA], await old.SealRetiredChainsAsync(db));
        for (var i = 0; i < 3; i++)
        {
            await using var db = Context(name);
            await old.AppendAsync(db, new AuditLogEntity { ActionType = "Old", ActorUsername = "a", Success = true });
        }
        var fresh = new AuditHashChainService(new FixedTimeProvider(DateTimeOffset.UtcNow.AddDays(-1)));
        for (var i = 0; i < 2; i++)
        {
            await using var db = Context(name);
            await fresh.AppendAsync(db, new AuditLogEntity { ActionType = "New", ActorUsername = "a", Success = true });
        }
        await using var read = Context(name);
        return await read.AuditLogs.AsNoTracking().SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction);
    }

    private static async Task AssertTailAsync(string name, RetiredChainState state)
    {
        await using var db = Context(name);
        Assert.Equal(state, (await new AuditHashChainService().CheckRetiredChainAsync(db, SpaceA)).State);
    }

    private static async Task DeleteAsync(string name, Guid id)
    {
        await using var db = Context(name);
        db.AuditLogs.Remove(await db.AuditLogs.SingleAsync(a => a.Id == id));
        await db.SaveChangesAsync();
    }

    /// <summary>The next start of the control role: seals nothing once the retired chains were sealed.</summary>
    private static async Task AssertNextStartSealsNothingAsync(string name)
    {
        await using var db = Context(name);
        Assert.Empty(await new AuditHashChainService().SealRetiredChainsAsync(db));
    }

    /// <summary>
    /// Review 2, 1(b): the seal was deleted, then retention pruned the instance records holding its
    /// succession. The succession is carried forward with the seal it first anchored, so the chain
    /// reads TailMissing, and the next start does not seal it afresh.
    /// </summary>
    [Fact]
    public async Task A_deleted_seal_stays_missing_when_retention_prunes_its_succession()
    {
        var name = $"ret-b-{Guid.NewGuid():N}";
        var seal = await SeedSealedAsync(name);
        await DeleteAsync(name, seal.Id);

        await using (var db = Context(name))
            await Build(name, db).RunAsync(CancellationToken.None);

        await AssertTailAsync(name, RetiredChainState.TailMissing);
        await AssertNextStartSealsNothingAsync(name);
        await AssertTailAsync(name, RetiredChainState.TailMissing);
        await using (var db = Context(name))
        {
            Assert.Equal(0, await db.AuditLogs.CountAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction));
            var succession = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction);
            Assert.True(succession.Timestamp > DateTime.UtcNow.AddDays(-30));
            Assert.Contains(seal.Id.ToString(), succession.DetailsJson);
            Assert.Contains(seal.RecordHash!, succession.DetailsJson);
            Assert.Empty((await new AuditHashChainService().VerifyAsync(db, null)).Breaks);
        }
    }

    /// <summary>
    /// Review 2, 1(c): the retired chain was rewritten and its hashes recomputed through a new seal.
    /// When retention prunes the original succession, its copy still names the original hash, so the
    /// chain keeps reading TailAltered instead of the rewritten seal being anchored.
    /// </summary>
    [Fact]
    public async Task A_rewritten_seal_is_not_anchored_when_retention_prunes_its_succession()
    {
        var name = $"ret-c-{Guid.NewGuid():N}";
        await SeedSealedAsync(name);
        await using (var db = Context(name))
        {
            var rows = await db.AuditLogs.Where(a => a.TenantId == SpaceA).OrderBy(a => a.Timestamp).ThenBy(a => a.Id).ToListAsync();
            rows[0].ActorUsername = "someone-else";
            string? previous = null;
            foreach (var row in rows)
            {
                row.PreviousRecordHash = previous;
                row.RecordHash = AuditHashChainService.ComputeHash(row, previous);
                previous = row.RecordHash;
            }
            await db.SaveChangesAsync();
            Assert.Empty((await new AuditHashChainService().VerifyAsync(db, SpaceA)).Breaks);
        }
        await AssertTailAsync(name, RetiredChainState.TailAltered);

        await using (var db = Context(name))
            await Build(name, db).RunAsync(CancellationToken.None);

        await AssertTailAsync(name, RetiredChainState.TailAltered);
        await AssertNextStartSealsNothingAsync(name);
        await AssertTailAsync(name, RetiredChainState.TailAltered);
    }

    /// <summary>
    /// Review 2, 1(d): the run dies (its context gone, nothing more reaches the database) in the
    /// instance-chain batch after the one that deleted the succession record. The copy was written
    /// with that delete, so the chain reads Sealed with the original details, and a seal deleted
    /// afterwards reads TailMissing rather than Unsealed.
    /// </summary>
    [Fact]
    public async Task A_crash_after_the_succession_is_deleted_leaves_its_copy_behind()
    {
        var name = $"ret-d-{Guid.NewGuid():N}";
        var seal = await SeedSealedAsync(name);
        string original;
        await using (var db = Context(name))
            original = (await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction)).DetailsJson!;

        await using (var db = Context(name))
        {
            var job = Build(name, db);
            var instanceBatches = 0;
            job.BeforeBatch = (_, space) =>
            {
                if (space == null && ++instanceBatches == 3)
                {
                    db.Dispose();
                    throw new InvalidOperationException("simulated crash");
                }
            };
            await job.RunAsync(CancellationToken.None);
            Assert.Equal(3, instanceBatches);
        }

        await using (var db = Context(name))
        {
            var cutoff = DateTime.UtcNow.AddDays(-30);
            Assert.Equal(2, await db.AuditLogs.CountAsync(a => a.TenantId == null && a.Timestamp < cutoff));
            var succession = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction);
            Assert.Equal(original, succession.DetailsJson);
        }
        await AssertTailAsync(name, RetiredChainState.Sealed);

        await DeleteAsync(name, seal.Id);
        await AssertTailAsync(name, RetiredChainState.TailMissing);
        await AssertNextStartSealsNothingAsync(name);
        await AssertTailAsync(name, RetiredChainState.TailMissing);
    }

    /// <summary>
    /// Archiving takes exactly the rows the run deletes: a retired chain's records before its seal
    /// the first time, and its kept seal and markers never, so a second run archives nothing.
    /// </summary>
    [Fact]
    public async Task Archiving_takes_only_the_rows_it_deletes_so_a_kept_seal_is_not_archived_again()
    {
        var name = $"ret-archive-{Guid.NewGuid():N}";
        var seal = await SeedSealedAsync(name);
        var root = Path.Combine(Path.GetTempPath(), $"mca-archive-{Guid.NewGuid():N}");
        try
        {
            static List<(Guid Id, Guid? Space)> Archived(string dir)
            {
                var rows = new List<(Guid, Guid?)>();
                foreach (var file in Directory.GetFiles(dir, "audit-AuditLogs-*.jsonl.gz"))
                {
                    using var gz = new System.IO.Compression.GZipStream(File.OpenRead(file), System.IO.Compression.CompressionMode.Decompress);
                    using var reader = new StreamReader(gz);
                    while (reader.ReadLine() is { Length: > 0 } line)
                    {
                        using var json = System.Text.Json.JsonDocument.Parse(line);
                        var space = json.RootElement.GetProperty("TenantId");
                        rows.Add((json.RootElement.GetProperty("Id").GetGuid(),
                            space.ValueKind == System.Text.Json.JsonValueKind.Null ? null : space.GetGuid()));
                    }
                }
                return rows;
            }

            var first = Path.Combine(root, "1");
            await using (var db = Context(name))
                await Build(name, db, first).RunAsync(CancellationToken.None);
            var firstRows = Archived(first);
            Assert.Equal(3, firstRows.Count(r => r.Space == SpaceA));
            Assert.DoesNotContain(firstRows, r => r.Id == seal.Id);
            Assert.Equal(6, firstRows.Count(r => r.Space == null));

            var second = Path.Combine(root, "2");
            await using (var db = Context(name))
                await Build(name, db, second).RunAsync(CancellationToken.None);
            Assert.Empty(Archived(second));
            await AssertTailAsync(name, RetiredChainState.Sealed);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }
}
