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

    private static TestJob Build(string name, AuditDbContext db)
    {
        var config = new SystemConfig();
        config.Audit.Retention = new AuditRetentionConfig
        {
            Enabled = true, GeneralRetentionDays = 30, NetworkRetentionDays = 0, DeleteBatchSize = 2,
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
}
