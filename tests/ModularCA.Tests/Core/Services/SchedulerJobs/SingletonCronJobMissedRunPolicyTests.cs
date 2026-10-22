using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.SchedulerJobs;

/// <summary>
/// <c>Scheduler.MissedRunPolicy</c> is marked Live: a job that has never run reads it on the
/// tick, so a policy saved while the scheduler runs decides the next tick, not the next start.
/// </summary>
public class SingletonCronJobMissedRunPolicyTests
{
    private sealed class TestJob(IServiceProvider sp, SystemConfig config, SchedulerJobRunner runner, TimeProvider time)
        : SingletonCronJob(sp, NullLogger.Instance, config, runner, time)
    {
        public int Runs;
        public override string Name => "MissedRunPolicyTestJob";
        protected override string CronExpression => "0 5 * * *";

        protected override Task ExecuteAsync(CancellationToken cancellationToken)
        {
            Runs++;
            return Task.CompletedTask;
        }
    }

    private static (TestJob Job, SystemConfig Config) Build()
    {
        var dbName = $"test-{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddDbContext<ModularCADbContext>(opts => opts
            .UseInMemoryDatabase(dbName)
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning)));
        var sp = services.BuildServiceProvider();

        var time = new FixedTimeProvider(new DateTimeOffset(2026, 4, 26, 7, 0, 0, TimeSpan.Zero));
        var config = new SystemConfig();
        var runner = new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test", time);
        return (new TestJob(sp, config, runner, time), config);
    }

    [Fact]
    public async Task A_job_with_no_earlier_run_follows_the_policy_as_it_is_saved()
    {
        var (job, config) = Build();

        config.Scheduler.MissedRunPolicy = "SkipMissed";
        await job.TickAsync(CancellationToken.None);
        Assert.Equal(0, job.Runs);

        config.Scheduler.MissedRunPolicy = "RunOnce";
        await job.TickAsync(CancellationToken.None);
        Assert.Equal(1, job.Runs);
    }
}
