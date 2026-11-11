using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// After a start the scheduler holds the jobs that need the signer until the signer has answered
/// once: a node is up a few seconds before a separate signer listens, and a CRL generation run in
/// that window logged a failure on every ordinary start. The hold must not hide an outage: it ends
/// for good at the first answer, and after five minutes without one.
/// </summary>
public sealed class SchedulerSignerHoldTests
{
    /// <summary>An <see cref="ISigningService"/> that answers only <c>HealthAsync</c>, with whatever the test set.</summary>
    public class Signer : DispatchProxy
    {
        public Func<SignerHealth> Health { get; set; } = SignerHealth.Unreachable;
        public int Calls { get; private set; }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod?.Name != nameof(ISigningService.HealthAsync))
                throw new NotSupportedException(targetMethod?.Name);
            Calls++;
            return Task.FromResult(Health());
        }
    }

    private sealed class Lines : ILogger<SchedulerService>
    {
        public List<(LogLevel Level, string Text)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    private sealed class World
    {
        public FixedTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 11, 10, 12, 0, 0, TimeSpan.Zero));
        public Lines Log { get; } = new();
        public ISigningService? SigningService { get; }
        public Signer? Signer { get; }
        private readonly SchedulerService _scheduler;
        private readonly IServiceProvider _services;

        public World(bool withSigner = true, params Type[] jobs)
        {
            var services = new ServiceCollection();
            if (withSigner)
            {
                SigningService = DispatchProxy.Create<ISigningService, Signer>();
                Signer = (Signer)(object)SigningService;
                services.AddSingleton(SigningService);
            }
            _services = services.BuildServiceProvider();
            _scheduler = new SchedulerService(_services, Log, new SystemConfig(), Clock);
            typeof(SchedulerService).GetField("_jobTypes", BindingFlags.NonPublic | BindingFlags.Instance)!
                .SetValue(_scheduler, jobs.Length > 0 ? jobs.ToList() : new List<Type> { typeof(CrlExportJob), typeof(CertExpireJob), typeof(AutoRenewalJob), typeof(TlsRenewalJob) });
        }

        /// <summary>One poll cycle's decision: whether the jobs that need the signer are held.</summary>
        public Task<bool> HoldsAsync() =>
            (Task<bool>)typeof(SchedulerService).GetMethod("HoldSignerJobsAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(_scheduler, [_services, CancellationToken.None])!;
    }

    private static SignerHealth Answering() => new(true, 3, SignerHealth.SoftwareBackend);

    /// <summary>The jobs that sign are the ones marked; the rest are never held.</summary>
    [Fact]
    public void The_jobs_that_have_something_signed_are_marked_and_the_others_are_not()
    {
        var marked = typeof(CrlExportJob).Assembly.GetTypes()
            .Where(t => !t.IsAbstract && typeof(ISignerDependentJob).IsAssignableFrom(t)).Select(t => t.Name).Order();

        Assert.Equal(["AutoRenewalJob", "CrlExportJob", "TlsRenewalJob"], marked);
    }

    /// <summary>While the signer has not answered, its jobs are held, and the log says so once, not every cycle.</summary>
    [Fact]
    public async Task Jobs_are_held_while_the_signer_has_not_answered_and_the_log_says_so_once()
    {
        var w = new World();

        Assert.True(await w.HoldsAsync());
        w.Clock.Now += TimeSpan.FromSeconds(5);
        Assert.True(await w.HoldsAsync());

        var said = Assert.Single(w.Log.Entries);
        Assert.Equal(LogLevel.Information, said.Level);
        Assert.Contains("CrlExportJob", said.Text);
        Assert.Contains("AutoRenewalJob", said.Text);
        Assert.DoesNotContain("CertExpireJob", said.Text);
    }

    /// <summary>
    /// The first answer ends the hold for good. A signer that goes silent afterwards is a fault:
    /// the jobs run and report it, and the scheduler does not even ask again.
    /// </summary>
    [Fact]
    public async Task The_first_answer_ends_the_hold_for_good()
    {
        var w = new World();
        Assert.True(await w.HoldsAsync());

        w.Signer!.Health = Answering;
        Assert.False(await w.HoldsAsync());
        Assert.Contains(w.Log.Entries, e => e.Level == LogLevel.Information && e.Text.Contains("The signer answered"));

        w.Signer.Health = SignerHealth.Unreachable;
        var calls = w.Signer.Calls;
        Assert.False(await w.HoldsAsync());
        Assert.False(await w.HoldsAsync());
        Assert.Equal(calls, w.Signer.Calls);
    }

    /// <summary>A signer that answers at the first cycle (in process, or already up) holds nothing and logs nothing.</summary>
    [Fact]
    public async Task A_signer_that_answers_at_once_holds_nothing_and_says_nothing()
    {
        var w = new World();
        w.Signer!.Health = Answering;

        Assert.False(await w.HoldsAsync());
        Assert.Empty(w.Log.Entries);
    }

    /// <summary>
    /// A signer that answers but is locked has answered: the jobs run and report what is wrong.
    /// Only "did not answer at all" is waited for.
    /// </summary>
    [Fact]
    public async Task A_signer_that_answers_locked_is_not_waited_for()
    {
        var w = new World();
        w.Signer!.Health = () => new SignerHealth(false, 0, SignerHealth.SoftwareBackend);

        Assert.False(await w.HoldsAsync());
    }

    /// <summary>
    /// The hold is bounded: a signer still silent after the grace is an outage, so the jobs are
    /// released to fail and log as they always have, with a warning that says why.
    /// </summary>
    [Fact]
    public async Task After_the_grace_the_jobs_run_even_though_the_signer_never_answered()
    {
        var w = new World();
        Assert.True(await w.HoldsAsync());

        w.Clock.Now += SchedulerService.SignerStartGrace - TimeSpan.FromSeconds(1);
        Assert.True(await w.HoldsAsync());

        w.Clock.Now += TimeSpan.FromSeconds(1);
        Assert.False(await w.HoldsAsync());
        Assert.Contains(w.Log.Entries, e => e.Level == LogLevel.Warning && e.Text.Contains("has not answered"));
        Assert.False(await w.HoldsAsync());
    }

    /// <summary>A process with no signing service, or with no job that needs one, waits for nothing.</summary>
    [Fact]
    public async Task Nothing_is_held_without_a_signing_service_or_without_a_job_that_needs_it()
    {
        Assert.False(await new World(withSigner: false).HoldsAsync());

        var noSignerJobs = new World(withSigner: true, typeof(CertExpireJob));
        Assert.False(await noSignerJobs.HoldsAsync());
        Assert.Equal(0, noSignerJobs.Signer!.Calls);
    }

    /// <summary>A health call that throws is not "has not answered yet": the jobs run, and the log has the error.</summary>
    [Fact]
    public async Task A_health_call_that_throws_does_not_hold_the_jobs()
    {
        var w = new World();
        w.Signer!.Health = () => throw new InvalidOperationException("broken channel");

        Assert.False(await w.HoldsAsync());
        Assert.Contains(w.Log.Entries, e => e.Level == LogLevel.Warning);
    }
}
