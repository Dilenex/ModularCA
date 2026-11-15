using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Ocsp;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Ocsp;
using Xunit;

namespace ModularCA.Tests.Modes;

/// <summary>A gate that answers one mode, which a test may change.</summary>
internal sealed class FixedModeGate(InstanceMode mode) : IInstanceModeGate
{
    public InstanceMode Mode { get; set; } = mode;
    public InstanceModeRecord Current => new(Mode, Mode == InstanceMode.Full ? InstanceModeSource.Default : InstanceModeSource.Hub);
}

/// <summary>
/// The places below the request filter that ask the mode: the scheduler before a job, the OCSP
/// responder, the CRL signer, and the node before it asks the signer to generate a key.
/// </summary>
public sealed class ModeGateServiceTests
{
    private class NoSigner : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
            => throw new InvalidOperationException($"The signer was asked: {targetMethod?.Name}");
    }

    private static ISigningService Signer() => DispatchProxy.Create<ISigningService, NoSigner>();

    private sealed class Lines : ILogger<SchedulerService>
    {
        public List<(LogLevel Level, string Text)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    private static Type JobRoles => ApiAssembly.TypeNamed("ModularCA.API.Startup.SchedulerJobRoles");

    private static IReadOnlyDictionary<Type, ModeOperation> JobClasses
        => (IReadOnlyDictionary<Type, ModeOperation>)JobRoles.GetField("ModeOperations")!.GetValue(null)!;

    private static Func<Type, ModeOperation> ClassOf
        => JobRoles.GetMethod("ModeOperationOf", [typeof(Type)])!.CreateDelegate<Func<Type, ModeOperation>>();

    private static (Func<List<string>> Held, Lines Log) Scheduler(IInstanceModeGate? gate)
    {
        var log = new Lines();
        var scheduler = new SchedulerService(new ServiceCollection().BuildServiceProvider(), log, new SystemConfig(),
            new FixedTimeProvider(DateTimeOffset.UnixEpoch), null, gate, gate == null ? null : ClassOf);
        var held = typeof(SchedulerService).GetMethod("HeldForMode", BindingFlags.NonPublic | BindingFlags.Instance)!;
        IReadOnlyList<Type> jobs = JobClasses.Keys.ToList();
        return (() => ((HashSet<Type>)held.Invoke(scheduler, [jobs])!).Select(t => t.Name).Order().ToList(), log);
    }

    [Fact]
    public void Every_scheduled_job_has_a_mode_class_and_the_table_names_only_jobs()
    {
        var owners = (System.Collections.IDictionary)JobRoles.GetField("Owners")!.GetValue(null)!;
        Assert.Equal(owners.Keys.Cast<Type>().Select(t => t.Name).Order(), JobClasses.Keys.Select(t => t.Name).Order());
        Assert.All(JobClasses.Keys, t => Assert.True(typeof(ISchedulerJob).IsAssignableFrom(t)));
    }

    [Fact]
    public void An_unlisted_job_and_an_unknown_job_name_are_not_let_through()
    {
        var ex = Assert.Throws<TargetInvocationException>(() => JobRoles.GetMethod("ModeOperationOf", [typeof(Type)])!.Invoke(null, [typeof(string)]));
        Assert.IsType<InvalidOperationException>(ex.InnerException);

        var byName = JobRoles.GetMethod("ModeOperationOfName")!;
        Assert.Equal(ModeOperation.Frozen, byName.Invoke(null, ["NoSuchJob"]));
        Assert.Equal(ModeOperation.Issue, byName.Invoke(null, ["AutoRenewal"]));
        Assert.Equal(ModeOperation.Fact, byName.Invoke(null, ["Compliance"]));
        Assert.Equal(ModeOperation.Manage, byName.Invoke(null, ["BackupCreation"]));
    }

    [Fact]
    public void With_no_gate_and_in_full_mode_the_scheduler_holds_nothing()
    {
        Assert.Empty(Scheduler(null).Held());
        Assert.Empty(Scheduler(FullInstanceModeGate.Instance).Held());
        Assert.Empty(Scheduler(new FixedModeGate(InstanceMode.Full)).Held());
    }

    [Fact]
    public void While_restricted_scheduled_issuance_continues_and_only_the_frozen_jobs_are_held()
    {
        var (held, log) = Scheduler(new FixedModeGate(InstanceMode.Restricted));

        Assert.Equal([nameof(AuditRetentionJob), nameof(LdapGroupSyncJob)], held());
        held();

        var said = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, said.Level);
        Assert.Contains("restricted mode", said.Text);
        Assert.DoesNotContain(nameof(AutoRenewalJob), said.Text);
    }

    /// <summary>
    /// Maintenance stops scheduled renewal with the jobs restricted mode already holds. CRL
    /// export, the LDAP publisher and expiry go on: a relying party still gets fresh revocation
    /// data while the instance is being worked on.
    /// </summary>
    [Fact]
    public void In_maintenance_scheduled_renewal_is_held_and_CRLs_are_still_exported()
    {
        var (held, log) = Scheduler(new FixedModeGate(InstanceMode.Maintenance));

        Assert.Equal([nameof(AuditRetentionJob), nameof(AutoRenewalJob), nameof(LdapGroupSyncJob)], held().Order());
        Assert.Contains("maintenance mode", Assert.Single(log.Entries).Text);
    }

    [Fact]
    public void In_DR_mode_every_job_but_the_backups_is_held_and_runs_again_when_the_mode_allows()
    {
        var gate = new FixedModeGate(InstanceMode.DisasterRecovery);
        var (held, _) = Scheduler(gate);

        var inDr = held();
        Assert.Contains(nameof(AutoRenewalJob), inDr);
        Assert.Contains(nameof(CrlExportJob), inDr);
        Assert.Contains(nameof(SshLoginNameSweepJob), inDr);
        Assert.DoesNotContain(nameof(BackupCreationJob), inDr);
        Assert.DoesNotContain(nameof(BackupVerificationJob), inDr);
        Assert.Equal(JobClasses.Count - 2, inDr.Count);

        gate.Mode = InstanceMode.Full;
        Assert.Empty(held());
    }

    [Fact]
    public async Task In_DR_mode_OCSP_answers_try_later_without_reading_or_signing_anything()
    {
        var responder = new OcspResponderService(null!, null!, NullLogger<OcspResponderService>.Instance, null!, Signer(),
            new FixedModeGate(InstanceMode.DisasterRecovery));
        var result = new OcspProcessingResult();

        var der = await responder.ProcessOcspRequestAsync([0x30, 0x00], null, result);

        Assert.Equal(OcspRespStatus.TryLater, new OcspResp(der).Status);
        Assert.Equal("tryLater", result.Status);
    }

    [Theory]
    [InlineData(InstanceMode.Full)]
    [InlineData(InstanceMode.Restricted)]
    [InlineData(InstanceMode.Maintenance)]
    public async Task Outside_DR_mode_the_OCSP_responder_goes_on_to_the_request(InstanceMode mode)
    {
        var responder = new OcspResponderService(null!, null!, NullLogger<OcspResponderService>.Instance, null!, Signer(), new FixedModeGate(mode));

        // Past the gate the responder reads its policy, which this test does not supply.
        await Assert.ThrowsAsync<NullReferenceException>(() => responder.ProcessOcspRequestAsync([0x30, 0x00], null, new OcspProcessingResult()));
    }

    [Fact]
    public async Task In_DR_mode_no_new_CRL_is_signed()
    {
        var crl = new CrlService(null!, null!, NullLogger<CrlService>.Instance, null!, null!, null!, Signer(), new FixedModeGate(InstanceMode.DisasterRecovery));

        var full = await Assert.ThrowsAsync<InstanceModeException>(() => crl.GenerateCrlAsync(Guid.NewGuid()));
        var delta = await Assert.ThrowsAsync<InstanceModeException>(() => crl.GenerateDeltaCrlAsync(Guid.NewGuid()));

        Assert.Equal(InstanceMode.DisasterRecovery, full.Mode);
        Assert.Contains("Signing a new CRL", full.Message);
        Assert.Contains("delta", delta.Message);
    }

    [Theory]
    [InlineData(InstanceMode.Full)]
    [InlineData(InstanceMode.Restricted)]
    [InlineData(InstanceMode.Maintenance)]
    public async Task Outside_DR_mode_the_CRL_signer_is_not_stopped_by_the_gate(InstanceMode mode)
    {
        var crl = new CrlService(null!, null!, NullLogger<CrlService>.Instance, null!, null!, null!, Signer(), new FixedModeGate(mode));

        var ex = await Record.ExceptionAsync(() => crl.GenerateCrlAsync(Guid.NewGuid()));

        Assert.NotNull(ex);
        Assert.IsNotType<InstanceModeException>(ex);
    }

    [Theory]
    [InlineData(InstanceMode.Restricted)]
    [InlineData(InstanceMode.DisasterRecovery)]
    public async Task Outside_full_mode_the_node_refuses_to_generate_a_CA_key_before_it_asks_the_signer(InstanceMode mode)
    {
        using var db = InMemoryDbContextFactory.Create();
        var service = new CaCreationService(db, null!, null!, null!, null!, new SystemConfig(), NullLogger<CaCreationService>.Instance,
            Signer(), null, new FixedModeGate(mode));

        // The signer double throws InvalidOperationException when asked; the gate's refusal comes first.
        var ex = await Assert.ThrowsAsync<InstanceModeException>(() => service.CreateRootAsync(
            "Mode Test Root", null, null, null, null, null, "RSA", 3072, 10, "mode-test-root", null));

        Assert.Contains("Generating a CA key", ex.Message);
    }

    [Fact]
    public async Task In_full_mode_the_node_goes_on_to_the_signer()
    {
        using var db = InMemoryDbContextFactory.Create();
        var service = new CaCreationService(db, null!, null!, null!, null!, new SystemConfig(), NullLogger<CaCreationService>.Instance,
            Signer(), null, new FixedModeGate(InstanceMode.Full));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => service.CreateRootAsync(
            "Mode Test Root", null, null, null, null, null, "RSA", 3072, 10, "mode-test-root", null));

        Assert.Contains("GenerateKeyAsync", ex.Message);
    }
}
