using Microsoft.Extensions.Logging;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that revokes the live SSH certificates the login name rules no longer allow:
/// one whose user is not active, was deleted, was renamed or may no longer request from the SSH
/// CA, and one that carries a login name its subject no longer holds (see
/// <see cref="ISshLoginNameService.SweepAsync"/>).
/// </summary>
/// <remarks>
/// <para>
/// Each of those is revoked by a hook that runs right after the change is saved: a grant
/// removed, a user taken out of a group, a role or a capability taken away, a user disabled or
/// deleted. The hook is not one transaction with its change, so a node that stops between the
/// two leaves the certificate live with nothing to come back for it. This job is that
/// backstop, across every SSH CA key. It is also what revokes after a change to rights that no
/// hook follows.
/// </para>
/// <para>
/// There is no master <c>Enabled</c> gate: a pass that finds nothing writes nothing, and one
/// that finds a certificate revokes it exactly as the hook would have.
/// </para>
/// </remarks>
public class SshLoginNameSweepJob : SingletonCronJob
{
    private readonly ILogger<SshLoginNameSweepJob> _logger;
    private readonly IAuditService _audit;
    private readonly SystemConfig _config;
    private readonly ISshLoginNameService _loginNames;

    /// <summary>
    /// Initializes a new instance of <see cref="SshLoginNameSweepJob"/> with the standard
    /// <see cref="SingletonCronJob"/> dependencies plus the audit service and the login name
    /// service whose sweep it runs.
    /// </summary>
    public SshLoginNameSweepJob(
        ILogger<SshLoginNameSweepJob> logger,
        IAuditService audit,
        SystemConfig config,
        ISshLoginNameService loginNames,
        IServiceProvider serviceProvider,
        SchedulerJobRunner runner,
        TimeProvider? timeProvider = null)
        : base(serviceProvider, logger, config, runner, timeProvider)
    {
        _logger = logger;
        _audit = audit;
        _config = config;
        _loginNames = loginNames;
    }

    /// <inheritdoc />
    public override string Name => "SshLoginNameSweep";

    /// <summary>Cron expression from <c>SshLoginNameSweep.Schedule</c>. No master enabled gate.</summary>
    protected override string CronExpression => _config.SshLoginNameSweep.Schedule;

    /// <summary>
    /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an operator
    /// clicks "Run Now" on the admin Schedules page, bypassing the cron past-due gate.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);

    /// <summary>
    /// Runs one sweep and returns what it revoked. Each revocation has its own
    /// <c>SshCertRevoked</c> audit entry, written by the service and naming the scheduler; a
    /// sweep that revoked anything adds one <c>SshLoginNameSweepCompleted</c> entry with the counts.
    /// </summary>
    public async Task<SshLoginNameSweep> RunOnceAsync(CancellationToken cancellationToken)
    {
        var result = await _loginNames.SweepAsync(new SshCaActor(null, SchedulerService.AuditActor), cancellationToken);
        if (result.Total > 0)
        {
            _logger.LogInformation(
                "Revoked {Count} SSH certificate(s): {UserNotActive} of a user that is not active, {UserDeleted} of a deleted user, {UserRenamed} of a renamed user, {RequestRightLost} of a user who may no longer request, {LoginNameLost} with a login name no longer held.",
                result.Total, result.UserNotActive, result.UserDeleted, result.UserRenamed, result.RequestRightLost, result.LoginNameLost);
            await _audit.LogAsync(AuditActionType.SshLoginNameSweepCompleted, null, SchedulerService.AuditActor,
                details: new { result.UserNotActive, result.UserDeleted, result.UserRenamed, result.RequestRightLost, result.LoginNameLost });
        }
        return result;
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken cancellationToken) => RunOnceAsync(cancellationToken);
}
