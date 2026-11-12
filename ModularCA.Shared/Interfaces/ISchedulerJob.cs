namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Contract for a scheduler-driven job. The <see cref="ModularCA.Core.Services.SchedulerService"/>
/// resolves every registered <see cref="ISchedulerJob"/> from DI on each poll cycle and invokes
/// <see cref="TickAsync"/> — each job decides what is past due in its own world (a single global
/// cron, multiple per-row schedules, etc.) and dispatches accordingly.
/// </summary>
/// <remarks>
/// <para>
/// Scheduler-side responsibilities — leader-election lease, CA-presence gate, poll cadence — stay
/// in <c>SchedulerService</c>. Job-side responsibilities — past-due math, cron evaluation, per-row
/// fan-out, persistence of <c>LastRunUtc</c>, audit emission on success/failure — live on the
/// concrete job (typically via the <c>SingletonCronJob</c> or <c>PerRowScheduledJob</c> base
/// classes that wrap the boilerplate).
/// </para>
/// <para>
/// A job's <see cref="TickAsync"/> MUST return quickly when nothing is due — no DB write, no audit,
/// no metric. Only on actual execution should the runner persist state and emit metrics.
/// </para>
/// </remarks>
public interface ISchedulerJob
{
    /// <summary>
    /// Stable identifier used for metrics, audit, and timeout lookup. Should be a constant
    /// short string per job class (e.g. <c>"BackupCreation"</c>, <c>"CrlExport"</c>). Per-row
    /// jobs append the row id at runtime (<c>"CrlExport:{guid}"</c>) inside their dispatch loop.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Called once per scheduler poll cycle. The job inspects its own state (config cron,
    /// per-row <c>NextRunUtc</c>, etc.) and dispatches whatever is past due. Returns quickly
    /// when nothing is due.
    /// </summary>
    Task TickAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Marks a scheduled job that cannot do its work without the signer: it has something signed
/// (a CRL, a certificate). After a start the scheduler holds such a job until the signer has
/// answered once, so a node that is up a few seconds before a separate signer listens does not
/// log a failed run on every ordinary start. It changes nothing once the signer has answered.
/// </summary>
public interface ISignerDependentJob : ISchedulerJob
{
}
