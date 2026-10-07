using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Base class for jobs that own multiple per-row schedules (CRL export per CA, LDAP publish
/// per (Space, CA, target)). Each tick walks <see cref="RowsAsync"/>, dispatches every row
/// whose <c>NextRunUtc</c> projection is past due, and advances that row's next-run timestamp
/// after a successful execution.
/// </summary>
/// <remarks>
/// <para>
/// Uses an adapter pattern (projector functions) instead of forcing rows to implement an
/// <c>IScheduledRow</c> interface — entities like <c>CrlConfigurationEntity</c> have non-conforming
/// PK names (<c>TaskId</c>) and adding a behavioral interface to <c>ModularCA.Shared.Entities</c>
/// would force every row type into the same shape. The projectors keep the data model unchanged.
/// </para>
/// <para>
/// Each row dispatch is its own <see cref="SchedulerJobRunner.RunAsync"/> invocation with a
/// per-row <c>jobName</c> of the form <c>"{BaseName}:{rowId}"</c>. That gives every row its own
/// <c>SchedulerJobStates</c> entry and consecutive-failure counter, while the timeout config
/// resolves against the bare <c>{BaseName}</c> prefix so all rows share the same timeout class.
/// </para>
/// <para>
/// Subclasses with custom dispatch needs (e.g. multiple cadences per row) can override
/// <see cref="TickAsync"/> and call <see cref="RunRowAsync"/> directly per row.
/// </para>
/// </remarks>
/// <typeparam name="TRow">The row entity type (e.g. <c>CrlConfigurationEntity</c>).</typeparam>
public abstract class PerRowScheduledJob<TRow> : ISchedulerJob where TRow : class
{
    /// <summary>Service provider used to resolve scoped services per row.</summary>
    protected readonly IServiceProvider ServiceProvider;

    /// <summary>Logger scoped to the concrete job class.</summary>
    protected readonly ILogger Logger;

    /// <summary>Solution-wide config snapshot.</summary>
    protected readonly SystemConfig Config;

    /// <summary>Shared runner used to invoke per-row execution with metrics/audit/state.</summary>
    protected readonly SchedulerJobRunner Runner;

    /// <summary>
    /// Time provider used by the base class for next-run math and exposed to subclasses that
    /// need to override <see cref="TickAsync"/> with custom dispatch logic (e.g. CRL's dual
    /// cadence). Tests inject a fake via the constructor; subclasses MUST read this rather
    /// than <c>DateTime.UtcNow</c> to keep deterministic behavior under test fakes.
    /// </summary>
    protected readonly TimeProvider TimeProvider;

    /// <summary>Initializes the base. Concrete jobs request these via constructor injection.</summary>
    protected PerRowScheduledJob(
        IServiceProvider serviceProvider,
        ILogger logger,
        SystemConfig config,
        SchedulerJobRunner runner,
        TimeProvider? timeProvider = null)
    {
        ServiceProvider = serviceProvider;
        Logger = logger;
        Config = config;
        Runner = runner;
        TimeProvider = timeProvider ?? System.TimeProvider.System;
    }

    /// <inheritdoc />
    public abstract string Name { get; }

    /// <summary>
    /// Loads the candidate rows for this tick. Concrete jobs apply their own filters here
    /// (e.g. <c>Enabled = true</c>, master-policy gating). Returns an empty list when nothing
    /// should be considered.
    /// </summary>
    /// <param name="db">DbContext from a scope owned by the caller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected abstract Task<IReadOnlyList<TRow>> RowsAsync(ModularCADbContext db, CancellationToken cancellationToken);

    /// <summary>Returns the row's stable identifier. Used to build the per-row <c>jobName</c>.</summary>
    protected abstract Guid IdOf(TRow row);

    /// <summary>Returns the row's current <c>NextRunUtc</c> projection.</summary>
    protected abstract DateTime NextRunUtcOf(TRow row);

    /// <summary>
    /// Performs the actual per-row work. Receives a per-row cancellation token already linked
    /// to the configured timeout. The base class handles state persistence and next-run
    /// advancement after this returns.
    /// </summary>
    protected abstract Task ExecuteRowAsync(TRow row, CancellationToken cancellationToken);

    /// <inheritdoc />
    public virtual async Task TickAsync(CancellationToken cancellationToken)
    {
        var now = TimeProvider.GetUtcNow().UtcDateTime;
        IReadOnlyList<TRow> rows;

        await using (var scope = ServiceProvider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            rows = await RowsAsync(db, cancellationToken);
        }

        foreach (var row in rows)
        {
            if (cancellationToken.IsCancellationRequested) break;
            if (NextRunUtcOf(row) > now) continue;

            await RunRowAsync(row, cancellationToken);
        }
    }

    /// <summary>
    /// Runs a single row through the shared runner. Per the <c>SchedulerJobRunner</c> contract,
    /// per-row jobs pass <c>nextRunOverride: null</c> because the row's <c>NextRunUtc</c> lives
    /// on the row entity itself (e.g. <c>CrlConfigurationEntity.NextUpdateUtc</c>,
    /// <c>LdapConfigurationEntity.NextUpdateUtc</c>) and is advanced inside
    /// <see cref="ExecuteRowAsync"/>. Exposed <c>protected</c> so subclasses with custom
    /// dispatch logic can call it directly.
    /// </summary>
    protected Task RunRowAsync(TRow row, CancellationToken cancellationToken)
    {
        var jobName = $"{Name}:{IdOf(row)}";
        return Runner.RunAsync(
            jobName,
            ct => ExecuteRowAsync(row, ct),
            cancellationToken,
            cronAnchor: null,
            nextRunOverride: null);
    }
}
