using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that clears what a failed protocol enrollment leaves behind: certificate
/// request rows that were written for issuance and never issued, and SCEP and CMP transaction
/// rows past their lifetime.
/// </summary>
/// <remarks>
/// <para>
/// Every protocol pipeline (EST, MSAE, SCEP, CMP, ACME) persists a request row and then asks
/// the issuer to sign. When the issuer refuses, whether a policy check or a signing failure, the
/// refusal goes back to the client and the row stays <c>Pending</c> with nothing to issue it: no
/// operator will act on it, the client has already moved on, and it accumulates in the request
/// list. Seen on the staging host after a Windows client's request was refused on its signature
/// algorithm. This job removes such rows once they are older than a grace window, so a request
/// that is genuinely mid-flight is never touched.
/// </para>
/// <para>
/// A row is an orphan only when all of these hold: status <c>Pending</c> (not
/// <c>PendingApproval</c>, which an approver owns), no issued certificate, no requesting user
/// (a person's upload waits for a person), no approval records, not referenced by an ACME order
/// (the order keeps it for diagnostics), and submitted before the grace cutoff.
/// </para>
/// <para>
/// The SCEP and CMP transaction sweeps used to ride on the ACME cleanup tick, after an early
/// return that fired whenever ACME had nothing to do, so on a host without ACME traffic they
/// never ran. They live here now and run every tick. There is no master <c>Enabled</c> gate:
/// each step is idempotent and cheap when there is nothing to do.
/// </para>
/// </remarks>
public class ProtocolCleanupJob : SingletonCronJob
{
    private readonly ILogger<ProtocolCleanupJob> _logger;
    private readonly ModularCADbContext _db;
    private readonly IAuditService _audit;
    private readonly SystemConfig _config;

    /// <summary>Status of a request written for immediate issuance that has not been issued.</summary>
    public const string PendingStatus = "Pending";

    /// <summary>How long a CMP transaction row is kept after creation before it is swept.</summary>
    public static readonly TimeSpan CmpTransactionLifetime = TimeSpan.FromHours(1);

    /// <summary>
    /// Initializes a new instance of <see cref="ProtocolCleanupJob"/> with the standard
    /// <see cref="SingletonCronJob"/> dependencies plus the database and audit service.
    /// </summary>
    public ProtocolCleanupJob(
        ILogger<ProtocolCleanupJob> logger,
        ModularCADbContext db,
        IAuditService audit,
        SystemConfig config,
        IServiceProvider serviceProvider,
        SchedulerJobRunner runner,
        TimeProvider? timeProvider = null)
        : base(serviceProvider, logger, config, runner, timeProvider)
    {
        _logger = logger;
        _db = db;
        _audit = audit;
        _config = config;
    }

    /// <inheritdoc />
    public override string Name => "ProtocolCleanup";

    /// <summary>Cron expression from <c>ProtocolCleanup.Schedule</c>. No master enabled gate.</summary>
    protected override string CronExpression => _config.ProtocolCleanup.Schedule;

    /// <summary>
    /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an operator
    /// clicks "Run Now" on the admin Schedules page, bypassing the cron past-due gate.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);

    /// <summary>Runs one cleanup pass and returns what it removed.</summary>
    public async Task<CleanupResult> RunOnceAsync(CancellationToken cancellationToken)
    {
        var now = TimeProvider.GetUtcNow().UtcDateTime;

        var graceMinutes = Math.Max(1, _config.ProtocolCleanup.OrphanRequestGraceMinutes);
        var orphanCutoff = now.AddMinutes(-graceMinutes);
        var referencedByAcme = _db.AcmeOrders.Where(o => o.FinalizedCsrId != null).Select(o => o.FinalizedCsrId!.Value);
        var withApprovals = _db.CsrApprovals.Select(a => a.CertRequestId);
        var orphans = await _db.CertificateRequests
            .Where(r => r.Status == PendingStatus
                && r.IssuedCertificateId == null
                && r.RequestorUserId == null
                && r.SubmittedAt < orphanCutoff
                && !referencedByAcme.Contains(r.Id)
                && !withApprovals.Contains(r.Id))
            .ToListAsync(cancellationToken);
        if (orphans.Count > 0)
        {
            _db.CertificateRequests.RemoveRange(orphans);
            await _db.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("Removed {Count} orphaned protocol enrollment request(s) older than {Grace} minutes.",
                orphans.Count, graceMinutes);
        }

        var scepExpired = await _db.ScepTransactions
            .Where(t => t.ExpiresAt < now)
            .ToListAsync(cancellationToken);
        if (scepExpired.Count > 0)
        {
            _db.ScepTransactions.RemoveRange(scepExpired);
            await _db.SaveChangesAsync(cancellationToken);
            _logger.LogDebug("Swept {Count} expired SCEP transaction row(s).", scepExpired.Count);
        }

        var cmpCutoff = now - CmpTransactionLifetime;
        var cmpExpired = await _db.CmpTransactions
            .Where(t => t.CreatedAt < cmpCutoff)
            .ToListAsync(cancellationToken);
        if (cmpExpired.Count > 0)
        {
            _db.CmpTransactions.RemoveRange(cmpExpired);
            await _db.SaveChangesAsync(cancellationToken);
            _logger.LogDebug("Swept {Count} expired CMP transaction row(s).", cmpExpired.Count);
        }

        var result = new CleanupResult(orphans.Count, scepExpired.Count, cmpExpired.Count);
        if (result.Total > 0)
        {
            await _audit.LogAsync(AuditActionType.ProtocolCleanupCompleted, null, "Scheduler",
                details: new { result.OrphanedRequests, result.ScepTransactions, result.CmpTransactions, GraceMinutes = graceMinutes });
        }
        return result;
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken cancellationToken) => RunOnceAsync(cancellationToken);

    /// <summary>What one pass removed.</summary>
    public sealed record CleanupResult(int OrphanedRequests, int ScepTransactions, int CmpTransactions)
    {
        public int Total => OrphanedRequests + ScepTransactions + CmpTransactions;
    }
}
