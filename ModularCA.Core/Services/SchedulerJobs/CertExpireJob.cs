using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that observes certificates that have passed their <c>NotAfter</c> and
/// emits a single <c>ExpiredCertificatesRevoked</c> audit row per cron tick.
/// <para>
/// Audit #36: this job replaces the old <c>CertExpireService</c>, which ran on every
/// 30 s scheduler poll and therefore emitted duplicate audit rows continuously while
/// any expired certificate sat on disk. Moving to <see cref="SingletonCronJob"/> means
/// the audit trail reflects one observation per
/// <see cref="CertPolicyConfig.ExpireCheckSchedule"/> occurrence.
/// </para>
/// <para>
/// This job intentionally does NOT flip <c>Revoked=true</c> on
/// naturally-expired certs — CRLs exclude expired entries per RFC 5280 §3.3 and an
/// "Expired" revocation reason confuses the audit trail with genuine revocations. The
/// method remains as a hook for audit emission and metric accounting so operators still
/// see when expiry processing ran and how many rows were observed.
/// </para>
/// </summary>
public class CertExpireJob : SingletonCronJob
{
    private readonly ModularCADbContext _dbContext;
    private readonly ILogger<CertExpireJob> _logger;
    private readonly IAuditService _audit;
    private readonly SystemConfig _config;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertExpireJob"/> class.
    /// </summary>
    public CertExpireJob(
        IServiceProvider serviceProvider,
        ModularCADbContext dbContext,
        ILogger<CertExpireJob> logger,
        IAuditService audit,
        SystemConfig config,
        SchedulerJobRunner runner)
        : base(serviceProvider, logger, config, runner)
    {
        _dbContext = dbContext;
        _logger = logger;
        _audit = audit;
        _config = config;
    }

    /// <inheritdoc />
    public override string Name => "CertExpire";

    /// <summary>
    /// Cron expression for the expired-certificate sweep. Returns <see cref="string.Empty"/>
    /// when <see cref="CertPolicyConfig.Enabled"/> is false so the base
    /// <see cref="SingletonCronJob.TickAsync"/> treats the job as disabled and writes no state.
    /// </summary>
    protected override string CronExpression =>
        _config.CertPolicy.Enabled
            ? _config.CertPolicy.ExpireCheckSchedule
            : string.Empty;

    /// <summary>
    /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an
    /// operator clicks "Run Now" for this job — bypassing the cron past-due gate that
    /// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
    /// regardless of schedule. The protected <see cref="ExecuteAsync"/> body is invoked
    /// directly.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);

    /// <summary>
    /// Counts expired-but-not-revoked certificates and emits an
    /// <c>ExpiredCertificatesRevoked</c> audit row when the count is non-zero. Does not
    /// mutate certificate rows — see class-level remarks for the rationale. Exceptions
    /// propagate to <see cref="SchedulerJobRunner"/> for metrics/audit/alert handling.
    /// </summary>
    protected override Task ExecuteAsync(CancellationToken cancellationToken)
        => MarkExpiredCertificatesAsync();

    /// <summary>
    /// Previously this method set <c>Revoked=true</c> + <c>RevocationReason="Expired"</c>
    /// on naturally-expired certs, which caused two defects: (1) expired entries remained on
    /// the CRL indefinitely (RFC 5280 §3.3 explicitly permits removal of expired entries),
    /// and (2) the audit trail became indistinguishable from an active revocation. The new
    /// behaviour simply relies on <c>NotAfter &lt; now</c> at query time — no schema change,
    /// no CRL pollution. The method is kept as a hook for audit emission and metric
    /// accounting so operators still see when expiry processing ran and how many rows were
    /// observed.
    /// </summary>
    private async Task MarkExpiredCertificatesAsync()
    {
        var now = TimeProvider.GetUtcNow().UtcDateTime;
        var expiredCount = await _dbContext.Certificates
            .Where(c => c.NotAfter < now && !c.Revoked)
            .CountAsync();

        if (expiredCount > 0)
        {
            await _audit.LogAsync(AuditActionType.ExpiredCertificatesRevoked, null, SchedulerService.AuditActor,
                details: new { Count = expiredCount, Note = "Observed expired certificates (NotAfter < now). No revocation write — CRLs exclude expired entries per RFC 5280 §3.3." });
        }
    }
}
