using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Scheduler;
using NCrontab;

namespace ModularCA.Core.Services.SchedulerJobs
{
    /// <summary>
    /// Scheduled job that generates and exports CRLs on a per-CA cron schedule.
    /// <para>
    /// Inherits <see cref="PerRowScheduledJob{TRow}"/> over <see cref="CrlConfigurationEntity"/>
    /// so the base class owns per-row past-due math against <c>NextUpdateUtc</c>, fan-out across
    /// every enabled row, and <c>SchedulerJobStates</c> persistence.
    /// </para>
    /// <para>
    /// CRL has dual-cadence semantics per row: a full CRL on <c>UpdateInterval</c>, plus an
    /// optional delta CRL when <c>DeltaInterval</c> is configured. The delta cadence is not
    /// separately persisted on the entity (no <c>NextDeltaRunUtc</c> column) — the behavior
    /// is opportunistic: when a row has <c>DeltaInterval</c> set, a delta CRL is rolled in
    /// the SAME pass as the full CRL. The per-row body in <see cref="ExecuteRowAsync"/>
    /// performs the IsDelta-aware full vs delta dispatch and the opportunistic delta-after-full
    /// regen. If the entity ever grows a separate <c>NextDeltaRunUtc</c>, override
    /// <see cref="PerRowScheduledJob{TRow}.TickAsync"/> to dispatch the two cadences independently.
    /// </para>
    /// <para>
    /// Exceptions propagate up to the shared <c>SchedulerJobRunner</c> which handles metrics,
    /// alerts, audit, and consecutive-failure escalation. Wire #11a CRL-generation audit
    /// emission is preserved.
    /// </para>
    /// <para>
    /// The <see cref="RunAsync(CrlExportScheduleOptions, string, CancellationToken)"/>
    /// entry point is retained as the operator-facing manual-run path used by
    /// <c>SchedulerJobRegistry.RunNowAsync</c> when an operator clicks "Run Now" for a
    /// specific CRL row in the admin Schedules page — bypassing the per-row past-due
    /// gate that <see cref="TickAsync"/> evaluates so the row regenerates immediately
    /// regardless of <c>NextUpdateUtc</c>.
    /// </para>
    /// </summary>
    public class CrlExportJob : PerRowScheduledJob<CrlConfigurationEntity>
    {
        private readonly ILogger<CrlExportJob> _logger;
        private readonly ICrlService _crlService;
        private readonly ModularCADbContext _db;
        private readonly IAuditService _audit;

        /// <summary>
        /// Initializes a new instance of <see cref="CrlExportJob"/>. The base class needs the
        /// service provider, runner, config, and a logger; the scoped <see cref="ModularCADbContext"/>,
        /// <see cref="ICrlService"/>, and <see cref="IAuditService"/> remain injected directly
        /// because both the <see cref="ExecuteRowAsync"/> path and the manual-run shim need them.
        /// </summary>
        public CrlExportJob(
            IServiceProvider serviceProvider,
            ILogger<CrlExportJob> logger,
            ICrlService crlService,
            ModularCADbContext db,
            IAuditService audit,
            SystemConfig config,
            SchedulerJobRunner runner)
            : base(serviceProvider, logger, config, runner)
        {
            _logger = logger;
            _crlService = crlService;
            _db = db;
            _audit = audit;
        }

        /// <inheritdoc />
        public override string Name => "CrlExport";

        /// <summary>
        /// Loads enabled <see cref="CrlConfigurationEntity"/> rows for this tick. There is no
        /// master CRL enable flag — gating is per-row via <c>CrlConfigurationEntity.Enabled</c>.
        /// </summary>
        protected override async Task<IReadOnlyList<CrlConfigurationEntity>> RowsAsync(
            ModularCADbContext db, CancellationToken cancellationToken)
        {
            return await db.CrlConfigurations
                .AsNoTracking()
                .Where(c => c.Enabled)
                .ToListAsync(cancellationToken);
        }

        /// <inheritdoc />
        protected override Guid IdOf(CrlConfigurationEntity row) => row.TaskId;

        /// <inheritdoc />
        protected override DateTime NextRunUtcOf(CrlConfigurationEntity row) => row.NextUpdateUtc;

        /// <summary>
        /// Per-row CRL pass. When there are new revoked entries we either (a) generate a
        /// delta-only CRL for <c>IsDelta=true</c> rows, or (b) generate a full CRL plus an
        /// opportunistic delta when <c>DeltaInterval</c> is configured. When there are no new
        /// entries we just advance the row's <c>NextUpdateUtc</c> and the latest
        /// <c>Crls.NextUpdate</c> mirror inside a transaction. Wire #11a audit emission is
        /// preserved on every actual CRL persist.
        /// </summary>
        protected override async Task ExecuteRowAsync(CrlConfigurationEntity row, CancellationToken cancellationToken)
        {
            var options = new CrlExportScheduleOptions
            {
                CaCertificateId = row.CaCertificateId,
                TaskId = row.TaskId,
            };
            await ExecuteCrlPassAsync(options, row.UpdateInterval, cancellationToken);
        }

        /// <summary>
        /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an
        /// operator clicks "Run Now" for a CRL configuration row in the admin Schedules page —
        /// bypassing the per-row past-due gate that <see cref="PerRowScheduledJob{TRow}.TickAsync"/>
        /// evaluates so the row regenerates immediately regardless of <c>NextUpdateUtc</c>.
        /// Delegates to the same <see cref="ExecuteCrlPassAsync"/> body that
        /// <see cref="ExecuteRowAsync"/> uses so both paths land in the same place.
        /// </summary>
        public Task RunAsync(CrlExportScheduleOptions task, string cronExpression, CancellationToken cancellationToken)
        {
            return ExecuteCrlPassAsync(task, cronExpression, cancellationToken);
        }

        /// <summary>
        /// Core per-row CRL execution body shared by the <see cref="ExecuteRowAsync"/> path
        /// and the <see cref="RunAsync(CrlExportScheduleOptions, string, CancellationToken)"/>
        /// manual-run shim. Generates or rolls a CRL for the requested CA — full + opportunistic
        /// delta when <c>IsDelta=false</c>, delta-only when <c>IsDelta=true</c>. When no new
        /// revoked entries exist since the last CRL we just advance <c>NextUpdateUtc</c> on the
        /// config row and the latest CRL row's <c>NextUpdate</c> mirror inside a transaction.
        /// Exceptions are deliberately not caught here — <c>SchedulerJobRunner.RunAsync</c>
        /// owns failure-handling (metrics, alerts, audit, consecutive-failure escalation).
        /// <para>
        /// Row state is advanced INSIDE this body rather than via the
        /// <c>PerRowScheduledJob.RunRowAsync.onSuccess</c> callback because
        /// <c>CrlConfigurationEntity.NextUpdateUtc</c> IS the source of truth — the base class's
        /// <see cref="NextRunUtcOf"/> reads it directly. The transactional read-modify-write here
        /// keeps <c>NextUpdateUtc</c> aligned with the <c>Crls.NextUpdate</c> mirror that relying
        /// parties consume; doing the advance via the runner-completion callback would split the
        /// two writes across separate scopes and risk drift. Don't refactor to use onSuccess.
        /// </para>
        /// </summary>
        private async Task ExecuteCrlPassAsync(CrlExportScheduleOptions task, string cronExpression, CancellationToken cancellationToken)
        {
            var caCertificate = await _db.Certificates
                .Where(c => c.CertificateId == task.CaCertificateId)
                .FirstOrDefaultAsync(cancellationToken);

            if (caCertificate == null)
            {
                throw new InvalidOperationException($"CA certificate with ID {task.CaCertificateId} not found.");
            }

            // Wire delta CRL generation into the scheduler. When the
            // matching config row has IsDelta=true we call GenerateDeltaCrlAsync; otherwise
            // we call the full generator and also opportunistically roll a delta CRL when
            // the same CA has a DeltaInterval configured.
            var crlJob = await _db.CrlConfigurations
                .AsNoTracking()
                .FirstOrDefaultAsync(j => j.TaskId == task.TaskId, cancellationToken);

            // Regenerate EVERY tick, whether or not anything new was revoked.
            //
            // A CRL is a time-bounded assertion, not a change log: its nextUpdate is baked into
            // the signed DER at generation time. The old code only regenerated when
            // CheckNewCrlEntries found something new, and otherwise advanced the NextUpdate
            // COLUMNS while leaving RawData untouched — so once a quiet period passed, the CA
            // served a CRL that had already expired, and PublicCrlController derived its
            // Cache-Control max-age from the advanced column, propagating the false freshness to
            // caches. It stayed that way until someone happened to revoke something.
            //
            // CheckNewCrlEntries is kept for the audit/log distinction only.
            var hadNewEntries = await CheckNewCrlEntries(caCertificate, cancellationToken);

            if (crlJob != null && crlJob.IsDelta)
            {
                await _crlService.GenerateDeltaCrlAsync(caCertificate.CertificateId, cancellationToken);
                _logger.LogInformation("Delta CRL generated for CA certificate {CaCertificateId}.", task.CaCertificateId);
            }
            else
            {
                await _crlService.GenerateCrlAsync(caCertificate.CertificateId, cancellationToken);
                _logger.LogInformation("CRL generated for CA certificate {CaCertificateId}.", task.CaCertificateId);

                if (crlJob != null && !string.IsNullOrWhiteSpace(crlJob.DeltaInterval))
                {
                    try
                    {
                        await _crlService.GenerateDeltaCrlAsync(caCertificate.CertificateId, cancellationToken);
                        _logger.LogInformation("Opportunistic delta CRL generated for CA certificate {CaCertificateId}.", task.CaCertificateId);
                    }
                    catch (Exception dex)
                    {
                        _logger.LogWarning(dex, "Opportunistic delta CRL regen failed for CA {CaCertificateId}; full CRL was still published.", task.CaCertificateId);
                    }
                }
            }

            await _audit.LogAsync(AuditActionType.CrlExported, null, "Scheduler",
                "CRL", task.CaCertificateId.ToString(),
                new { CaCertificateId = task.CaCertificateId, IsDelta = crlJob?.IsDelta ?? false, HadNewEntries = hadNewEntries });
        }

        /// <summary>
        /// Returns <c>true</c> when there are revoked certs newer than the latest CRL's
        /// <c>GeneratedAt</c> (or when no CRL exists yet, per RFC 5280 §3.3 — an empty CRL is
        /// still required). Used to decide whether to actually regenerate a CRL on this tick or
        /// just advance the schedule.
        /// </summary>
        internal async Task<bool> CheckNewCrlEntries(CertificateEntity caCertificate, CancellationToken cancellationToken = default)
        {
            if (caCertificate == null)
                return false;

            // Get the latest CRL for this CA
            var latestCrl = await _db.Crls
                .Where(c => c.IssuerName == caCertificate.SubjectDN)
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefaultAsync(cancellationToken);

            // Get all revoked certs for this CA
            var revokedCerts = await _db.Certificates
                .Where(c => c.Revoked && c.Issuer == caCertificate.SubjectDN)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            if (latestCrl == null)
            {
                // No CRL exists yet — generate one (even if empty, per RFC 5280 §3.3)
                return true;
            }

            // If any revoked cert has a revocation date after the last CRL generation, it's new
            var newRevoked = revokedCerts.Any(cert =>
                cert.RevocationDate != null && cert.RevocationDate > latestCrl.GeneratedAt);

            return newRevoked;
        }
    }
}
