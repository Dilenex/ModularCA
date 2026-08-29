using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Scheduler;
using NCrontab;
using System.DirectoryServices.Protocols;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that publishes CA certificates, CRLs, and optionally
/// end-entity user certificates to LDAP directories.
/// <para>
/// Inherits <see cref="PerRowScheduledJob{TRow}"/> over <see cref="LdapConfigurationEntity"/>
/// so the base class owns per-row past-due math against <c>NextUpdateUtc</c>, fan-out across
/// every enabled row, and <c>SchedulerJobStates</c> persistence. The body below is purely
/// the per-row publish work plus the row-state advance after a successful publish.
/// </para>
/// <para>
/// Gated by the DB-backed <c>LdapPublisherPolicyEntity.Enabled</c> master flag; when
/// disabled <see cref="RowsAsync"/> returns an empty list and no rows dispatch.
/// </para>
/// <para>
/// <c>LdapConnection.Timeout</c> is set from <c>LdapPublisherPolicyEntity.ConnectionTimeoutSeconds</c>,
/// and the "publish recent certs since" fallback window is configurable via
/// <c>LdapPublisherPolicyEntity.SinceFallbackHours</c>.
/// </para>
/// <para>
/// The <see cref="RunAsync(LdapScheduleOptions, string, CancellationToken)"/> entry point
/// is retained as the operator-facing manual-run path used by
/// <c>SchedulerJobRegistry.RunNowAsync</c> when an operator clicks "Run Now" for a specific
/// LDAP configuration row in the admin Schedules page — bypassing the per-row past-due
/// gate that <see cref="PerRowScheduledJob{TRow}.TickAsync"/> evaluates so the row publishes
/// immediately regardless of <c>NextUpdateUtc</c>.
/// </para>
/// </summary>
public class LdapPublisherJob : PerRowScheduledJob<LdapConfigurationEntity>
{
    private readonly ModularCADbContext _dbContext;
    private readonly ILogger<LdapPublisherJob> _logger;
    private readonly ILdapPublisherPolicyService _publisherPolicy;
    private readonly ILdapSecretProtector _secretProtector;

    /// <summary>
    /// Initializes a new instance of <see cref="LdapPublisherJob"/>. The base class needs the
    /// service provider, runner, config, and a logger; the scoped <see cref="ModularCADbContext"/>
    /// and <see cref="ILdapPublisherPolicyService"/> remain injected directly because both the
    /// <see cref="PerRowScheduledJob{TRow}.ExecuteRowAsync"/> path and the manual-run shim
    /// need them.
    /// </summary>
    /// <param name="secretProtector">Decrypts the row's stored bind password.</param>
    public LdapPublisherJob(
        IServiceProvider serviceProvider,
        ModularCADbContext dbContext,
        ILogger<LdapPublisherJob> logger,
        ILdapPublisherPolicyService publisherPolicy,
        ILdapSecretProtector secretProtector,
        SystemConfig config,
        SchedulerJobRunner runner)
        : base(serviceProvider, logger, config, runner)
    {
        _dbContext = dbContext;
        _logger = logger;
        _publisherPolicy = publisherPolicy;
        _secretProtector = secretProtector;
    }

    /// <inheritdoc />
    public override string Name => "LdapPublisher";

    /// <summary>
    /// Loads enabled <see cref="LdapConfigurationEntity"/> rows for this tick. Honors the
    /// DB-backed <c>LdapPublisherPolicyEntity.Enabled</c> master gate: when the master
    /// flag is off, returns an empty list so no rows dispatch.
    /// </summary>
    protected override async Task<IReadOnlyList<LdapConfigurationEntity>> RowsAsync(
        ModularCADbContext db, CancellationToken cancellationToken)
    {
        var publisherPolicy = await db.LdapPublisherPolicies
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        if (publisherPolicy?.Enabled != true)
            return Array.Empty<LdapConfigurationEntity>();

        return await db.LdapConfigurations
            .AsNoTracking()
            .Where(l => l.Enabled)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    protected override Guid IdOf(LdapConfigurationEntity row) => row.Id;

    /// <inheritdoc />
    protected override DateTime NextRunUtcOf(LdapConfigurationEntity row) => row.NextUpdateUtc;

    /// <summary>
    /// Performs one LDAP publish run for a single configuration row: publishes the CA
    /// certificate, full CRL, delta CRL, and recently-issued user certificates per the row's
    /// publish flags. After a successful publish, advances the row's <c>LastUpdatedUtc</c> to
    /// "now" and <c>NextUpdateUtc</c> to the next cron occurrence so the next tick's past-due
    /// check skips this row until it's due again.
    /// </summary>
    protected override async Task ExecuteRowAsync(LdapConfigurationEntity row, CancellationToken cancellationToken)
    {
        var options = new LdapScheduleOptions { TaskId = row.Id };
        await PublishAsync(options, cancellationToken);

        // Row state is advanced INSIDE this body because the row's NextUpdateUtc IS the
        // source of truth — the base class's NextRunUtcOf(row) reads it directly. If
        // ExecuteUpdateAsync below throws, the runner catches it and marks the job
        // 'failed'; next tick re-publishes (LDAP ModifyRequest.Replace is idempotent so
        // the redundant publish is harmless). Use the base class's TimeProvider so test
        // fakes apply uniformly.
        var now = TimeProvider.GetUtcNow().UtcDateTime;
        DateTime nextRun;
        try
        {
            var schedule = CrontabSchedule.TryParse(row.UpdateInterval);
            nextRun = schedule?.GetNextOccurrence(now) ?? now.AddHours(1);
        }
        catch
        {
            nextRun = now.AddHours(1);
        }

        await _dbContext.LdapConfigurations
            .Where(l => l.Id == row.Id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(l => l.LastUpdatedUtc, now)
                .SetProperty(l => l.NextUpdateUtc, nextRun),
                cancellationToken);
    }

    /// <summary>
    /// Manual-run shim. <c>AdminSchedulerController.RunLdapSchedule</c> routes here
    /// (via <see cref="SchedulerJobRunner"/>) when an operator clicks "Run Now" for an
    /// LDAP configuration row in the admin Schedules page — bypassing the per-row
    /// past-due gate that <see cref="PerRowScheduledJob{TRow}.TickAsync"/> evaluates
    /// so the row publishes immediately regardless of <c>NextUpdateUtc</c>. The shim
    /// resolves the row by <c>options.TaskId</c> and delegates to
    /// <see cref="ExecuteRowAsync"/> so both paths land in the same body. All callers
    /// supply a real <c>TaskId</c>; an empty Guid is treated as a misuse and rejected.
    /// </summary>
    public async Task RunAsync(LdapScheduleOptions options, string cronExpression, CancellationToken cancellationToken)
    {
        if (options.TaskId == Guid.Empty)
            throw new ArgumentException("LdapPublisherJob.RunAsync requires options.TaskId; callers must resolve the LDAP configuration row first.", nameof(options));

        var row = await _dbContext.LdapConfigurations
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == options.TaskId, cancellationToken);

        if (row == null)
        {
            _logger.LogWarning("LdapPublisherJob: manual-run called with TaskId {TaskId} but no LdapConfigurations row found", options.TaskId);
            return;
        }

        await ExecuteRowAsync(row, cancellationToken);
    }

    /// <summary>
    /// Executes the LDAP publishing cycle: publishes the CA certificate, full CRL,
    /// delta CRL, and recently-issued user certificates according to the supplied options.
    /// Hydrates connection/credential/publish-flag fields from the <c>LdapConfigurations</c>
    /// row identified by <see cref="LdapScheduleOptions.TaskId"/> when the caller passed a
    /// sparse options object.
    /// </summary>
    private async Task PublishAsync(LdapScheduleOptions options, CancellationToken cancellationToken)
    {
        // Hydrate the connection fields from the LdapConfigurations row. Callers (the
        // ExecuteRowAsync path and the manual-run shim) pass a sparse options object
        // containing only the TaskId; populate connection/credential/publish-flag fields
        // from the DB.
        if (options.TaskId != Guid.Empty && string.IsNullOrWhiteSpace(options.LdapHost))
        {
            var ldapConfig = await _dbContext.LdapConfigurations
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == options.TaskId, cancellationToken);
            if (ldapConfig != null)
            {
                options.CertificateAuthorityId = ldapConfig.CertificateAuthorityId;
                options.LdapHost = ldapConfig.Host;
                options.LdapPort = ldapConfig.Port;
                options.UseSsl = ldapConfig.UseSsl;
                options.BaseDn = ldapConfig.BaseDn;
                options.Username = ldapConfig.Username;
                options.Password = _secretProtector.Unprotect(ldapConfig.Password);
                options.PublishCRL = ldapConfig.PublishCRL;
                options.PublishCACert = ldapConfig.PublishCACert;
                options.PublishDelta = ldapConfig.PublishDelta;
                options.PublishUserCerts = ldapConfig.PublishUserCerts;
                options.UserDnTemplate = ldapConfig.UserDnTemplate ?? string.Empty;

                // Self-heal rows written before the password was protected at rest. The
                // scheduled run is the natural place for it: it already holds the row and a
                // writable context, and it reaches every enabled publisher without waiting for
                // an operator to open and re-save each one. Re-protecting is a pure re-encoding
                // of a value we just decrypted, so a failure here is not worth failing the
                // publish over.
                if (LdapSecretProtection.NeedsUpgrade(ldapConfig.Password))
                {
                    try
                    {
                        var protectedPassword = _secretProtector.Protect(options.Password);
                        await _dbContext.LdapConfigurations
                            .Where(l => l.Id == ldapConfig.Id)
                            .ExecuteUpdateAsync(setters => setters
                                .SetProperty(l => l.Password, protectedPassword),
                                cancellationToken);
                        _logger.LogInformation(
                            "Encrypted the stored bind password for LDAP publisher {PublisherId} ({Name}).",
                            ldapConfig.Id, ldapConfig.Name);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex,
                            "Could not encrypt the stored bind password for LDAP publisher {PublisherId}; it remains in plaintext.",
                            ldapConfig.Id);
                    }
                }
            }
        }

        var policy = await _publisherPolicy.GetAsync();
        var connectTimeout = TimeSpan.FromSeconds(Math.Max(5, policy.ConnectionTimeoutSeconds));

        using var connection = LdapPublishHelper.Connect(options, connectTimeout, _logger);

        _logger.LogInformation("LDAP bind successful to {Host}:{Port}", options.LdapHost, options.LdapPort);

        // Resolve the CA entity via the FK to obtain its certificate for publishing.
        var caEntity = await _dbContext.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.Id == options.CertificateAuthorityId, cancellationToken);

        if (caEntity?.CertificateId == null)
        {
            _logger.LogWarning("CA {CaId} not found or has no certificate; skipping LDAP publish.", options.CertificateAuthorityId);
            return;
        }

        var caCertificateId = caEntity.CertificateId.Value;

        if (options.PublishCACert)
        {
            var cert = await _dbContext.Certificates
                .Where(c => c.CertificateId == caCertificateId && !c.Revoked)
                .Select(c => c.RawCertificate)
                .FirstOrDefaultAsync(cancellationToken);

            if (cert != null)
            {
                var request = new ModifyRequest(options.BaseDn, DirectoryAttributeOperation.Replace, "cACertificate", cert);
                connection.SendRequest(request);
                _logger.LogInformation("Published CA certificate to LDAP under {BaseDn}", options.BaseDn);
            }
        }

        if (options.PublishCRL)
        {
            var crl = await _dbContext.Crls
                .Where(c => !c.IsDelta
                    && ((c.Task != null && c.Task.CaCertificateId == caCertificateId)
                        || c.IssuerName == caEntity.Name))
                .OrderByDescending(c => c.CrlNumber)
                .Select(c => c.RawData)
                .FirstOrDefaultAsync(cancellationToken);

            if (crl != null)
            {
                var request = new ModifyRequest(options.BaseDn, DirectoryAttributeOperation.Replace, "certificateRevocationList", crl);
                connection.SendRequest(request);
                _logger.LogInformation("Published CRL to LDAP under {BaseDn}", options.BaseDn);
            }
        }

        if (options.PublishDelta)
        {
            var delta = await _dbContext.Crls
                .Where(c => c.IsDelta
                    && ((c.Task != null && c.Task.CaCertificateId == caCertificateId)
                        || c.IssuerName == caEntity.Name))
                .OrderByDescending(c => c.CrlNumber)
                .Select(c => c.RawData)
                .FirstOrDefaultAsync(cancellationToken);

            if (delta != null)
            {
                var request = new ModifyRequest(options.BaseDn, DirectoryAttributeOperation.Replace, "deltaRevocationList", delta);
                connection.SendRequest(request);
                _logger.LogInformation("Published delta CRL to LDAP under {BaseDn}", options.BaseDn);
            }
        }

        if (options.PublishUserCerts)
        {
            await PublishRecentUserCertsAsync(connection, options, cancellationToken);
        }
    }

    /// <summary>
    /// Queries end-entity certificates issued since the last LDAP publish run for the
    /// configured CA and publishes each one to the corresponding LDAP user entry's
    /// <c>userCertificate;binary</c> attribute.
    /// </summary>
    private async Task PublishRecentUserCertsAsync(LdapConnection connection, LdapScheduleOptions options, CancellationToken cancellationToken)
    {
        // Determine the cut-off: use the LDAP config's LastUpdatedUtc if available
        var ldapConfig = await _dbContext.LdapConfigurations
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == options.TaskId, cancellationToken);

        var policy = await _publisherPolicy.GetAsync();
        var sinceFallback = TimeSpan.FromHours(Math.Max(1, policy.SinceFallbackHours));
        var since = ldapConfig?.LastUpdatedUtc ?? TimeProvider.GetUtcNow().UtcDateTime.Subtract(sinceFallback);

        // Resolve the CA's certificate ID to filter issued certs by issuer FK.
        var caEntity = await _dbContext.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.Id == options.CertificateAuthorityId, cancellationToken);

        if (caEntity?.CertificateId == null)
        {
            _logger.LogWarning("CA {CaId} not found or has no certificate; skipping user cert publish.", options.CertificateAuthorityId);
            return;
        }

        var caCertId = caEntity.CertificateId.Value;

        var recentCerts = await _dbContext.Certificates
            .Where(c => c.IssuerCertificateId == caCertId
                && !c.IsCA
                && !c.Revoked
                && c.CreatedAt > since
                && c.RawCertificate != null)
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        _logger.LogInformation("Found {Count} user certificates to publish to LDAP since {Since}", recentCerts.Count, since);

        foreach (var cert in recentCerts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                LdapPublishHelper.PublishUserCertificate(connection, options, cert.RawCertificate!, cert.SubjectDN, _logger);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to publish user certificate {Serial} to LDAP", cert.SerialNumber);
            }
        }
    }
}
