using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ModularCA.Core.Helpers;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that automatically renews the management UI / API server's Web TLS
/// certificate before expiration, and, on the same tick and window, the endpoint certificate
/// of every tenant hostname.
///
/// Inherits <see cref="SingletonCronJob"/> so the base class owns past-due math,
/// missed-run policy, timeout enforcement, metrics, and <c>SchedulerJobStates</c>
/// persistence. The cron expression comes from
/// <c>_config.Https.RenewalCheckSchedule</c> (defaults to <c>"0 5 * * *"</c>) and
/// always fires — there is no master Enabled flag. The window-gate inside
/// <see cref="ExecuteAsync"/> (cert within renewal window?) is what decides whether
/// an actual renewal happens on any given tick. The <c>RunAsync(ct)</c> entry point
/// is retained as the operator-facing manual-run path:
/// <c>SchedulerJobRegistry.RunNowAsync</c> calls it directly when an operator clicks
/// "Run Now" in the admin Schedules page — bypassing the cron past-due gate that
/// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
/// regardless of schedule.
/// </summary>
public class TlsRenewalJob : SingletonCronJob
{
    // Number of historical backups to retain (.bak, .bak.1, .bak.2 by default). The
    // current PFX rotates into .bak, the previous .bak shifts to .bak.1, etc. Lets an
    // operator roll back several renewals if the most recent cert turns out to be
    // problematic (e.g. wrong SAN list because the source profile was misconfigured).
    private const int BackupRetainCount = 3;

    // Serializes the file-ops + in-memory swap critical section. The runner does not
    // serialize per-job so a manual "Run Now" can otherwise race a cron-tick run on
    // the same .new temp file. Static (per-process) is the right scope — cross-replica
    // contention is owned by the lease in SchedulerService.
    private static readonly SemaphoreSlim _swapLock = new(1, 1);

    private readonly ILogger<TlsRenewalJob> _logger;
    private readonly ModularCADbContext _db;
    private readonly IKeystoreCertificates _keystore;
    private readonly ApiCertificateProvider _certProvider;
    private readonly SystemConfig _config;
    private readonly IAuditService _audit;
    private readonly INotificationService _notifications;
    private readonly ICsrService _csrService;
    private readonly ICertificateIssuanceService _issuanceService;
    private readonly ITenantHostnameCertificateIssuer _hostnameCerts;

    /// <summary>
    /// Initializes a new instance of <see cref="TlsRenewalJob"/>. The
    /// <paramref name="serviceProvider"/> and <paramref name="runner"/> parameters
    /// are forwarded to the <see cref="SingletonCronJob"/> base so the shared
    /// scheduling/locking machinery wires up correctly.
    /// </summary>
    public TlsRenewalJob(
        IServiceProvider serviceProvider,
        ILogger<TlsRenewalJob> logger,
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ApiCertificateProvider certProvider,
        SystemConfig config,
        IAuditService audit,
        INotificationService notifications,
        ICsrService csrService,
        ICertificateIssuanceService issuanceService,
        ITenantHostnameCertificateIssuer hostnameCerts,
        SchedulerJobRunner runner)
        : base(serviceProvider, logger, config, runner)
    {
        _hostnameCerts = hostnameCerts;
        _logger = logger;
        _db = db;
        _keystore = keystore;
        _certProvider = certProvider;
        _notifications = notifications;
        _config = config;
        _audit = audit;
        _csrService = csrService;
        _issuanceService = issuanceService;
    }

    /// <inheritdoc />
    public override string Name => "TlsRenewal";

    /// <summary>
    /// Cron expression for the TLS renewal check sweep. Always-on — there is no
    /// master Enabled flag for this job. The window-gate inside
    /// <see cref="ExecuteAsync"/> still controls whether an actual renewal fires
    /// on any given tick (only when the current cert is inside its renewal window).
    /// </summary>
    protected override string CronExpression => _config.Https.RenewalCheckSchedule;

    /// <summary>
    /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an
    /// operator clicks "Run Now" for this job — bypassing the cron past-due gate that
    /// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
    /// regardless of schedule. The protected <see cref="ExecuteAsync"/> body is invoked
    /// directly.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);

    /// <summary>
    /// Renews the Web TLS certificate when it is inside its renewal window, then every tenant
    /// hostname certificate that is inside the same window or missing. Each part is independent:
    /// a console certificate the operator supplied (<c>Custom</c> mode) is left alone while the
    /// tenant names still renew. Failures are logged and a notification is sent to
    /// administrators via <see cref="INotificationService"/>.
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        await RenewWebTlsIfDueAsync(cancellationToken);
        await RenewTenantHostnamesIfDueAsync(cancellationToken);
    }

    /// <summary>
    /// Renews every tenant hostname whose certificate is missing, or inside
    /// <c>Https.RenewalWindow</c> of expiry, through <see cref="ITenantHostnameCertificateIssuer"/>.
    /// A hostname whose issuance fails is reported and retried on the next tick; the others
    /// still renew.
    /// </summary>
    private async Task RenewTenantHostnamesIfDueAsync(CancellationToken cancellationToken)
    {
        var renewalWindow = Iso8601ParserUtil.ParseIso8601(_config.Https.RenewalWindow);
        var now = TimeProvider.GetUtcNow().UtcDateTime;
        var hostnames = await _db.TenantHostnames.AsNoTracking().Include(h => h.Certificate)
            .OrderBy(h => h.Hostname).ToListAsync(cancellationToken);

        foreach (var hostname in hostnames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var expiry = hostname.Certificate?.NotAfter.ToUniversalTime();
            var due = expiry == null || expiry.Value - now <= renewalWindow;
            if (!due) continue;

            _logger.LogInformation("Tenant hostname {Host}: certificate {State}; renewing.",
                hostname.Hostname, expiry == null ? "missing" : $"expires in {expiry.Value - now}");
            try
            {
                var previous = hostname.Certificate?.SerialNumber;
                var issued = await _hostnameCerts.IssueAsync(hostname, cancellationToken);
                await _audit.LogAsync(AuditActionType.TenantHostnameCertificateIssued, null, "Scheduler",
                    "TenantHostname", hostname.Id.ToString(),
                    new { hostname.Hostname, OldSerial = previous, NewSerial = issued.SerialNumber, issued.NotAfter },
                    tenantId: hostname.TenantId);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Tenant hostname {Host}: renewal failed", hostname.Hostname);
                try
                {
                    await _notifications.NotifyAsync("TlsRenewalFailed",
                        $"TLS certificate renewal for tenant hostname {hostname.Hostname} failed: {ex.Message}");
                }
                catch (Exception notifyEx) { Serilog.Log.Warning(notifyEx, "Failed to send TLS renewal failure notification"); }
            }
        }
    }

    /// <summary>
    /// Checks whether the current Web TLS certificate is within its renewal window and,
    /// if so, triggers an automatic renewal. Only a self-issued console certificate is renewed.
    /// </summary>
    private async Task RenewWebTlsIfDueAsync(CancellationToken cancellationToken)
    {
        // Only auto-renew self-issued certs
        if (!string.Equals(_config.Https.Mode, "SelfIssued", StringComparison.OrdinalIgnoreCase))
            return;

        var currentCert = _certProvider.GetCertificate();
        if (currentCert == null)
            return;

        // Check if within renewal window
        var renewalWindow = Iso8601ParserUtil.ParseIso8601(_config.Https.RenewalWindow);
        var timeUntilExpiry = currentCert.NotAfter.ToUniversalTime() - TimeProvider.GetUtcNow().UtcDateTime;

        if (timeUntilExpiry > renewalWindow)
            return; // Not yet time to renew

        _logger.LogInformation("Web TLS certificate expires in {TimeUntilExpiry}. Renewal window is {RenewalWindow}. Starting renewal...",
            timeUntilExpiry, _config.Https.RenewalWindow);

        try
        {
            await RenewCertificateAsync(currentCert, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to renew Web TLS certificate");
            try
            {
                await _notifications.NotifyAsync("TlsRenewalFailed",
                    $"TLS certificate renewal failed: {ex.Message}");
            }
            catch (Exception notifyEx) { Serilog.Log.Warning(notifyEx, "Failed to send TLS renewal failure notification"); } // Don't let notification failure mask the real error
        }
    }

    /// <summary>
    /// Renews the Web TLS certificate through the standard CSR → profile validation →
    /// CertificateIssuanceService pipeline. Reuses the subject DN and SANs from the current
    /// certificate. After issuance, validates the chain, exports to PFX, and hot-swaps.
    /// </summary>
    private async Task RenewCertificateAsync(X509Certificate2 currentCert, CancellationToken cancellationToken)
    {
        var currentSerial = currentCert.SerialNumber;
        var dbCert = await _db.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(currentSerial, cancellationToken);

        if (dbCert == null)
        {
            _logger.LogWarning("Current Web TLS cert (SN={Serial}) not found in database.", currentSerial);
            return;
        }

        // Resolve signing profile for the issuance pipeline
        if (dbCert.SigningProfileId == null)
        {
            _logger.LogWarning("No signing profile on current TLS cert for renewal");
            return;
        }

        // Look up the Web TLS cert profile (or fall back to the cert's existing profile)
        var certProfile = await _db.CertProfiles
            .FirstOrDefaultAsync(cp => cp.Name == "Web TLS Certificate Profile", cancellationToken);
        var certProfileId = certProfile?.Id ?? dbCert.CertProfileId
            ?? throw new InvalidOperationException("No cert profile available for TLS renewal");

        // Generate CSR through the infrastructure pipeline
        var subjectDn = dbCert.SubjectDN;
        var (csrId, keyPair) = await _csrService.GenerateInfrastructureCsrAsync(
            subjectDn, "ECDSA", 256, certProfileId, dbCert.SigningProfileId.Value);

        // Issue through the standard pipeline — CA is in the keystore at renewal time
        // Named argument: the tenant validity-ceiling enforcement mode now sits ahead of the token,
        // and the default (always shorten) is what a scheduled renewal must have. A refusal here
        // would let a tenant setting quietly stop the CA renewing its own TLS certificate.
        var result = await _issuanceService.IssueCertificateAsync(csrId, null, null, cancellationToken: cancellationToken);

        if (result.Warnings.Count > 0)
            foreach (var w in result.Warnings)
                _logger.LogWarning("TLS renewal warning: {Warning}", w);

        // Parse the issued cert
        var tlsCert = CertificateUtil.ParseFromPem(result.Pem);
        var newSerial = CertificateUtil.FormatSerialNumber(tlsCert.SerialNumber);

        // Resolve CA cert for chain validation and PFX export
        var signingProfile = await _db.SigningProfiles.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == dbCert.SigningProfileId, cancellationToken);
        var caCertEntity = signingProfile?.IssuerId != null
            ? await _db.Certificates.AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId, cancellationToken)
            : null;

        // Chain validation before PFX swap
        if (caCertEntity?.RawCertificate != null)
        {
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(X509CertificateLoader.LoadCertificate(caCertEntity.RawCertificate));
                var newCert2 = X509CertificateLoader.LoadCertificate(tlsCert.GetEncoded());
                if (!chain.Build(newCert2))
                {
                    _logger.LogError("TLS renewal: chain validation failed — aborting swap");
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TLS renewal: chain validation error — aborting swap");
                return;
            }
        }

        // Atomic PFX swap. We write the new PFX to a sibling .new temp file, load-test it,
        // then commit via a single File.Move — eliminating the corrupted-PFX failure mode
        // where a partial write leaves the API unable to start. Backups are rotated
        // (.bak → .bak.1 → ... → .bak.{N-1}) before the new .pfx replaces the current one,
        // so an operator can roll back several renewals deep if needed. If anything between
        // the rename and SetCertificate throws, restore from .bak so on-disk state matches
        // what the in-memory provider is still serving.
        var pfxPath = Path.Combine(AppContext.BaseDirectory, "config", "api-tls.pfx");
        var pfxTempPath = pfxPath + ".new";
        var pfxBackupPath = pfxPath + ".bak";

        // Serialize the swap so a manual "Run Now" can't race a cron-tick run on .new.
        await _swapLock.WaitAsync(cancellationToken);
        try
        {
            // Build the new PFX in memory + write to .new (NOT .pfx — original stays intact
            // until we commit). FileMode.Create overwrites any leftover .new from a prior crash.
            var caBcCert = caCertEntity != null ? CertificateUtil.ParseFromPem(caCertEntity.Pem) : null;
            var pfxStore = new Pkcs12StoreBuilder().Build();
            var chainEntries = caBcCert != null
                ? new[] { new X509CertificateEntry(tlsCert), new X509CertificateEntry(caBcCert) }
                : new[] { new X509CertificateEntry(tlsCert) };
            pfxStore.SetKeyEntry("api-tls", new AsymmetricKeyEntry(keyPair.Private), chainEntries);

            try
            {
                using (var fs = new FileStream(pfxTempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    pfxStore.Save(fs, _config.Https.CertificatePassword.ToCharArray(), new SecureRandom());
                }
                FileSecurityUtil.SetOwnerOnly(pfxTempPath);

                // Load-test BEFORE committing. If the password or PKCS#12 structure is wrong
                // we discover it now while the original PFX is still intact and authoritative.
                var newX509 = X509CertificateLoader.LoadPkcs12FromFile(pfxTempPath,
                    _config.Https.CertificatePassword, X509KeyStorageFlags.MachineKeySet);

                // Commit point. Rotate backups, atomic rename, in-memory swap. The window
                // between the Move and SetCertificate is microseconds; if SetCertificate
                // throws we restore the backup so on-disk state matches what the provider
                // is serving.
                RotateBackups(pfxBackupPath);
                if (File.Exists(pfxPath))
                {
                    File.Copy(pfxPath, pfxBackupPath, overwrite: true);
                    FileSecurityUtil.SetOwnerOnly(pfxBackupPath);
                }

                File.Move(pfxTempPath, pfxPath, overwrite: true);

                try
                {
                    _certProvider.SetCertificate(newX509);
                }
                catch (Exception swapEx)
                {
                    // SetCertificate failed AFTER the file rename. The provider is still
                    // serving the OLD cert in memory; restore the .bak so disk + memory agree
                    // until an operator can investigate. Without this, a process restart would
                    // load the new PFX and resume serving the new cert without an audit row.
                    _logger.LogError(swapEx, "TLS renewal: SetCertificate failed after PFX rename; rolling back to .bak");
                    if (File.Exists(pfxBackupPath))
                    {
                        try
                        {
                            File.Copy(pfxBackupPath, pfxPath, overwrite: true);
                            FileSecurityUtil.SetOwnerOnly(pfxPath);
                        }
                        catch (Exception rollbackEx)
                        {
                            _logger.LogError(rollbackEx, "TLS renewal: rollback from .bak ALSO failed; manual recovery required (PFX on disk = new cert, provider in memory = old cert)");
                        }
                    }
                    throw;
                }
            }
            finally
            {
                // Clean up .new if it's still around (e.g. write succeeded but load-test threw,
                // or the Move never happened). Best-effort — failures here are noise.
                if (File.Exists(pfxTempPath))
                {
                    try { File.Delete(pfxTempPath); }
                    catch (Exception cleanupEx)
                    {
                        _logger.LogWarning(cleanupEx, "TLS renewal: failed to clean up {TempPath}", pfxTempPath);
                    }
                }
            }
        }
        finally
        {
            _swapLock.Release();
        }

        _logger.LogInformation("Web TLS certificate renewed via standard pipeline. New SN={Serial}, Expires={NotAfter}",
            newSerial, tlsCert.NotAfter);

        await _audit.LogAsync(AuditActionType.TlsCertificateRenewed, null, "Scheduler",
            "Certificate", newSerial,
            new { OldSerial = currentSerial, NewSerial = newSerial, tlsCert.NotAfter });

        await _notifications.NotifyTlsCertRenewedAsync(newSerial, tlsCert.NotAfter);
    }

    /// <summary>
    /// Rotates backup files up by one slot before the caller copies the current PFX into
    /// <paramref name="bakPath"/>. Drops the oldest retained slot, shifts the rest:
    /// .bak.{N-2} → .bak.{N-1}, ..., .bak.1 → .bak.2, .bak → .bak.1. After this returns,
    /// the .bak slot is free for the caller to overwrite. Each step is best-effort —
    /// rotation failures are logged but do not abort the renewal (the swap itself is what
    /// matters; a missing historical backup is recoverable, an aborted swap is not).
    /// </summary>
    private void RotateBackups(string bakPath)
    {
        // Drop the oldest retained slot.
        var oldest = BackupRetainCount == 1 ? bakPath : $"{bakPath}.{BackupRetainCount - 1}";
        if (File.Exists(oldest))
        {
            try { File.Delete(oldest); }
            catch (Exception ex) { _logger.LogWarning(ex, "TLS renewal: failed to delete oldest backup {Path}", oldest); }
        }

        // Shift slots up: .bak.{N-2} -> .bak.{N-1}, ..., .bak -> .bak.1.
        for (int i = BackupRetainCount - 1; i >= 1; i--)
        {
            var src = i == 1 ? bakPath : $"{bakPath}.{i - 1}";
            var dst = $"{bakPath}.{i}";
            if (File.Exists(src))
            {
                try { File.Move(src, dst, overwrite: true); }
                catch (Exception ex) { _logger.LogWarning(ex, "TLS renewal: rotate {Src} -> {Dst} failed", src, dst); }
            }
        }
    }
}
