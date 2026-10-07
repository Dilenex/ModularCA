using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using System.Text.Json;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that scans all active (non-revoked, non-expired) certificates for
/// security vulnerabilities and compliance issues. Findings include weak RSA keys,
/// deprecated signature algorithms, over-long validity periods, missing SANs on TLS
/// server certificates, certificates expiring without a renewal request, and wildcard
/// certificates. The scan is idempotent: duplicate findings are not created, and
/// findings for certificates that are no longer active are automatically resolved.
///
/// Inherits <see cref="SingletonCronJob"/> so the base class owns past-due math against
/// <c>ComplianceScan.Schedule</c>, missed-run policy, timeout enforcement,
/// metrics, and <c>SchedulerJobStates</c> persistence — the body below is purely the
/// per-tick scan work. The <c>RunAsync(ct)</c> entry point is retained as the
/// operator-facing manual-run path: <c>SchedulerJobRegistry.RunNowAsync</c> calls it
/// directly when an operator clicks "Run Now" in the admin Schedules page — bypassing
/// the cron past-due gate that <see cref="SingletonCronJob.TickAsync"/> evaluates so the
/// work fires immediately regardless of schedule.
/// </summary>
public class ComplianceScanJob : SingletonCronJob
{
    private readonly ModularCADbContext _db;
    private readonly ISecurityAlertService _alerts;
    private readonly SystemConfig _config;
    private readonly ILogger<ComplianceScanJob> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ComplianceScanJob"/> class.
    /// </summary>
    /// <param name="serviceProvider">Root service provider used by the base class to scope per-tick dependencies.</param>
    /// <param name="db">Database context for querying certificates and storing findings.</param>
    /// <param name="alerts">Security alert service for raising critical-level alerts.</param>
    /// <param name="config">System configuration containing compliance scan settings.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="runner">Shared <see cref="SchedulerJobRunner"/> coordinator for singleton execution and metrics.</param>
    public ComplianceScanJob(
        IServiceProvider serviceProvider,
        ModularCADbContext db,
        ISecurityAlertService alerts,
        SystemConfig config,
        ILogger<ComplianceScanJob> logger,
        SchedulerJobRunner runner)
        : base(serviceProvider, logger, config, runner)
    {
        _db = db;
        _alerts = alerts;
        _config = config;
        _logger = logger;
    }

    /// <inheritdoc />
    public override string Name => "Compliance";

    /// <summary>
    /// Cron expression for the certificate compliance scan. Returns
    /// <see cref="string.Empty"/> when the scan is disabled, which the base
    /// <see cref="SingletonCronJob.TickAsync"/> treats as "skip without state write".
    /// </summary>
    protected override string CronExpression =>
        _config.ComplianceScan.Enabled
            ? _config.ComplianceScan.Schedule
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
    /// Executes the certificate compliance scan. Loads all active certificates,
    /// parses each one via BouncyCastle, checks for known vulnerability patterns,
    /// and persists findings. Old findings for inactive certificates are auto-resolved.
    /// Critical findings trigger security alerts via <see cref="ISecurityAlertService"/>.
    /// </summary>
    /// <param name="cancellationToken">Token to signal cancellation of the operation.</param>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        // CronExpression already short-circuits when the scan is disabled. The check
        // here is defense-in-depth for the manual-run RunAsync path which bypasses
        // the cron evaluation in the base class.
        var scanConfig = _config.ComplianceScan;
        if (!scanConfig.Enabled)
            return;

        // Compliance scans sweep every active cert; on large installs
        // the initial materialisation can exceed the 30s default command timeout.
        _db.Database.SetCommandTimeout(TimeSpan.FromMinutes(5));

        _logger.LogInformation("Starting certificate compliance scan");

        var now = TimeProvider.GetUtcNow().UtcDateTime;

        // Load all active (non-revoked, non-expired) certificates
        var activeCerts = await _db.Certificates
            .AsNoTracking()
            .Where(c => !c.Revoked && c.NotAfter > now)
            .ToListAsync(cancellationToken);

        // Load existing unresolved findings to avoid duplicates
        var existingFindings = await _db.CertComplianceFindings
            .Where(v => !v.IsResolved)
            .ToListAsync(cancellationToken);

        var activeCertIds = activeCerts.Select(c => c.CertificateId).ToHashSet();

        // Auto-resolve findings for certificates that are no longer active
        await AutoResolveStaleFindings(existingFindings, activeCertIds, now, cancellationToken);

        // Build lookup of existing unresolved findings by (CertificateId, Type)
        var existingLookup = existingFindings
            .Where(f => !f.IsResolved)
            .GroupBy(f => (f.CertificateId, f.Type))
            .ToDictionary(g => g.Key, g => g.First());

        // Load renewal request certificate IDs for expiring-without-renewal check
        var renewalCertIds = await _db.CertificateRequests
            .AsNoTracking()
            .Where(r => r.RenewalOfCertificateId != null && r.Status != "Rejected")
            .Select(r => r.RenewalOfCertificateId!.Value)
            .Distinct()
            .ToListAsync(cancellationToken);
        var renewalSet = renewalCertIds.ToHashSet();

        int newFindings = 0;

        foreach (var cert in activeCerts)
        {
            // Per-cert isolation: a single malformed cert shouldn't poison the rest of the
            // scan. The per-tick failure path (DB outage, etc.) still propagates.
            try
            {
                var findings = AnalyzeCertificate(cert, scanConfig, now, renewalSet);
                foreach (var finding in findings)
                {
                    var key = (cert.CertificateId, finding.Type);
                    if (existingLookup.ContainsKey(key))
                        continue; // Already reported and unresolved — skip

                    _db.CertComplianceFindings.Add(finding);
                    newFindings++;

                    // Raise security alerts for critical findings
                    if (finding.Severity == AlertSeverity.Critical)
                    {
                        await RaiseCriticalAlert(cert, finding);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to analyze certificate {CertId} ({Subject})",
                    cert.CertificateId, cert.SubjectDN);
            }
        }

        if (newFindings > 0)
        {
            await _db.SaveChangesAsync(cancellationToken);
            _logger.LogInformation(
                "Certificate compliance scan complete: {NewFindings} new finding(s) across {Total} active certificate(s)",
                newFindings, activeCerts.Count);
        }
        else
        {
            _logger.LogInformation(
                "Certificate compliance scan complete: no new findings across {Total} active certificate(s)",
                activeCerts.Count);
        }

        // Update vulnerability gauge metrics by severity
        var unresolvedFindings = await _db.CertComplianceFindings
            .Where(v => !v.IsResolved)
            .ToListAsync(cancellationToken);
        MetricsService.VulnerabilitiesActive.WithLabels("Critical").Set(
            unresolvedFindings.Count(f => f.Severity == AlertSeverity.Critical));
        MetricsService.VulnerabilitiesActive.WithLabels("Warning").Set(
            unresolvedFindings.Count(f => f.Severity == AlertSeverity.Warning));
        MetricsService.VulnerabilitiesActive.WithLabels("Info").Set(
            unresolvedFindings.Count(f => f.Severity == AlertSeverity.Info));
    }

    /// <summary>
    /// True when a BouncyCastle signature algorithm name (<c>SHA-1withRSA</c>, <c>MD5withRSA</c>)
    /// contains any configured deprecated entry, ignoring case and hyphens. BouncyCastle writes
    /// SHA-1 with a hyphen, so without folding hyphens the default entry <c>SHA1WithRSA</c>, and
    /// the console's suggestion <c>SHA1</c>, never matched a SHA-1 certificate. Blank entries are
    /// skipped, since an empty fragment would match every certificate.
    /// </summary>
    /// <param name="sigAlgName">The certificate's signature algorithm name.</param>
    /// <param name="deprecated">The configured deprecated entries.</param>
    internal static bool MatchesDeprecatedAlgorithm(string? sigAlgName, IEnumerable<string>? deprecated)
    {
        if (string.IsNullOrEmpty(sigAlgName) || deprecated == null) return false;
        static string Fold(string s) => s.Replace("-", string.Empty).ToUpperInvariant();
        var name = Fold(sigAlgName);
        return deprecated
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Any(d => name.Contains(Fold(d.Trim()), StringComparison.Ordinal));
    }

    /// <summary>
    /// Analyzes a single certificate for known vulnerability patterns and returns
    /// a list of findings. Parses the raw certificate bytes via BouncyCastle to
    /// inspect key size, signature algorithm, extensions, and validity period.
    /// </summary>
    /// <param name="cert">The certificate entity to analyze.</param>
    /// <param name="scanConfig">Compliance scan configuration thresholds.</param>
    /// <param name="now">Current UTC timestamp for validity calculations.</param>
    /// <param name="renewalSet">Set of certificate IDs that have pending renewal requests.</param>
    /// <returns>List of vulnerability findings for this certificate.</returns>
    private List<CertComplianceFindingEntity> AnalyzeCertificate(
        CertificateEntity cert,
        ComplianceScanConfig scanConfig,
        DateTime now,
        HashSet<Guid> renewalSet)
    {
        var findings = new List<CertComplianceFindingEntity>();

        X509Certificate? bcCert = null;
        if (cert.RawCertificate != null && cert.RawCertificate.Length > 0)
        {
            try
            {
                bcCert = new X509Certificate(cert.RawCertificate);
            }
            catch
            {
                // If we can't parse the raw cert, skip BouncyCastle checks
            }
        }

        // 1. Weak RSA key check
        if (bcCert != null)
        {
            var pubKey = bcCert.GetPublicKey();
            if (pubKey is RsaKeyParameters rsaKey)
            {
                var keySize = rsaKey.Modulus.BitLength;
                if (keySize < scanConfig.MinRsaKeySize)
                {
                    findings.Add(CreateFinding(cert.CertificateId, AlertSeverity.Critical, "WeakKey",
                        $"RSA key size {keySize} bits is below the minimum threshold of {scanConfig.MinRsaKeySize} bits"));
                }
            }
        }

        // 2. Deprecated signature algorithm check
        if (bcCert != null && MatchesDeprecatedAlgorithm(bcCert.SigAlgName, scanConfig.DeprecatedAlgorithms))
        {
            findings.Add(CreateFinding(cert.CertificateId, AlertSeverity.Critical, "DeprecatedAlgorithm",
                $"Certificate uses deprecated signature algorithm: {bcCert.SigAlgName}"));
        }

        // 3. Over-long validity check — warning-only threshold, does not block issuance.
        var validityDays = (cert.NotAfter - cert.NotBefore).TotalDays;
        if (validityDays > scanConfig.WarnOverValidityDays)
        {
            findings.Add(CreateFinding(cert.CertificateId, AlertSeverity.Warning, "OverLongValidity",
                $"Certificate validity period of {(int)validityDays} days exceeds the warning threshold of {scanConfig.WarnOverValidityDays} days"));
        }

        // 4. Missing SANs on TLS server certificates
        if (!cert.IsCA && IsTlsServerCert(cert))
        {
            var hasSans = !string.IsNullOrWhiteSpace(cert.SubjectAlternativeNamesJson)
                          && cert.SubjectAlternativeNamesJson != "[]";
            if (!hasSans)
            {
                findings.Add(CreateFinding(cert.CertificateId, AlertSeverity.Warning, "MissingSANs",
                    "TLS server certificate has no Subject Alternative Names — modern browsers require SANs"));
            }
        }

        // 5. Expiring without renewal — window is configurable via
        // ComplianceScan.ExpiringWithinDays (default 30).
        var daysToExpiry = (cert.NotAfter - now).TotalDays;
        var expiringWindow = Math.Max(1, _config.ComplianceScan.ExpiringWithinDays);
        if (daysToExpiry <= expiringWindow && daysToExpiry > 0 && !renewalSet.Contains(cert.CertificateId))
        {
            findings.Add(CreateFinding(cert.CertificateId, AlertSeverity.Warning, "ExpiringWithoutRenewal",
                $"Certificate expires in {(int)daysToExpiry} day(s) and no renewal request exists"));
        }

        // 6. Wildcard certificate (informational)
        if (IsWildcardCert(cert))
        {
            findings.Add(CreateFinding(cert.CertificateId, AlertSeverity.Info, "WildcardCert",
                "Certificate includes a wildcard domain — not a vulnerability but worth tracking"));
        }

        return findings;
    }

    /// <summary>
    /// Determines whether a certificate is a TLS server certificate by inspecting
    /// its extended key usages for the TLS Web Server Authentication OID.
    /// </summary>
    private static bool IsTlsServerCert(CertificateEntity cert)
    {
        if (string.IsNullOrWhiteSpace(cert.ExtendedKeyUsagesJson))
            return false;

        try
        {
            var ekus = JsonSerializer.Deserialize<List<string>>(cert.ExtendedKeyUsagesJson);
            if (ekus == null)
                return false;

            // TLS Web Server Authentication OID or common name variants
            return ekus.Any(e =>
                e.Contains("1.3.6.1.5.5.7.3.1", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("serverAuth", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("TLS Web Server", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Determines whether a certificate contains wildcard domains in its subject CN
    /// or Subject Alternative Names.
    /// </summary>
    private static bool IsWildcardCert(CertificateEntity cert)
    {
        if (cert.SubjectDN?.Contains("*.", StringComparison.Ordinal) == true)
            return true;

        if (!string.IsNullOrWhiteSpace(cert.SubjectAlternativeNamesJson))
        {
            try
            {
                var sans = JsonSerializer.Deserialize<List<string>>(cert.SubjectAlternativeNamesJson);
                if (sans != null && sans.Any(s => s.Contains("*.", StringComparison.Ordinal)))
                    return true;
            }
            catch
            {
                // Ignore parse errors
            }
        }

        return false;
    }

    /// <summary>
    /// Marks existing unresolved findings as resolved when the associated certificate
    /// is no longer in the active set (revoked or expired).
    /// </summary>
    private async Task AutoResolveStaleFindings(
        List<CertComplianceFindingEntity> existingFindings,
        HashSet<Guid> activeCertIds,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var staleFindings = existingFindings
            .Where(f => !f.IsResolved && !activeCertIds.Contains(f.CertificateId))
            .ToList();

        if (staleFindings.Count == 0)
            return;

        foreach (var finding in staleFindings)
        {
            finding.IsResolved = true;
            finding.ResolvedAt = now;
            _db.CertComplianceFindings.Update(finding);
        }

        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Auto-resolved {Count} stale vulnerability finding(s) for inactive certificates",
            staleFindings.Count);
    }

    /// <summary>
    /// Raises a critical security alert for a vulnerability finding via <see cref="ISecurityAlertService"/>.
    /// </summary>
    private async Task RaiseCriticalAlert(CertificateEntity cert, CertComplianceFindingEntity finding)
    {
        var alertMessage = $"Critical certificate vulnerability: {finding.Type} — " +
                           $"Subject={cert.SubjectDN}, Serial={cert.SerialNumber}. " +
                           finding.Description;

        await _alerts.RaiseAlertAsync(
            $"CertVulnerability_{finding.Type}",
            AlertSeverity.Critical,
            alertMessage,
            new
            {
                cert.SubjectDN,
                cert.SerialNumber,
                VulnerabilityType = finding.Type,
                finding.Description,
                finding.DetectedAt
            });
    }

    /// <summary>
    /// Creates a new <see cref="CertComplianceFindingEntity"/> with the specified parameters.
    /// </summary>
    private CertComplianceFindingEntity CreateFinding(
        Guid certificateId, string severity, string type, string description)
    {
        return new CertComplianceFindingEntity
        {
            CertificateId = certificateId,
            Severity = severity,
            Type = type,
            Description = description,
            DetectedAt = TimeProvider.GetUtcNow().UtcDateTime
        };
    }
}
