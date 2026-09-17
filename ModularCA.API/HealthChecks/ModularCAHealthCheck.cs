using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// Comprehensive health check verifying database connectivity, keystore status,
/// CA availability, Web TLS certificate expiry, and disk space.
/// Returns a structured response suitable for load balancer health probes.
/// </summary>
public class ModularCAHealthCheck : IHealthCheck
{
    private readonly ModularCADbContext _db;
    private readonly AuditDbContext? _auditDb;
    private readonly IKeystoreCertificates _keystore;
    private readonly ModularCA.Shared.Signing.ISigningService _signer;
    private readonly ApiCertificateProvider _apiCertProvider;
    private readonly SystemConfig _config;

    /// <summary>
    /// Initializes a new instance of the <see cref="ModularCAHealthCheck"/> class.
    /// </summary>
    /// <param name="db">The application database context.</param>
    /// <param name="keystore">The keystore providing CA certificates and signers.</param>
    /// <param name="signer">The signer, whose own account of its state (unlocked, key count, backend) is reported.</param>
    /// <param name="apiCertProvider">Provider for the current Web TLS certificate.</param>
    /// <param name="config">The system configuration.</param>
    /// <param name="auditDb">The optional audit database context.</param>
    public ModularCAHealthCheck(
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ModularCA.Shared.Signing.ISigningService signer,
        ApiCertificateProvider apiCertProvider,
        SystemConfig config,
        AuditDbContext? auditDb = null)
    {
        _db = db;
        _auditDb = auditDb;
        _keystore = keystore;
        _signer = signer;
        _apiCertProvider = apiCertProvider;
        _config = config;
    }

    /// <summary>
    /// Runs the health check, returning the status of the ModularCA subsystems
    /// including database connectivity, keystore accessibility, Web TLS certificate
    /// expiry, disk space, and overall certificate statistics.
    /// </summary>
    /// <param name="context">The health check context.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>A <see cref="HealthCheckResult"/> indicating the aggregate health status.</returns>
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        var data = new Dictionary<string, object>();
        var overallHealthy = true;
        var degraded = false;

        // --- Database connectivity ---
        var dbCheck = await CheckDatabaseAsync(ct);
        data["database"] = dbCheck.Result;
        if (dbCheck.Status == "unhealthy") overallHealthy = false;

        // --- Audit DB connectivity ---
        var auditDbCheck = await CheckAuditDatabaseAsync(ct);
        data["auditDatabase"] = auditDbCheck.Result;
        if (auditDbCheck.Status == "unhealthy") degraded = true;

        // --- Keystore accessibility ---
        var keystoreCheck = CheckKeystore();
        data["keystore"] = keystoreCheck.Result;
        if (keystoreCheck.Status == "unhealthy") overallHealthy = false;
        else if (keystoreCheck.Status == "degraded") degraded = true;

        // --- The signer ---
        var signerCheck = await CheckSignerAsync(ct);
        data["signer"] = signerCheck.Result;
        if (signerCheck.Status == "unhealthy") overallHealthy = false;

        // --- Web TLS certificate expiry ---
        var tlsCheck = CheckTlsCertificate();
        data["tlsCertificate"] = tlsCheck.Result;
        if (tlsCheck.Status == "unhealthy") overallHealthy = false;
        else if (tlsCheck.Status == "degraded") degraded = true;

        // --- Disk space ---
        var diskCheck = CheckDiskSpace();
        data["diskSpace"] = diskCheck.Result;
        if (diskCheck.Status == "degraded") degraded = true;

        // --- Certificate counts from DB ---
        try
        {
            var totalCerts = await _db.Certificates.CountAsync(ct);
            var revokedCerts = await _db.Certificates.CountAsync(c => c.Revoked, ct);
            data["certificates"] = new { total = totalCerts, revoked = revokedCerts };
        }
        catch (Exception ex) { Serilog.Log.Debug(ex, "Health check: failed to query certificate counts"); }

        if (!overallHealthy)
            return HealthCheckResult.Unhealthy("ModularCA has critical issues", data: data);
        if (degraded)
            return HealthCheckResult.Degraded("ModularCA is degraded", data: data);
        return HealthCheckResult.Healthy("ModularCA is operational", data);
    }

    /// <summary>
    /// Checks application database connectivity and measures response time.
    /// Raw exception messages are no longer placed in the
    /// health payload (they leaked MySQL hostnames + table names). Full detail is
    /// written to the structured log.
    /// </summary>
    private async Task<(string Status, object Result)> CheckDatabaseAsync(CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            await _db.Database.CanConnectAsync(ct);
            sw.Stop();
            return ("healthy", new { status = "healthy", responseTimeMs = sw.ElapsedMilliseconds });
        }
        catch (Exception ex)
        {
            sw.Stop();
            Serilog.Log.Warning(ex, "Health check: application DB connectivity failed");
            return ("unhealthy", new { status = "unhealthy", responseTimeMs = sw.ElapsedMilliseconds });
        }
    }

    /// <summary>
    /// Checks audit database connectivity and measures response time.
    /// Exception messages stay in the Serilog log, not the
    /// public health payload.
    /// </summary>
    private async Task<(string Status, object Result)> CheckAuditDatabaseAsync(CancellationToken ct)
    {
        if (_auditDb == null)
            return ("healthy", new { status = "healthy", detail = "not configured" });

        var sw = Stopwatch.StartNew();
        try
        {
            await _auditDb.Database.CanConnectAsync(ct);
            sw.Stop();
            return ("healthy", new { status = "healthy", responseTimeMs = sw.ElapsedMilliseconds });
        }
        catch (Exception ex)
        {
            sw.Stop();
            Serilog.Log.Error(ex, "Health check: audit DB connectivity failed — audit trail at risk");
            return ("unhealthy", new { status = "unhealthy", responseTimeMs = sw.ElapsedMilliseconds });
        }
    }

    /// <summary>
    /// Asks the signer for its own state. A signer that has not unlocked its keystore holds no
    /// usable key, so nothing can be issued: the node is not ready, and the readiness endpoint
    /// says so with the signer's report rather than an inference from the registry.
    /// </summary>
    private async Task<(string Status, object Result)> CheckSignerAsync(CancellationToken ct)
    {
        try
        {
            var health = await _signer.HealthAsync(ct);
            var status = health.Unlocked ? "healthy" : "unhealthy";
            return (status, new { status, unlocked = health.Unlocked, keyCount = health.KeyCount, backend = health.Backend });
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "Health check: the signer did not answer");
            return ("unhealthy", new { status = "unhealthy", unlocked = false });
        }
    }

    /// <summary>
    /// Checks keystore accessibility by verifying signers and trusted certs are loaded,
    /// and that the keystore directory exists on disk.
    /// </summary>
    private (string Status, object Result) CheckKeystore()
    {
        try
        {
            var signers = _keystore.GetSigners();
            var trusted = _keystore.GetTrustedAuthorities();

            // Check if keystore directory exists on disk
            var keystorePath = Path.Combine(AppContext.BaseDirectory, "keystores");
            var keystoreExists = Directory.Exists(keystorePath);

            var expiringCas = trusted.Where(c => c.NotAfter < DateTime.UtcNow.AddDays(30)).ToList();

            if (signers.Count == 0)
                return ("unhealthy", new { status = "unhealthy", caSigners = 0, trustedCerts = trusted.Count, keystoreDirectoryExists = keystoreExists });

            if (expiringCas.Count > 0)
            {
                // Suppress expiring-CA subject DNs from the public
                // payload — they are a renewal-attack target. Details are still written
                // to Serilog for operators who have access to the log sinks.
                Serilog.Log.Warning(
                    "Health check: {Count} CA certificates expire within 30 days: {Subjects}",
                    expiringCas.Count,
                    string.Join("; ", expiringCas.Select(c => $"{c.SubjectDN} (NotAfter={c.NotAfter:o})")));
                return ("degraded", new
                {
                    status = "degraded",
                    caSigners = signers.Count,
                    trustedCerts = trusted.Count,
                    keystoreDirectoryExists = keystoreExists,
                    expiringCaCerts = expiringCas.Count
                });
            }

            return ("healthy", new { status = "healthy", caSigners = signers.Count, trustedCerts = trusted.Count, keystoreDirectoryExists = keystoreExists });
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "Health check: keystore inspection failed");
            return ("unhealthy", new { status = "unhealthy" });
        }
    }

    /// <summary>
    /// Checks the Web TLS certificate expiry, flagging degraded if within 30 days.
    /// </summary>
    private (string Status, object Result) CheckTlsCertificate()
    {
        try
        {
            var cert = _apiCertProvider.GetCertificate();
            if (cert == null)
                return ("degraded", new { status = "degraded", detail = "No Web TLS certificate loaded" });

            var daysRemaining = (int)(cert.NotAfter - DateTime.UtcNow).TotalDays;

            // Strip raw NotAfter + expiration message from the
            // payload (attackers use this for renewal-window attack timing). Days remaining
            // is less specific but still useful to operators.
            if (daysRemaining <= 0)
            {
                Serilog.Log.Error("Health check: Web TLS certificate has expired (NotAfter={NotAfter})", cert.NotAfter);
                return ("unhealthy", new { status = "unhealthy" });
            }

            if (daysRemaining <= 30)
            {
                Serilog.Log.Warning("Health check: Web TLS certificate expires in {Days} days (NotAfter={NotAfter})", daysRemaining, cert.NotAfter);
                return ("degraded", new { status = "degraded", daysRemaining });
            }

            return ("healthy", new { status = "healthy" });
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "Health check: Web TLS certificate inspection failed");
            return ("degraded", new { status = "degraded" });
        }
    }

    /// <summary>
    /// Checks available disk space on the config/keystore directory drive.
    /// Reports degraded if less than 1 GB of free space.
    /// </summary>
    private (string Status, object Result) CheckDiskSpace()
    {
        try
        {
            var configDir = Path.Combine(AppContext.BaseDirectory, "config");
            // Resolve to the directory we actually want to measure. If config/ doesn't
            // exist yet (fresh install), fall back to the binary directory, which always does.
            var measurePath = Directory.Exists(configDir) ? configDir : AppContext.BaseDirectory;

            // Pick the value DriveInfo can resolve on each platform:
            //  - Windows: DriveInfo requires a drive ROOT ("C:\"), so use GetPathRoot.
            //  - Linux/macOS: GetPathRoot returns "/" for every absolute path, which can
            //    point at the wrong filesystem (e.g. a tiny read-only composefs/ostree root
            //    showing 0 bytes free → permanent false "degraded"). Hand DriveInfo the path
            //    itself so statvfs resolves the real mount that backs config/keystore.
            var drivePath = OperatingSystem.IsWindows()
                ? (Path.GetPathRoot(measurePath) ?? "C:\\")
                : measurePath;
            var driveInfo = new DriveInfo(drivePath);

            var freeGb = driveInfo.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);

            // Don't leak host disk capacity to the public health payload.
            // Only report a low-disk boolean outward; log the numbers for operators.
            if (freeGb < 1.0)
            {
                Serilog.Log.Warning("Health check: less than 1 GB free disk space on config volume (free={FreeGb:F2} GB, total={TotalGb:F2} GB)",
                    freeGb, driveInfo.TotalSize / (1024.0 * 1024.0 * 1024.0));
                return ("degraded", new { status = "degraded", lowDiskSpace = true });
            }

            return ("healthy", new { status = "healthy" });
        }
        catch (Exception ex)
        {
            Serilog.Log.Debug(ex, "Health check: unable to query free disk space");
            return ("healthy", new { status = "healthy" });
        }
    }
}
