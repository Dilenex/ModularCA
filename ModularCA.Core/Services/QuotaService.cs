using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;

namespace ModularCA.Core.Services;

/// <summary>
/// Evaluates certificate quota limits configured on CA admin groups. Counts active (non-revoked,
/// non-expired) certificates per CA and raises security alerts when thresholds are approached or exceeded.
/// </summary>
public class QuotaService : IQuotaService
{
    private readonly ModularCADbContext _db;
    private readonly ISecurityAlertService _alertService;
    private readonly ILogger<QuotaService> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="QuotaService"/>.
    /// </summary>
    /// <param name="db">Database context for querying certificates and groups.</param>
    /// <param name="alertService">Security alert service for quota threshold notifications.</param>
    /// <param name="logger">Logger instance.</param>
    public QuotaService(ModularCADbContext db, ISecurityAlertService alertService, ILogger<QuotaService> logger)
    {
        _db = db;
        _alertService = alertService;
        _logger = logger;
    }

    /// <summary>
    /// Returns detailed quota status for a specific CA by looking up the admin group's MaxCertificates
    /// and counting active certificates issued through signing profiles that reference the CA's certificate.
    /// </summary>
    /// <param name="caId">The certificate authority ID.</param>
    public async Task<QuotaStatus> CheckQuotaAsync(Guid caId)
    {
        var ca = await _db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == caId);

        if (ca == null)
            throw new InvalidOperationException($"Certificate authority '{caId}' not found.");

        // Find the admin group for this CA to read quota limits (identified by CaManage capability)
        var adminGroup = await _db.CaGroups
            .AsNoTracking()
            .Where(g => g.CertificateAuthorityId == caId
                && g.Grants.Any(gr => gr.Capability == Capabilities.CaManage && gr.ResourceType == null))
            .FirstOrDefaultAsync();

        int maxCerts = adminGroup?.MaxCertificates ?? 0;
        int maxPending = adminGroup?.MaxPendingRequests ?? 0;

        // SSH CAs have no X.509 certificate, so quota counting does not apply
        var now = DateTime.UtcNow;
        int issuedCount = 0;
        int pendingCount = 0;
        if (ca.CertificateId.HasValue)
        {
            issuedCount = await CountActiveCertificatesAsync(ca.CertificateId.Value, now);
            pendingCount = await CountPendingRequestsAsync(ca.CertificateId.Value);
        }

        var status = new QuotaStatus
        {
            CaId = caId,
            CaName = ca.Name,
            MaxCertificates = maxCerts,
            MaxPendingRequests = maxPending,
            IssuedCount = issuedCount,
            PendingCount = pendingCount
        };

        if (maxCerts == 0)
        {
            // Unlimited
            status.RemainingCount = -1;
            status.IsExceeded = false;
            status.UsagePercent = 0;
        }
        else
        {
            status.RemainingCount = Math.Max(0, maxCerts - issuedCount);
            status.IsExceeded = issuedCount >= maxCerts;
            status.UsagePercent = Math.Round((double)issuedCount / maxCerts * 100, 2);
        }

        return status;
    }

    /// <summary>
    /// Checks whether the CA can issue another certificate without exceeding its quota.
    /// Raises a warning alert at 80% usage and a critical alert when the quota is exceeded.
    /// </summary>
    /// <param name="caId">The certificate authority ID.</param>
    public async Task<bool> CanIssueCertificateAsync(Guid caId)
    {
        var status = await CheckQuotaAsync(caId);

        if (status.MaxCertificates == 0)
            return true; // Unlimited

        if (status.UsagePercent >= 100)
        {
            _logger.LogCritical("Certificate quota EXCEEDED for CA '{CaName}' ({CaId}): {Issued}/{Max}",
                status.CaName, status.CaId, status.IssuedCount, status.MaxCertificates);

            await _alertService.RaiseAlertAsync(
                "QuotaExceeded",
                AlertSeverity.Critical,
                $"Certificate quota exceeded for CA '{status.CaName}': {status.IssuedCount}/{status.MaxCertificates} certificates issued.",
                new { status.CaId, status.CaName, status.IssuedCount, status.MaxCertificates, status.UsagePercent });

            return false;
        }

        if (status.UsagePercent >= 80)
        {
            _logger.LogWarning("Certificate quota approaching limit for CA '{CaName}' ({CaId}): {Issued}/{Max} ({Usage}%)",
                status.CaName, status.CaId, status.IssuedCount, status.MaxCertificates, status.UsagePercent);

            await _alertService.RaiseAlertAsync(
                "QuotaWarning",
                AlertSeverity.Warning,
                $"Certificate quota approaching limit for CA '{status.CaName}': {status.IssuedCount}/{status.MaxCertificates} ({status.UsagePercent}%).",
                new { status.CaId, status.CaName, status.IssuedCount, status.MaxCertificates, status.UsagePercent });
        }

        return true;
    }

    /// <summary>
    /// Returns an aggregated summary of quota usage across all registered CAs.
    /// Batch-loads all required data upfront to avoid N+1 query overhead.
    /// </summary>
    public async Task<QuotaUsageSummary> GetUsageSummaryAsync()
    {
        // Load all enabled CAs upfront
        var cas = await _db.CertificateAuthorities
            .AsNoTracking()
            .Where(c => c.IsEnabled)
            .ToListAsync();

        // Load all signing profiles in one query
        var allSigningProfiles = await _db.SigningProfiles
            .AsNoTracking()
            .ToListAsync();

        var now = DateTime.UtcNow;

        // Count active certs per signing profile in one query
        var certCounts = await _db.Certificates
            .Where(c => c.SigningProfileId != null && !c.Revoked && !c.IsCA && c.NotAfter > now)
            .GroupBy(c => c.SigningProfileId)
            .Select(g => new { SigningProfileId = g.Key, Count = g.Count() })
            .ToListAsync();

        // Count pending requests per signing profile in one query
        var pendingCounts = await _db.CertificateRequests
            .Where(c => c.SigningProfileId != null && c.Status == "Pending")
            .GroupBy(c => c.SigningProfileId)
            .Select(g => new { SigningProfileId = g.Key, Count = g.Count() })
            .ToListAsync();

        // Load admin groups for quota limits in one query (identified by CaManage capability)
        var adminGroups = await _db.CaGroups
            .Where(g => g.CertificateAuthorityId != null
                && g.Grants.Any(gr => gr.Capability == Capabilities.CaManage && gr.ResourceType == null))
            .AsNoTracking()
            .ToListAsync();

        // Build summary in memory — no per-CA queries
        var summary = new QuotaUsageSummary();

        foreach (var ca in cas)
        {
            var caSigningProfileIds = ca.CertificateId.HasValue
                ? allSigningProfiles
                    .Where(sp => sp.IssuerId == ca.CertificateId.Value)
                    .Select(sp => sp.Id)
                    .ToHashSet()
                : new HashSet<Guid>();

            var issuedCount = certCounts
                .Where(cc => cc.SigningProfileId.HasValue && caSigningProfileIds.Contains(cc.SigningProfileId.Value))
                .Sum(cc => cc.Count);

            var pendingCount = pendingCounts
                .Where(pc => pc.SigningProfileId.HasValue && caSigningProfileIds.Contains(pc.SigningProfileId.Value))
                .Sum(pc => pc.Count);

            var adminGroup = adminGroups.FirstOrDefault(g => g.CertificateAuthorityId == ca.Id);
            var maxCerts = adminGroup?.MaxCertificates ?? 0;
            var maxPending = adminGroup?.MaxPendingRequests ?? 0;

            var status = new QuotaStatus
            {
                CaId = ca.Id,
                GroupId = adminGroup?.Id,
                CaName = ca.Name,
                MaxCertificates = maxCerts,
                MaxPendingRequests = maxPending,
                IssuedCount = issuedCount,
                PendingCount = pendingCount
            };

            if (maxCerts == 0)
            {
                status.RemainingCount = -1;
                status.IsExceeded = false;
                status.UsagePercent = 0;
            }
            else
            {
                status.RemainingCount = Math.Max(0, maxCerts - issuedCount);
                status.IsExceeded = issuedCount >= maxCerts;
                status.UsagePercent = Math.Round((double)issuedCount / maxCerts * 100, 2);
            }

            summary.CaQuotas.Add(status);
            summary.TotalIssuedCertificates += status.IssuedCount;

            if (status.IsExceeded)
                summary.ExceededCount++;
            else if (status.MaxCertificates > 0 && status.UsagePercent >= 80)
                summary.WarningCount++;
        }

        return summary;
    }

    /// <summary>
    /// Counts active (non-revoked, non-expired) non-CA certificates issued by signing profiles
    /// that reference the given CA certificate ID as their issuer.
    /// </summary>
    /// <param name="caCertificateId">The CA's certificate entity ID.</param>
    /// <param name="now">Current UTC time for expiration check.</param>
    private async Task<int> CountActiveCertificatesAsync(Guid caCertificateId, DateTime now)
    {
        // Get signing profile IDs that use this CA as the issuer
        var signingProfileIds = await _db.SigningProfiles
            .AsNoTracking()
            .Where(sp => sp.IssuerId == caCertificateId)
            .Select(sp => sp.Id)
            .ToListAsync();

        if (signingProfileIds.Count == 0)
            return 0;

        return await _db.Certificates
            .AsNoTracking()
            .Where(c => c.SigningProfileId != null
                && signingProfileIds.Contains(c.SigningProfileId.Value)
                && !c.Revoked
                && !c.IsCA
                && c.NotAfter > now)
            .CountAsync();
    }

    /// <summary>
    /// Counts pending CSRs associated with signing profiles that reference the given CA certificate ID.
    /// </summary>
    /// <param name="caCertificateId">The CA's certificate entity ID.</param>
    private async Task<int> CountPendingRequestsAsync(Guid caCertificateId)
    {
        var signingProfileIds = await _db.SigningProfiles
            .AsNoTracking()
            .Where(sp => sp.IssuerId == caCertificateId)
            .Select(sp => sp.Id)
            .ToListAsync();

        if (signingProfileIds.Count == 0)
            return 0;

        return await _db.CertificateRequests
            .AsNoTracking()
            .Where(c => c.SigningProfileId != null
                && signingProfileIds.Contains(c.SigningProfileId.Value)
                && c.Status == "Pending")
            .CountAsync();
    }
}
