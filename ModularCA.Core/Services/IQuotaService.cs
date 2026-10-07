namespace ModularCA.Core.Services;

/// <summary>
/// Checks and reports certificate quota usage per CA, based on the admin group's configured limits.
/// </summary>
public interface IQuotaService
{
    /// <summary>
    /// Returns detailed quota status for a specific CA, including issued count, remaining count, and usage percentage.
    /// </summary>
    /// <param name="caId">The certificate authority ID.</param>
    Task<QuotaStatus> CheckQuotaAsync(Guid caId);

    /// <summary>
    /// Returns true if the CA has not exceeded its certificate quota (or if quotas are unlimited).
    /// Raises security alerts when usage exceeds 80% or 100%.
    /// </summary>
    /// <param name="caId">The certificate authority ID.</param>
    Task<bool> CanIssueCertificateAsync(Guid caId);

    /// <summary>
    /// Returns an aggregated summary of quota usage across all CAs.
    /// </summary>
    Task<QuotaUsageSummary> GetUsageSummaryAsync();
}

/// <summary>
/// Represents the quota status for a single certificate authority.
/// </summary>
public class QuotaStatus
{
    /// <summary>The certificate authority ID.</summary>
    public Guid CaId { get; set; }

    /// <summary>The admin group ID that carries the quota limits. Used by PUT /api/v1/admin/quotas/{groupId}.</summary>
    public Guid? GroupId { get; set; }

    /// <summary>The certificate authority name.</summary>
    public string CaName { get; set; } = string.Empty;

    /// <summary>Maximum certificates allowed. 0 means unlimited.</summary>
    public int MaxCertificates { get; set; }

    /// <summary>Maximum pending CSRs allowed. 0 means unlimited.</summary>
    public int MaxPendingRequests { get; set; }

    /// <summary>Number of active (non-revoked, non-expired) certificates issued by this CA.</summary>
    public int IssuedCount { get; set; }

    /// <summary>Number of pending CSRs for this CA.</summary>
    public int PendingCount { get; set; }

    /// <summary>Remaining certificates that can be issued. -1 if unlimited.</summary>
    public int RemainingCount { get; set; }

    /// <summary>Whether the certificate quota has been exceeded.</summary>
    public bool IsExceeded { get; set; }

    /// <summary>Usage percentage (0-100). 0 if unlimited.</summary>
    public double UsagePercent { get; set; }
}

/// <summary>
/// Aggregated quota usage summary across all CAs.
/// </summary>
public class QuotaUsageSummary
{
    /// <summary>Per-CA quota statuses.</summary>
    public List<QuotaStatus> CaQuotas { get; set; } = new();

    /// <summary>Total active certificates across all CAs.</summary>
    public int TotalIssuedCertificates { get; set; }

    /// <summary>Number of CAs that have exceeded their quota.</summary>
    public int ExceededCount { get; set; }

    /// <summary>Number of CAs approaching their quota (above 80%).</summary>
    public int WarningCount { get; set; }
}
