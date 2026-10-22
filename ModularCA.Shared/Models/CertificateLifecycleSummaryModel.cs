namespace ModularCA.Shared.Models;

/// <summary>
/// Expiry and replacement counts over every end-entity certificate the caller may view in the
/// requested scope, returned by <c>GET /api/v1/admin/certificates/lifecycle-summary</c>.
/// </summary>
/// <remarks>
/// A certificate is <em>replaced</em> when it was reissued (flag or renewal link), or when a newer,
/// unrevoked, unexpired certificate from the same issuing CA carries the same subject DN and the
/// same SAN set. Replacement is only evaluated for certificates that expired within
/// <see cref="ReplacementWindowDays"/>; older expired certificates are counted in
/// <see cref="ExpiredUnchecked"/>. A certificate that was retired or whose expiry warning was
/// dismissed, and is not replaced, counts in <see cref="RetiredOrDismissed"/> and in none of the
/// <c>NotReplaced</c> counts.
/// </remarks>
public class CertificateLifecycleSummaryModel
{
    /// <summary>The server time the summary was computed against.</summary>
    public DateTime GeneratedAt { get; set; }

    /// <summary>How far back, in days, expired certificates are checked for a replacement.</summary>
    public int ReplacementWindowDays { get; set; }

    /// <summary>Every end-entity certificate in scope.</summary>
    public int Total { get; set; }

    /// <summary>Not revoked and not expired.</summary>
    public int Active { get; set; }

    /// <summary>Revoked, whatever their expiry.</summary>
    public int Revoked { get; set; }

    /// <summary>Expired and not revoked.</summary>
    public int Expired { get; set; }

    /// <summary>Active certificates that expire within 7 days.</summary>
    public int ExpiringWithin7Days { get; set; }

    /// <summary>Active certificates that expire within 30 days (includes the 7-day ones).</summary>
    public int ExpiringWithin30Days { get; set; }

    /// <summary>Active certificates expiring within 7 days with no replacement, not retired or dismissed.</summary>
    public int ExpiringWithin7DaysNotReplaced { get; set; }

    /// <summary>Active certificates expiring within 30 days with no replacement, not retired or dismissed.</summary>
    public int ExpiringWithin30DaysNotReplaced { get; set; }

    /// <summary>Certificates that expired within the replacement window and were replaced.</summary>
    public int ExpiredReplaced { get; set; }

    /// <summary>Certificates that expired within the replacement window, were not replaced, and were not retired or dismissed.</summary>
    public int ExpiredNotReplaced { get; set; }

    /// <summary>
    /// Certificates in the replacement band (expiring within 30 days, or expired within the window)
    /// that are not replaced but were retired or had their expiry warning dismissed.
    /// </summary>
    public int RetiredOrDismissed { get; set; }

    /// <summary>Expired certificates older than the replacement window, not checked for a replacement.</summary>
    public int ExpiredUnchecked { get; set; }

    /// <summary>Certificates that expired in the last 30 days, were not replaced, and were not retired or dismissed.</summary>
    public int RecentlyExpiredNotReplaced { get; set; }

    /// <summary>Number of certificates needing attention; <see cref="Attention"/> holds at most the first few.</summary>
    public int AttentionTotal { get; set; }

    /// <summary>
    /// Certificates needing attention, capped: recently expired ones with no replacement (most
    /// recent first), then ones expiring within 30 days with no replacement (soonest first).
    /// </summary>
    public List<CertificateAttentionItemModel> Attention { get; set; } = new();

    /// <summary>Certificate counts per issuing CA, for the dashboard's CA overview.</summary>
    public List<CertificateCountByCaModel> ByCa { get; set; } = new();
}

/// <summary>One certificate on the dashboard's "Needs attention" list.</summary>
public class CertificateAttentionItemModel
{
    public Guid CertificateId { get; set; }
    public string SerialNumber { get; set; } = string.Empty;
    public string SubjectDN { get; set; } = string.Empty;

    /// <summary>The subject's common name, or the serial when it has none.</summary>
    public string CommonName { get; set; } = string.Empty;

    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }

    /// <summary><c>expired</c> or <c>expiring</c>.</summary>
    public string State { get; set; } = string.Empty;

    public Guid? CaId { get; set; }
    public string? CaLabel { get; set; }
    public string? CaName { get; set; }

    /// <summary>
    /// How the certificate was issued, when recorded: ACME, EST, SCEP, CMP, MSAE or Manual. Null
    /// when nothing on record says.
    /// </summary>
    public string? IssuanceChannel { get; set; }

    /// <summary>
    /// Whether the auto-renewal job would renew this certificate before it expires. Null when the
    /// configuration is not available to the caller.
    /// </summary>
    public bool? AutoRenewal { get; set; }

    /// <summary>A renewal request exists for this certificate and has not been issued, rejected or cancelled.</summary>
    public bool RenewalPending { get; set; }
}

/// <summary>Number of end-entity certificates one CA issued, within the caller's scope.</summary>
public class CertificateCountByCaModel
{
    public Guid CaId { get; set; }
    public int Total { get; set; }
}
