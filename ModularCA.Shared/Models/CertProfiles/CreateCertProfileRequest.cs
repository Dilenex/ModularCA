namespace ModularCA.Shared.Models.CertProfiles;

/// <summary>
/// Request body for creating a new certificate profile.
/// </summary>
public class CreateCertProfileRequest
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsCaProfile { get; set; }
    /// <summary>
    /// Comma-separated key usage flags (e.g., "digitalSignature,keyCertSign").
    /// </summary>
    public string KeyUsages { get; set; } = string.Empty;

    /// <summary>
    /// Comma-separated OIDs for extended key usages.
    /// </summary>
    public string ExtendedKeyUsages { get; set; } = string.Empty;

    /// <summary>
    /// Minimum validity period in ISO 8601 duration format (e.g., "P47D").
    /// </summary>
    public string? ValidityPeriodMin { get; set; }

    /// <summary>
    /// Maximum validity period in ISO 8601 duration format (e.g., "P1Y").
    /// </summary>
    public string? ValidityPeriodMax { get; set; }

    /// <summary>
    /// JSON array of allowed key algorithms (e.g., ["RSA", "ECDSA"]).
    /// </summary>
    public string AllowedKeyAlgorithms { get; set; } = "[]";

    /// <summary>
    /// JSON array of allowed key sizes (e.g., [2048, 4096]).
    /// </summary>
    public string AllowedKeySizes { get; set; } = "[]";

    /// <summary>
    /// JSON array of allowed signature algorithms (e.g., ["SHA256WithRSA"]).
    /// </summary>
    public string AllowedSignatureAlgorithms { get; set; } = "[]";

    /// <summary>
    /// Optional CA scope. Null means system-wide profile.
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>
    /// ID of the parent profile this profile inherits from. Null means no inheritance.
    /// </summary>
    public Guid? InheritsFromId { get; set; }

    /// <summary>
    /// When true, this profile merges with its parent profile via inheritance.
    /// </summary>
    public bool InheritanceEnabled { get; set; }

    /// <summary>
    /// Whether wildcard SAN/CN entries may be issued under this profile.
    /// <para>
    /// SECURITY-RELEVANT. Enforced at issuance via
    /// <c>CertificateIssuanceService.ValidateOverridesAgainstProfile</c> and passed to the builder as
    /// <c>allowWildcardSans</c>. The admin UI has always rendered a checkbox for it and sent the
    /// value, but it was missing here and unmapped in the service — so an operator UNCHECKING it to
    /// forbid wildcards saw the change accepted while the profile kept issuing them.
    /// </para>
    /// </summary>
    public bool AllowWildcard { get; set; }

    /// <summary>
    /// Whether issued certificates are submitted to Certificate Transparency logs. Same story as
    /// <see cref="AllowWildcard"/>: sent by the UI, previously dropped.
    /// </summary>
    public bool CtEnabled { get; set; }

    /// <summary>JSON array of CT log IDs to submit to when <see cref="CtEnabled"/> is set.</summary>
    public string? CtLogIds { get; set; }

    /// <summary>
    /// Share of a certificate's lifetime, 1 to 100, that remains when its soft expiry warning
    /// starts; null for the parent's value or the default (30; a CA certificate warns 30 days ahead).
    /// </summary>
    public int? ExpiryWarningPercent { get; set; }

    /// <summary>Longest soft warning window, an ISO 8601 duration such as <c>P30D</c>; null for no cap.</summary>
    public string? ExpiryWarningMaxWindow { get; set; }

    /// <summary>
    /// Share of the lifetime, 1 to 100 and no larger than <see cref="ExpiryWarningPercent"/>, that
    /// remains when the expiry alert starts; null for the parent's value or the default (10; a CA
    /// certificate alerts 7 days ahead).
    /// </summary>
    public int? ExpiryAlertPercent { get; set; }

    /// <summary>Longest alert window, an ISO 8601 duration; null for no cap.</summary>
    public string? ExpiryAlertMaxWindow { get; set; }

    /// <summary>The certificates are renewed automatically: their expiry never warns.</summary>
    public bool ExpiryNeverWarn { get; set; }

    /// <summary>
    /// The expiry warning settings replace the parent's rather than being held to warn no later
    /// than it. Only meaningful with inheritance.
    /// </summary>
    public bool ExpiryWarningOverridesParent { get; set; }
}
