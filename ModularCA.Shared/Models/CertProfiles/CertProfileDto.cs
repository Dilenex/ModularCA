namespace ModularCA.Shared.Models.CertProfiles;

/// <summary>
/// Data transfer object for a certificate profile, representing extension templates,
/// validity constraints, algorithm restrictions, and CT log configuration.
/// </summary>
public class CertProfileDto
{
    public Guid Id { get; set; }
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

    /// <summary>Whether wildcard SAN/CN entries may be issued under this profile.</summary>
    public bool AllowWildcard { get; set; }

    /// <summary>Whether issued certificates are submitted to Certificate Transparency logs.</summary>
    public bool CtEnabled { get; set; }

    /// <summary>JSON array of CT log IDs to submit to.</summary>
    public string? CtLogIds { get; set; }

    /// <summary>
    /// Resolved friendly names for the extended key usage OIDs.
    /// </summary>
    public List<string> ExtendedKeyUsageNames { get; set; } = new();

    /// <summary>
    /// Minimum validity period in ISO 8601 duration format (e.g., "P47D"). Nullable.
    /// </summary>
    public string? ValidityPeriodMin { get; set; }

    /// <summary>
    /// Maximum validity period in ISO 8601 duration format (e.g., "P1Y"). Nullable.
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
    /// The space the profile belongs to; null for an instance profile. A profile with neither a
    /// space nor a CA is instance-wide, and only a caller holding cert.revoke at system scope may change it.
    /// </summary>
    public Guid? SpaceId { get; set; }

    /// <summary>
    /// ID of the parent profile this profile inherits from. Null means no inheritance.
    /// </summary>
    public Guid? InheritsFromId { get; set; }

    /// <summary>
    /// When true, this profile merges with its parent profile via inheritance.
    /// </summary>
    public bool InheritanceEnabled { get; set; }

    /// <summary>
    /// What the application uses this profile for when it finds it by name, or null. A profile
    /// with a purpose cannot be renamed, deleted, bound to one CA or changed in kind.
    /// </summary>
    public string? SystemPurpose { get; set; }

    /// <summary>
    /// The CAs that name this profile for a certificate of their own, one line each
    /// ("CA name: TSA"). A profile with any cannot be deleted.
    /// </summary>
    public List<string> InfrastructureUses { get; set; } = new();

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
