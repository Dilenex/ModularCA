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
    /// ID of the parent profile this profile inherits from. Null means no inheritance.
    /// </summary>
    public Guid? InheritsFromId { get; set; }

    /// <summary>
    /// When true, this profile merges with its parent profile via inheritance.
    /// </summary>
    public bool InheritanceEnabled { get; set; }
}
