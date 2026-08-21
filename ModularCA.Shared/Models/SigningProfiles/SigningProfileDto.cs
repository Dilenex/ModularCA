namespace ModularCA.Shared.Models.SigningProfiles;

/// <summary>
/// Data transfer object for a signing profile, representing algorithm constraints,
/// name constraints, policy OIDs, and allowed cert profile associations.
/// </summary>
public class SigningProfileDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// JSON array of allowed key algorithms (e.g., ["RSA", "ECDSA"]).
    /// </summary>
    public string AllowedAlgorithms { get; set; } = "[]";

    /// <summary>
    /// JSON array of allowed extended key usage OIDs.
    /// </summary>
    public string AllowedEKUs { get; set; } = "[]";

    /// <summary>Whether the ExtendedKeyUsage extension is emitted as critical.</summary>
    public bool ExtendedKeyUsageCritical { get; set; }

    /// <summary>JSON object mapping certificate policy OIDs to their qualifiers.</summary>
    public string? PolicyQualifiersJson { get; set; }

    public bool IsDefault { get; set; }

    public Guid? IssuerId { get; set; }

    public int? MaxPathLength { get; set; }

    /// <summary>
    /// JSON array of permitted name subtrees for NameConstraints extension.
    /// </summary>
    public string? NameConstraintsPermitted { get; set; }

    /// <summary>
    /// JSON array of excluded name subtrees for NameConstraints extension.
    /// </summary>
    public string? NameConstraintsExcluded { get; set; }

    /// <summary>
    /// JSON array of certificate policy OIDs.
    /// </summary>
    public string? PolicyOids { get; set; }

    /// <summary>
    /// When true, adds the InhibitAnyPolicy extension to issued certificates.
    /// </summary>
    public bool InhibitAnyPolicy { get; set; }

    /// <summary>
    /// IDs of cert profiles allowed for use with this signing profile.
    /// </summary>
    public List<Guid> AllowedCertProfileIds { get; set; } = new();

    /// <summary>
    /// ID of the parent signing profile this profile inherits from. Null means no inheritance.
    /// </summary>
    public Guid? InheritsFromId { get; set; }

    /// <summary>
    /// When true, this profile merges with its parent profile via inheritance.
    /// </summary>
    public bool InheritanceEnabled { get; set; }
}
