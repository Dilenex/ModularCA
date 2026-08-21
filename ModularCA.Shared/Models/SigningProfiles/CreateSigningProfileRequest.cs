namespace ModularCA.Shared.Models.SigningProfiles;

/// <summary>
/// Request body for creating a new signing profile.
/// </summary>
public class CreateSigningProfileRequest
{
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
    /// Cert profile IDs to link as allowed for this signing profile.
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

    /// <summary>
    /// When true, the ExtendedKeyUsage extension is emitted as critical (RFC 5280 §4.2.1.12).
    /// The admin UI has always sent this, but it was absent from the request DTO, so the
    /// "mark Extended Key Usage as critical" checkbox silently did nothing.
    /// </summary>
    public bool ExtendedKeyUsageCritical { get; set; }

    /// <summary>
    /// JSON object mapping certificate policy OIDs to their qualifiers. Same story as
    /// <see cref="ExtendedKeyUsageCritical"/> — sent by the UI, previously dropped on the floor.
    /// </summary>
    public string? PolicyQualifiersJson { get; set; }
}
