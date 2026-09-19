using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Represents a signing profile that controls how certificates are issued by a CA.
/// Defines algorithm constraints, name constraints, policy OIDs, and other signing parameters.
/// </summary>
[Table("SigningProfiles")]
public class SigningProfileEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid(); // UUID primary key

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    public int? MaxPathLength { get; set; }

    /// <summary>
    /// JSON array of allowed key algorithms (e.g., ["RSA", "ECDSA"]).
    /// </summary>
    public string AllowedAlgorithms { get; set; } = "[]";

    /// <summary>
    /// JSON array of allowed extended key usage OIDs.
    /// </summary>
    public string AllowedEKUs { get; set; } = "[]";

    public bool IsDefault { get; set; } = false;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public int Revision { get; set; } = 0;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Guid? IssuerId { get; set; } // CA keypair ID or CA entity reference
    public CertificateEntity Issuer { get; set; } = default!;

    /// <summary>
    /// JSON array of permitted name subtrees for NameConstraints extension.
    /// Format: ["DNS:.example.com", "IP:10.0.0.0/8", "Email:@example.com"]
    /// </summary>
    public string? NameConstraintsPermitted { get; set; }

    /// <summary>
    /// JSON array of excluded name subtrees for NameConstraints extension.
    /// </summary>
    public string? NameConstraintsExcluded { get; set; }

    /// <summary>
    /// JSON array of certificate policy OIDs (e.g., ["2.23.140.1.2.1"]).
    /// </summary>
    public string? PolicyOids { get; set; }

    /// <summary>
    /// JSON object mapping each policy OID in <see cref="PolicyOids"/> to its qualifiers and
    /// criticality flag. Shape: <c>{ "2.23.140.1.2.1": { "cpsUri": "https://...", "userNotice": "...", "critical": false } }</c>.
    /// Missing keys mean "no qualifiers, non-critical". The <c>CertificateBuilderService.AddPolicyExtensions</c>
    /// method emits <c>PolicyInformation</c> with <c>CpsUri</c> and <c>UserNotice</c> qualifier sequences
    /// when present and sets the extension critical flag to true if any per-OID <c>critical</c> is true.
    /// </summary>
    public string? PolicyQualifiersJson { get; set; }

    /// <summary>
    /// When true, the <c>ExtendedKeyUsage</c> extension is emitted as critical on certificates
    /// issued under this profile. RFC 5280 §4.2.1.12 recommends critical when the cert's purpose
    /// is restricted. Default <c>false</c> for backwards compatibility.
    /// </summary>
    public bool ExtendedKeyUsageCritical { get; set; } = false;

    /// <summary>
    /// When true, adds the InhibitAnyPolicy extension to issued certificates.
    /// </summary>
    public bool InhibitAnyPolicy { get; set; } = false;

    /// <summary>
    /// Parent signing profile this profile inherits from. Null means standalone.
    /// </summary>
    public Guid? InheritsFromId { get; set; }

    /// <summary>
    /// When true, non-null fields override the parent's values. When false, standalone.
    /// </summary>
    public bool InheritanceEnabled { get; set; } = false;

    /// <summary>
    /// Navigation property to the parent signing profile this profile inherits from.
    /// </summary>
    [ForeignKey("InheritsFromId")]
    public virtual SigningProfileEntity? InheritsFrom { get; set; }
}
