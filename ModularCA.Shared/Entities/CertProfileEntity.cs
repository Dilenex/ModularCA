using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Represents a certificate profile that defines the structure and constraints of issued certificates.
/// Includes key usage, EKU, validity period, algorithm restrictions, and CT log configuration.
/// </summary>
[Table("CertProfiles")]
public class CertProfileEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid(); // UUID primary key

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(255)]
    public string Description { get; set; } = string.Empty;

    public bool IsCaProfile { get; set; }

    /// <summary>
    /// Comma-separated key usage flags (e.g., "digitalSignature,keyCertSign").
    /// </summary>
    [MaxLength(255)]
    public string KeyUsages { get; set; } = string.Empty;

    /// <summary>
    /// Comma-separated OIDs for extended key usages.
    /// </summary>
    [MaxLength(255)]
    public string ExtendedKeyUsages { get; set; } = string.Empty;

    /// <summary>
    /// Minimum validity period in ISO 8601 duration format (e.g., "P47D"). Nullable.
    /// </summary>
    [MaxLength(50)]
    public string? ValidityPeriodMin { get; set; }

    /// <summary>
    /// Maximum validity period in ISO 8601 duration format (e.g., "P1Y"). Nullable.
    /// </summary>
    [MaxLength(50)]
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
    /// JSON array of allowed signature algorithms (e.g., ["SHA256WithRSA", "SHA384WithECDSA"]).
    /// </summary>
    public string AllowedSignatureAlgorithms { get; set; } = "[]";

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public int Revision { get; set; } = 0;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    [Required]
    public bool CanBeDeleted { get; set; } = true;

    public string ProfileHash { get; set; } = string.Empty;

    /// <summary>
    /// When true, certificates issued with this profile will be submitted to configured CT logs.
    /// </summary>
    public bool CtEnabled { get; set; } = false;

    /// <summary>
    /// When true, this profile permits wildcard SAN/CN entries (e.g. <c>*.example.com</c>).
    /// Wildcards are still subject to structural validation in <c>DnComponentSanitizer.ValidateDnsName</c>:
    /// at most one <c>*</c>, only as the leftmost label, and at least two additional labels.
    /// Default is <c>false</c> — fail-closed for new profiles.
    /// </summary>
    public bool AllowWildcard { get; set; } = false;

    /// <summary>
    /// JSON array of CtLog Guids to submit certificates to. Null = use all enabled CT logs.
    /// </summary>
    public string? CtLogIds { get; set; }

    /// <summary>
    /// The CA this profile is scoped to. Null means system-wide (managed by system-admin/operator only).
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>
    /// The space that owns this profile. Null means the profile
    /// is not space-scoped (system-wide baseline profiles set by a system admin). When
    /// non-null, the profile is only visible inside the owning space and cannot be
    /// linked to a CA in a different space. Populated automatically when a CA-scoped
    /// profile is created via <c>CaCreationService</c> / <c>BootstrapProfileSeeder</c>.
    /// </summary>
    public Guid? SpaceId { get; set; }

    /// <summary>
    /// Parent profile this profile inherits from. Null means standalone (no inheritance).
    /// Only CA-scoped profiles should inherit from system-wide profiles.
    /// </summary>
    public Guid? InheritsFromId { get; set; }

    /// <summary>
    /// When true, non-null fields in this profile override the parent's values.
    /// When false, this profile is standalone and ignores any parent.
    /// </summary>
    public bool InheritanceEnabled { get; set; } = false;

    /// <summary>
    /// Navigation property to the CA this profile is scoped to.
    /// </summary>
    [ForeignKey("CertificateAuthorityId")]
    public virtual CertificateAuthorityEntity? CertificateAuthority { get; set; }

    /// <summary>
    /// Navigation property to the parent profile this profile inherits from.
    /// </summary>
    [ForeignKey("InheritsFromId")]
    public virtual CertProfileEntity? InheritsFrom { get; set; }
}
