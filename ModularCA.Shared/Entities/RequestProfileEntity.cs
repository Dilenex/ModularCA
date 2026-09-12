using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Defines what requesters can submit in certificate enrollment requests.
/// Controls subject DN field rules, SAN constraints, allowed cert profiles, and approval behavior.
/// </summary>
[Table("RequestProfiles")]
public class RequestProfileEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(255)]
    public string? Description { get; set; }

    /// <summary>
    /// JSON array of subject DN field rules. Each entry defines a DN component
    /// (CN, O, OU, etc.) with requirement level, fixed value, regex, and defaults.
    /// </summary>
    public string SubjectDnRules { get; set; } = "[]";

    /// <summary>
    /// JSON object defining SAN type constraints — allowed types, regex patterns,
    /// max counts per type, and whether SANs are required.
    /// </summary>
    public string SanRules { get; set; } = "{}";

    /// <summary>
    /// JSON array of allowed CertProfile IDs the requester can choose from.
    /// Empty array means all cert profiles are allowed.
    /// </summary>
    public string AllowedCertProfileIds { get; set; } = "[]";

    /// <summary>
    /// Default cert profile used when the requester doesn't specify one.
    /// </summary>
    public Guid? DefaultCertProfileId { get; set; }

    [ForeignKey("DefaultCertProfileId")]
    public virtual CertProfileEntity? DefaultCertProfile { get; set; }

    /// <summary>
    /// When true, requests require manual admin approval before issuance.
    /// When false, requests are auto-approved and issued immediately.
    /// </summary>
    public bool RequireApproval { get; set; } = false;

    /// <summary>
    /// Number of admin approvals required before a CSR can be issued.
    /// Only applies when RequireApproval is true. Default 1.
    /// </summary>
    public int RequiredApprovalCount { get; set; } = 1;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The CA this profile is scoped to. Null means system-wide (managed by system-admin/operator only).
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

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
    public virtual RequestProfileEntity? InheritsFrom { get; set; }
}
