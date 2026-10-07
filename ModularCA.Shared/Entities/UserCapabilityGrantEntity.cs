using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A direct capability grant on a user (no role or group required).
/// Scope is determined by SpaceId and CertificateAuthorityId:
/// both null = global, SpaceId only = space-wide, both set = CA-scoped.
/// </summary>
public class UserCapabilityGrantEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The user this grant applies to.</summary>
    [Required]
    public Guid UserId { get; set; }

    /// <summary>The capability being granted.</summary>
    [Required]
    [MaxLength(100)]
    public string Capability { get; set; } = string.Empty;

    /// <summary>Space scope. Null = the instance.</summary>
    public Guid? SpaceId { get; set; }

    /// <summary>CA scope. Null = all CAs in scope.</summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>
    /// Optional resource type for resource-scoped grants
    /// (e.g. "CertProfile", "SigningProfile", "RequestProfile").
    /// </summary>
    [MaxLength(50)]
    public string? ResourceType { get; set; }

    /// <summary>Optional resource ID for resource-scoped grants.</summary>
    public Guid? ResourceId { get; set; }

    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    /// <summary>The user who created this grant, for audit trail.</summary>
    public Guid? GrantedByUserId { get; set; }

    // Navigation

    [ForeignKey("UserId")]
    public virtual UserEntity User { get; set; } = null!;

    [ForeignKey(nameof(SpaceId))]
    public virtual SpaceEntity? Space { get; set; }

    [ForeignKey("CertificateAuthorityId")]
    public virtual CertificateAuthorityEntity? CertificateAuthority { get; set; }

    [ForeignKey("GrantedByUserId")]
    public virtual UserEntity? GrantedByUser { get; set; }
}
