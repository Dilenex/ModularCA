using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Assigns a role to a user or group with optional scope (global, space, or CA).
/// Exactly one of UserId or GroupId must be set.
/// </summary>
public class RoleAssignmentEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The role being assigned.</summary>
    [Required]
    public Guid RoleId { get; set; }

    /// <summary>The user this role is assigned to. Null if assigned to a group.</summary>
    public Guid? UserId { get; set; }

    /// <summary>The group this role is assigned to. Null if assigned to a user.</summary>
    public Guid? GroupId { get; set; }

    /// <summary>
    /// Space scope. Null = the instance (all spaces).
    /// </summary>
    public Guid? SpaceId { get; set; }

    /// <summary>
    /// CA scope. Null = all CAs in scope (space-wide or global).
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;

    /// <summary>The user who created this assignment, for audit trail.</summary>
    public Guid? AssignedByUserId { get; set; }

    // Navigation

    [ForeignKey("RoleId")]
    public virtual RoleEntity Role { get; set; } = null!;

    [ForeignKey("UserId")]
    public virtual UserEntity? User { get; set; }

    [ForeignKey("GroupId")]
    public virtual CaGroupEntity? Group { get; set; }

    [ForeignKey(nameof(SpaceId))]
    public virtual SpaceEntity? Space { get; set; }

    [ForeignKey("CertificateAuthorityId")]
    public virtual CertificateAuthorityEntity? CertificateAuthority { get; set; }

    [ForeignKey("AssignedByUserId")]
    public virtual UserEntity? AssignedByUser { get; set; }
}
