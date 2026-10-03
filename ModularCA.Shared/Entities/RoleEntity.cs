using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A named, reusable bundle of capabilities. Roles can be assigned to users or groups
/// with scope (global, space, or CA). Built-in roles (Administrator, Operator, Auditor,
/// Requester) are seeded at bootstrap and cannot be deleted.
/// </summary>
public class RoleEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Unique display name for this role.</summary>
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description of what this role grants.</summary>
    [MaxLength(500)]
    public string? Description { get; set; }

    /// <summary>True for the seeded Administrator/Operator/Auditor/Requester roles. Cannot be deleted.</summary>
    public bool IsBuiltIn { get; set; }

    /// <summary>
    /// Space that owns this role. Null for system-wide roles visible across all spaces.
    /// </summary>
    public Guid? SpaceId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>The user who created this role, for audit trail.</summary>
    public Guid? CreatedByUserId { get; set; }

    // Navigation

    [ForeignKey(nameof(SpaceId))]
    public virtual SpaceEntity? Space { get; set; }

    [ForeignKey("CreatedByUserId")]
    public virtual UserEntity? CreatedByUser { get; set; }

    /// <summary>Capability bindings that make up this role.</summary>
    public virtual ICollection<RoleCapabilityEntity> Capabilities { get; set; } = new List<RoleCapabilityEntity>();

    /// <summary>Assignments of this role to users or groups.</summary>
    public virtual ICollection<RoleAssignmentEntity> Assignments { get; set; } = new List<RoleAssignmentEntity>();
}
