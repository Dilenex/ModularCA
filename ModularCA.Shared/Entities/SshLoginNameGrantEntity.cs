using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A login name granted on one SSH CA key to one user or to one group: the holder may get a
/// certificate from that key that logs in as <see cref="LoginName"/>. Exactly one of
/// <see cref="UserId"/> and <see cref="GroupId"/> is set, which a check constraint holds. A
/// group's members hold the name while they are members.
/// </summary>
[Table("SshLoginNameGrants")]
public class SshLoginNameGrantEntity
{
    /// <summary>The grant.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The SSH CA key the name is granted on.</summary>
    [Required]
    public Guid SshCaKeyId { get; set; }

    /// <summary>The SSH CA key the name is granted on.</summary>
    [ForeignKey(nameof(SshCaKeyId))]
    public virtual SshCaKeyEntity SshCaKey { get; set; } = default!;

    /// <summary>The login name, as <c>SshLoginNameRules</c> allows one. Compared byte for byte.</summary>
    [Required]
    [MaxLength(128)]
    public string LoginName { get; set; } = string.Empty;

    /// <summary>The user the name is granted to, or null for a grant to a group.</summary>
    public Guid? UserId { get; set; }

    /// <summary>The user the name is granted to.</summary>
    [ForeignKey(nameof(UserId))]
    public virtual UserEntity? User { get; set; }

    /// <summary>The group the name is granted to, or null for a grant to a user.</summary>
    public Guid? GroupId { get; set; }

    /// <summary>The group the name is granted to.</summary>
    [ForeignKey(nameof(GroupId))]
    public virtual CaGroupEntity? Group { get; set; }

    /// <summary>The longest certificate that may carry the name under this grant, in hours; null for the SSH CA key's maximum.</summary>
    public int? MaxValidityHours { get; set; }

    /// <summary>When the grant ends, UTC; null for a grant that does not end. No certificate under it is valid past this.</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>A note by whoever granted the name.</summary>
    [MaxLength(256)]
    public string? Note { get; set; }

    /// <summary>Who granted the name; null once that user is deleted.</summary>
    public Guid? GrantedByUserId { get; set; }

    /// <summary>The username of whoever granted the name, kept as text so the row still reads after that user is deleted.</summary>
    [MaxLength(255)]
    public string? GrantedByUsername { get; set; }

    /// <summary>When the name was granted, UTC.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>The names of the constraints on <see cref="SshLoginNameGrantEntity"/> that code refers to.</summary>
public static class SshLoginNameGrantConstraints
{
    /// <summary>The check that a grant names a user or a group, and not both.</summary>
    public const string ExactlyOneTarget = "CK_SshLoginNameGrants_ExactlyOneTarget";
}
