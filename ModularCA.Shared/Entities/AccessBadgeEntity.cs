using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A named subset of the rights a user already holds. A session wears at most one badge;
/// wearing none is the normal state, in which every grant source counts. A badge can only
/// restrict: it selects from grant sources the user genuinely holds and never adds one.
/// </summary>
/// <remarks>
/// Two uses drive it: least privilege for day-to-day work, and security testing, where an
/// administrator needs to see the console exactly as, say, an auditor on one CA sees it, with
/// the API refusing exactly what it would refuse them. The worn badge travels in the access
/// token's <c>badge</c> claim and is enforced by the authorization resolver on every request.
/// Named <c>AccessBadge</c> in code because the front end already uses "badge" for its status
/// chips.
/// </remarks>
[Table("AccessBadges")]
public class AccessBadgeEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The user the badge belongs to. Only that user can wear it.</summary>
    [Required]
    public Guid UserId { get; set; }

    /// <summary>Display name, unique per user, e.g. "Auditor on staging-ca-r1".</summary>
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Description { get; set; }

    /// <summary>When set, a new session starts wearing this badge. At most one per user.</summary>
    public bool IsDefault { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Who created it: the user themself, or an administrator on their behalf.</summary>
    public Guid? CreatedByUserId { get; set; }

    public DateTime? UpdatedAt { get; set; }

    [ForeignKey(nameof(UserId))]
    public virtual UserEntity User { get; set; } = null!;

    /// <summary>The grant sources the badge keeps. Everything else the user holds is ignored while it is worn.</summary>
    public virtual ICollection<AccessBadgeSourceEntity> Sources { get; set; } = new List<AccessBadgeSourceEntity>();
}

/// <summary>One grant source kept by a badge.</summary>
[Table("AccessBadgeSources")]
public class AccessBadgeSourceEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid BadgeId { get; set; }

    [Required]
    public AccessBadgeSourceKind Kind { get; set; }

    /// <summary>
    /// The source's id: the group id for <see cref="AccessBadgeSourceKind.Group"/>, the role
    /// assignment id for <see cref="AccessBadgeSourceKind.RoleAssignment"/>, the user grant id
    /// for <see cref="AccessBadgeSourceKind.CapabilityGrant"/>.
    /// </summary>
    [Required]
    public Guid SourceId { get; set; }

    [ForeignKey(nameof(BadgeId))]
    public virtual AccessBadgeEntity Badge { get; set; } = null!;
}
