using System.ComponentModel.DataAnnotations;
using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Models.AccessBadges;

/// <summary>A badge as the console shows it: name, default flag and the sources it keeps.</summary>
public class AccessBadgeDto
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsDefault { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public List<AccessBadgeSourceDto> Sources { get; set; } = new();
}

/// <summary>One grant source a badge keeps, with a label for display.</summary>
public class AccessBadgeSourceDto
{
    public AccessBadgeSourceKind Kind { get; set; }
    public Guid SourceId { get; set; }
    /// <summary>Human-readable name, resolved when the source still exists; null if it was removed since.</summary>
    public string? Label { get; set; }
}

/// <summary>A grant source the user holds and may put on a badge.</summary>
public class AccessBadgeSourceOptionDto
{
    public AccessBadgeSourceKind Kind { get; set; }
    public Guid SourceId { get; set; }
    /// <summary>Display name: the group, the role, or the capability.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>Where it applies: "System", the tenant, or the CA label.</summary>
    public string Scope { get; set; } = string.Empty;
    /// <summary>The capabilities this source contributes, for the picker's preview.</summary>
    public List<string> Capabilities { get; set; } = new();
}

/// <summary>Create or replace a badge.</summary>
public class AccessBadgeWriteRequest
{
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Description { get; set; }

    public bool IsDefault { get; set; }

    /// <summary>The sources to keep. Every one must be a source the user holds.</summary>
    [Required]
    public List<AccessBadgeSourceRef> Sources { get; set; } = new();
}

/// <summary>A source reference in a write request.</summary>
public class AccessBadgeSourceRef
{
    public AccessBadgeSourceKind Kind { get; set; }
    public Guid SourceId { get; set; }
}

/// <summary>Put on a badge, or take the worn one off (<c>BadgeId</c> null).</summary>
public class AccessBadgeSwitchRequest
{
    public Guid? BadgeId { get; set; }

    /// <summary>
    /// The session's refresh token, so later refreshes keep the badge. Stored hashed; matched
    /// against the caller's own live tokens only.
    /// </summary>
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}

/// <summary>The new access token after a switch, and what is now worn.</summary>
public class AccessBadgeSwitchResponse
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public AccessBadgeSummary? Badge { get; set; }
}

/// <summary>The worn badge as <c>/api/v1/me</c> and the switch response report it.</summary>
public class AccessBadgeSummary
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
}
