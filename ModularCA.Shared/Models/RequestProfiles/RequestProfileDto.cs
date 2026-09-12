namespace ModularCA.Shared.Models.RequestProfiles;

public class RequestProfileDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public List<SubjectDnFieldRule> SubjectDnRules { get; set; } = new();
    public SanRules SanRules { get; set; } = new();
    public List<Guid> AllowedCertProfileIds { get; set; } = new();
    public Guid? DefaultCertProfileId { get; set; }
    public bool RequireApproval { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    /// <summary>
    /// Optional CA scope. Null means system-wide profile.
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>
    /// ID of the parent profile this profile inherits from. Null means no inheritance.
    /// </summary>
    public Guid? InheritsFromId { get; set; }

    /// <summary>
    /// When true, this profile merges with its parent profile via inheritance.
    /// </summary>
    public bool InheritanceEnabled { get; set; }
}
