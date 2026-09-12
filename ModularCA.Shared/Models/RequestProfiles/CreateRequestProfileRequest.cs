namespace ModularCA.Shared.Models.RequestProfiles;

public class CreateRequestProfileRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public List<SubjectDnFieldRule> SubjectDnRules { get; set; } = new();
    public SanRules? SanRules { get; set; }
    public List<Guid>? AllowedCertProfileIds { get; set; }
    public Guid? DefaultCertProfileId { get; set; }
    public bool RequireApproval { get; set; } = false;

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
