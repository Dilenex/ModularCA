using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Defines an SSH request profile that controls which signing and cert profiles a user
/// may select, whether approval is required, and access scoping via CA association.
/// </summary>
[Table("SshRequestProfiles")]
public class SshRequestProfileEntity
{
    /// <summary>Unique identifier for this request profile.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Human-readable name (must be unique).</summary>
    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description of the profile's purpose.</summary>
    [MaxLength(255)]
    public string? Description { get; set; }

    /// <summary>JSON array of allowed SSH signing profile IDs (Guids).</summary>
    public string AllowedSshSigningProfileIds { get; set; } = "[]";

    /// <summary>JSON array of allowed SSH cert profile IDs (Guids).</summary>
    public string AllowedSshCertProfileIds { get; set; } = "[]";

    /// <summary>Whether certificate requests under this profile require manual approval.</summary>
    public bool RequireApproval { get; set; } = false;

    /// <summary>Maximum validity duration in hours allowed by this request profile.</summary>
    public int MaxValidityHours { get; set; } = 720;

    /// <summary>Optional CA association for group-based access scoping.</summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>
    /// The certificate type the profile is for: <c>user</c>, <c>host</c>, or null for either
    /// (<see cref="ModularCA.Shared.Utils.SshProfileCertificateType"/>).
    /// </summary>
    [MaxLength(10)]
    public string? CertificateType { get; set; }

    /// <summary>UTC timestamp when this profile was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
