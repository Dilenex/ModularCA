using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Defines an SSH certificate profile that constrains which principals, extensions,
/// and validity durations are allowed on issued SSH certificates.
/// </summary>
[Table("SshCertProfiles")]
public class SshCertProfileEntity
{
    /// <summary>Unique identifier for this cert profile.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Human-readable name (must be unique).</summary>
    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description of the profile's purpose.</summary>
    [MaxLength(255)]
    public string? Description { get; set; }

    /// <summary>JSON array of regex patterns that allowed principals must match.</summary>
    public string AllowedPrincipalPatterns { get; set; } = "[]";

    /// <summary>Maximum number of principals permitted on a single certificate.</summary>
    public int MaxPrincipals { get; set; } = 10;

    /// <summary>JSON array of SSH extensions that are permitted on certificates.</summary>
    public string AllowedExtensions { get; set; } = "[\"permit-pty\",\"permit-port-forwarding\",\"permit-agent-forwarding\",\"permit-X11-forwarding\",\"permit-user-rc\"]";

    /// <summary>JSON array of SSH extensions that must be present on every certificate.</summary>
    public string RequiredExtensions { get; set; } = "[]";

    /// <summary>Maximum validity duration in hours allowed by this cert profile.</summary>
    public int MaxValidityHours { get; set; } = 720;

    /// <summary>
    /// The certificate type the profile is for: <c>user</c>, <c>host</c>, or null for either
    /// (<see cref="ModularCA.Shared.Utils.SshProfileCertificateType"/>).
    /// </summary>
    [MaxLength(10)]
    public string? CertificateType { get; set; }

    /// <summary>UTC timestamp when this profile was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
