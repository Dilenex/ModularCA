using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A named certificate template that bundles a Request Profile, Cert Profile, Signing Profile,
/// and CA together. Clients can request certificates by template name instead of profile IDs.
/// </summary>
[Table("CertificateTemplates")]
public class CertificateTemplateEntity
{
    /// <summary>
    /// Unique identifier for the certificate template.
    /// </summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Human-readable template name used by protocol clients to request certificates.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Optional description explaining the purpose or usage of this template.
    /// </summary>
    [MaxLength(255)]
    public string? Description { get; set; }

    /// <summary>
    /// The Certificate Authority that will issue certificates using this template.
    /// </summary>
    [Required]
    public Guid CaId { get; set; }

    /// <summary>
    /// Navigation property to the associated Certificate Authority.
    /// </summary>
    [ForeignKey("CaId")]
    public virtual CertificateAuthorityEntity Ca { get; set; } = default!;

    /// <summary>
    /// Optional request profile that controls subject/SAN validation and approval behavior.
    /// </summary>
    public Guid? RequestProfileId { get; set; }

    /// <summary>
    /// Navigation property to the optional request profile.
    /// </summary>
    [ForeignKey("RequestProfileId")]
    public virtual RequestProfileEntity? RequestProfile { get; set; }

    /// <summary>
    /// The certificate profile defining key usage, extensions, and certificate content.
    /// </summary>
    [Required]
    public Guid CertProfileId { get; set; }

    /// <summary>
    /// Navigation property to the associated certificate profile.
    /// </summary>
    [ForeignKey("CertProfileId")]
    public virtual CertProfileEntity CertProfile { get; set; } = default!;

    /// <summary>
    /// The signing profile defining algorithm and validity period for issued certificates.
    /// </summary>
    [Required]
    public Guid SigningProfileId { get; set; }

    /// <summary>
    /// Navigation property to the associated signing profile.
    /// </summary>
    [ForeignKey("SigningProfileId")]
    public virtual SigningProfileEntity SigningProfile { get; set; } = default!;

    /// <summary>
    /// Whether this template is active and available for enrollment requests.
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// The OID under which this template is offered to Windows clients through the MSAE policy
    /// service (MS-XCEP), and by which a client's CSR names it (szOID_CERTIFICATE_TEMPLATE).
    /// Null means the template is not offered to Windows clients. Generated from the template id
    /// under the UUID arc (2.25.x) unless an operator supplies one, for example to keep the OID
    /// of a template migrated from Active Directory Certificate Services.
    /// </summary>
    [MaxLength(64)]
    public string? MsaeTemplateOid { get; set; }

    /// <summary>
    /// Major version reported to Windows clients. A client re-enrolls when the major version of a
    /// template it holds a certificate for increases; bump it when the template's meaning changes.
    /// </summary>
    public int MsaeMajorVersion { get; set; } = 100;

    /// <summary>Minor version reported to Windows clients; informational to them.</summary>
    public int MsaeMinorVersion { get; set; } = 0;

    /// <summary>
    /// True for a template a computer enrolls for (the Windows "machine" flag), false for a user
    /// template. Decides which autoenrollment engine on the client picks it up.
    /// </summary>
    public bool MsaeMachineType { get; set; } = true;

    /// <summary>
    /// Timestamp when this template was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
