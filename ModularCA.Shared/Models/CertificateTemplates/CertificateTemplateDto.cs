namespace ModularCA.Shared.Models.CertificateTemplates;

/// <summary>
/// Data transfer object representing a certificate template with resolved names
/// for the associated CA, request profile, cert profile, and signing profile.
/// </summary>
public class CertificateTemplateDto
{
    /// <summary>
    /// Unique identifier for the certificate template.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Human-readable template name used by protocol clients.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Optional description of the template's purpose.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// The ID of the Certificate Authority associated with this template.
    /// </summary>
    public Guid CaId { get; set; }

    /// <summary>
    /// The display name of the associated Certificate Authority.
    /// </summary>
    public string? CaName { get; set; }

    /// <summary>
    /// The optional request profile ID controlling subject/SAN validation.
    /// </summary>
    public Guid? RequestProfileId { get; set; }

    /// <summary>
    /// The display name of the associated request profile, if any.
    /// </summary>
    public string? RequestProfileName { get; set; }

    /// <summary>
    /// The certificate profile ID defining key usage and extensions.
    /// </summary>
    public Guid CertProfileId { get; set; }

    /// <summary>
    /// The display name of the associated certificate profile.
    /// </summary>
    public string? CertProfileName { get; set; }

    /// <summary>
    /// The signing profile ID defining algorithm and validity.
    /// </summary>
    public Guid SigningProfileId { get; set; }

    /// <summary>
    /// The display name of the associated signing profile.
    /// </summary>
    public string? SigningProfileName { get; set; }

    /// <summary>
    /// Whether this template is active and available for enrollment.
    /// </summary>
    public bool IsEnabled { get; set; }

    /// <summary>True when the template is offered to Windows clients through the MSAE policy service.</summary>
    public bool OfferedToWindows { get; set; }

    /// <summary>The OID Windows clients know the template by, or null when not offered.</summary>
    public string? MsaeTemplateOid { get; set; }

    public int MsaeMajorVersion { get; set; }

    public int MsaeMinorVersion { get; set; }

    /// <summary>True for a computer template, false for a user template.</summary>
    public bool MsaeMachineType { get; set; }
}
