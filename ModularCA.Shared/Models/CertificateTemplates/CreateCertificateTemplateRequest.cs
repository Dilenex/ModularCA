namespace ModularCA.Shared.Models.CertificateTemplates;

/// <summary>
/// Request model for creating a new certificate template that bundles
/// a CA, signing profile, cert profile, and optional request profile.
/// </summary>
public class CreateCertificateTemplateRequest
{
    /// <summary>
    /// Unique human-readable name for the template (max 100 characters).
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Optional description explaining the purpose of this template.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// The Certificate Authority that will issue certificates using this template.
    /// </summary>
    public Guid CaId { get; set; }

    /// <summary>
    /// Optional request profile controlling subject/SAN validation and approval behavior.
    /// </summary>
    public Guid? RequestProfileId { get; set; }

    /// <summary>
    /// The certificate profile defining key usage, extensions, and certificate content.
    /// </summary>
    public Guid CertProfileId { get; set; }

    /// <summary>
    /// The signing profile defining algorithm and validity period.
    /// </summary>
    public Guid SigningProfileId { get; set; }

    /// <summary>
    /// Whether this template is active and available for enrollment. Defaults to true.
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Offer this template to Windows clients through the MSAE policy service. When true and
    /// <see cref="MsaeTemplateOid"/> is blank, an OID is generated from the template id.
    /// </summary>
    public bool OfferToWindows { get; set; } = false;

    /// <summary>
    /// The OID to offer the template under. Leave blank to have one generated; set it to keep the
    /// OID of a template migrated from Active Directory Certificate Services.
    /// </summary>
    public string? MsaeTemplateOid { get; set; }

    /// <summary>Major version reported to Windows clients; bump to force re-enrollment.</summary>
    public int MsaeMajorVersion { get; set; } = 100;

    public int MsaeMinorVersion { get; set; } = 0;

    /// <summary>True for a computer template, false for a user template.</summary>
    public bool MsaeMachineType { get; set; } = true;
}
