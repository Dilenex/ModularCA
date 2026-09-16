using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One Windows autoenrollment (MSAE, MS-WSTEP) protocol event: an enrollment issued or refused
/// over the CES endpoint.
/// </summary>
/// <remarks>
/// Same shape as <see cref="AuditEstEntity"/> so the audit page can render it with the shared
/// protocol columns, plus the template the client asked for, which is the one MSAE-specific
/// fact an auditor needs when a Windows client got a certificate it did not expect.
/// </remarks>
[Table("AuditMsae")]
public class AuditMsaeEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>"Enroll" for an issued certificate, "EnrollRejected" for a refusal.</summary>
    [Required]
    [MaxLength(20)]
    public string Operation { get; set; } = string.Empty;

    [MaxLength(255)]
    public string? SubjectDN { get; set; }

    [MaxLength(64)]
    public string? CertificateSerial { get; set; }

    [MaxLength(20)]
    public string? KeyAlgorithm { get; set; }

    [MaxLength(20)]
    public string? KeySize { get; set; }

    /// <summary>The certificate template the client named in its CSR, or null.</summary>
    [MaxLength(100)]
    public string? TemplateName { get; set; }

    [MaxLength(50)]
    public string? CaLabel { get; set; }

    [MaxLength(45)]
    public string? SourceIp { get; set; }

    public bool Success { get; set; } = true;

    [MaxLength(500)]
    public string? ErrorMessage { get; set; }

    public Guid? CertificateAuthorityId { get; set; }

    public Guid? TenantId { get; set; }

    /// <summary>The authenticated caller, recorded as <c>user:{username}</c>.</summary>
    [MaxLength(255)]
    public string? CallerPrincipal { get; set; }
}
