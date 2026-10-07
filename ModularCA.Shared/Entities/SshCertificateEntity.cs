using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("SshCertificates")]
public class SshCertificateEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid SshCaKeyId { get; set; }

    [ForeignKey("SshCaKeyId")]
    public virtual SshCaKeyEntity SshCaKey { get; set; } = default!;

    [Required]
    [MaxLength(10)]
    public string CertificateType { get; set; } = "user";

    [MaxLength(255)]
    public string KeyId { get; set; } = string.Empty;

    public long SerialNumber { get; set; }

    public string Principals { get; set; } = "[]";

    public DateTime ValidAfter { get; set; }
    public DateTime ValidBefore { get; set; }

    public string PublicKey { get; set; } = string.Empty;
    public string SignedCertificate { get; set; } = string.Empty;

    public string? Extensions { get; set; }

    public bool IsRevoked { get; set; } = false;

    /// <summary>Who asked for the certificate.</summary>
    public Guid? IssuedByUserId { get; set; }

    /// <summary>
    /// The user the certificate is for, as distinct from <see cref="IssuedByUserId"/>, who asked.
    /// Null for a host certificate, for a service identity, once that user is deleted, and on a
    /// row issued before login names whose key id was not its issuer's username.
    /// </summary>
    public Guid? SubjectUserId { get; set; }

    /// <summary>
    /// Why the subject held each login name when the certificate was issued: a JSON array with,
    /// per name, its source (<c>own</c>, <c>user</c>, <c>group</c> or <c>typed</c>) and, for a
    /// grant, the grant, the group and who granted it. Null on a host certificate and on a row
    /// issued before login names.
    /// </summary>
    public string? LoginNameGrounds { get; set; }

    [MaxLength(45)]
    public string? SourceIp { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
