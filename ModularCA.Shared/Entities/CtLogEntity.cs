using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("CtLogs")]
public class CtLogEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [MaxLength(500)]
    public string Url { get; set; } = string.Empty;

    /// <summary>
    /// The log's public key, the base64 of its DER SubjectPublicKeyInfo. Every SCT the log returns
    /// is verified against it (<c>CtSctVerifier</c>, RFC 6962 section 3.2), and an SCT that does not
    /// verify is discarded. Empty means no key: the log's SCTs cannot be verified and are discarded.
    /// </summary>
    public string PublicKeyBase64 { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
