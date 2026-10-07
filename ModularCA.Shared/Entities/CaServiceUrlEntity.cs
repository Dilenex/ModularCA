using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Per-CA service URL configuration. Holds the public base URL only — the certificate builder
/// auto-generates CDP, OCSP, and AIA endpoints from the base URL plus the standard short-URL
/// paths (<c>/crl/{label}</c>, <c>/ocsp</c>, <c>/ca/{label}</c>). Per-field URL overrides are
/// intentionally not supported: a single base URL is enough for multi-space deployments where
/// different CAs need different public hostnames, and removing the override path keeps the data
/// model and admin UI simple.
/// </summary>
[Table("CaServiceUrls")]
public class CaServiceUrlEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid CaCertificateId { get; set; }

    [ForeignKey("CaCertificateId")]
    public CertificateEntity CaCertificate { get; set; } = default!;

    /// <summary>
    /// Public base URL for this CA (e.g. <c>http://path2.ca.example.com</c>). At cert-build time
    /// the certificate builder appends the standard short-URL paths to produce the CDP, OCSP, and
    /// AIA endpoints embedded in every issued certificate. Trailing slashes are stripped on save.
    /// May be null only on legacy rows; the admin API and UI now treat it as required.
    /// </summary>
    [MaxLength(500)]
    public string? PublicBaseUrl { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
