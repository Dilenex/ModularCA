using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("CertificateRequests")]
public class CertRequestEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public string CSR { get; set; } = string.Empty; // PEM-encoded string or raw base64

    [Required]
    [MaxLength(1024)]
    public string Subject { get; set; } = string.Empty; // Extracted from CSR

    public string? SubjectAlternativeNames { get; set; } // Extracted from CSR

    [Required]
    public DateTime SubmittedAt { get; set; } = DateTime.UtcNow;

    [Required]
    [MaxLength(20)]
    // Canonical lifecycle states written across the codebase. One of:
    // "Pending" | "Approved" | "Rejected" | "Cancelled" | "Issued" | "Failed"
    public string Status { get; set; } = "Pending";

    public string KeyAlgorithm { get; set; } = string.Empty; // e.g., RSA, ECDSA

    public string KeySize { get; set; } = "2048"; // e.g., 2048, 4096

    public string SignatureAlgorithm { get; set; } = string.Empty; // e.g., SHA256WITHRSA

    public byte[]? EncryptedPrivateKey { get; set; }
    public byte[]? AesKeyEncryptionIv { get; set; }

    public byte[]? EncryptedAesForPrivateKey { get; set; }

    public string? EncryptionCertSerialNumber { get; set; }

    public Guid? CertProfileId { get; set; }

    [ForeignKey("CertProfileId")]

    public CertProfileEntity CertProfile { get; set; } = default!;

    public Guid? SigningProfileId { get; set; }

    [ForeignKey("SigningProfileId")]

    public SigningProfileEntity? SigningProfile { get; set; }

    /// <summary>
    /// Reason the CSR was rejected. Only set when Status is "Rejected".
    /// </summary>
    [MaxLength(500)]
    public string? RejectionReason { get; set; }

    public Guid? IssuedCertificateId { get; set; }

    [ForeignKey(nameof(IssuedCertificateId))]
    public CertificateEntity? IssuedCertificate { get; set; }

    public Guid? RequestorUserId { get; set; } // User ID of the requestor
    [ForeignKey(nameof(RequestorUserId))]

    public UserEntity? RequestorUser { get; set; } // Navigation property to UserEntity

    /// <summary>
    /// Current number of approvals received. Compared against the request profile's RequiredApprovalCount.
    /// </summary>
    public int ApprovalCount { get; set; } = 0;

    /// <summary>
    /// Navigation property to approval records.
    /// </summary>
    public virtual ICollection<CsrApprovalEntity> Approvals { get; set; } = new List<CsrApprovalEntity>();

    /// <summary>
    /// ID of the certificate being renewed, if this is a renewal request.
    /// </summary>
    public Guid? RenewalOfCertificateId { get; set; }

    /// <summary>
    /// When true, this CSR was created by the system for an infrastructure certificate
    /// (TSA signer, OCSP responder). Infrastructure CSRs bypass quota enforcement and
    /// are auto-approved at creation time.
    /// </summary>
    public bool IsInfrastructureCert { get; set; } = false;

    /// <summary>
    /// JSON dictionary of subject DN field overrides (keyed by field name: CN, O, OU, etc.).
    /// When set, these values replace the CSR's original subject fields at issuance time.
    /// </summary>
    public string? SubjectOverrides { get; set; }

    /// <summary>
    /// JSON array of SAN overrides. When set, these replace the CSR's original SANs at issuance time.
    /// </summary>
    public string? SanOverrides { get; set; }

    /// <summary>
    /// JSON array of <see cref="Models.RequestedExtension"/>: extensions the enrolling protocol asks
    /// to have stamped on the certificate beyond what the profiles produce, such as the Windows
    /// Certificate Template Information extension. Applied whenever the request is issued, so an
    /// approval that happens later still honours it. Null when there are none.
    /// </summary>
    public string? AdditionalExtensions { get; set; }

    /// <summary>Optimistic concurrency token (MySQL TIMESTAMP(6)).</summary>
    [Timestamp]
    public byte[]? RowVersion { get; set; }

    /// <summary>
    /// Validity window requested when the CSR was submitted, or null to let the profile decide.
    /// </summary>
    /// <remarks>
    /// The Request Certificate page lets an operator pick Not Before / Not After, but neither
    /// submission path had anywhere to put them: the request creates a CSR, and issuance happens
    /// later from the Requests page. The values were accepted by the DTO and dropped on the
    /// floor, so the certificate came out with the profile default and nothing said otherwise.
    /// Issuance now falls back to these when the issuer does not specify a window explicitly.
    /// </remarks>
    public DateTime? RequestedNotBefore { get; set; }

    /// <inheritdoc cref="RequestedNotBefore"/>
    public DateTime? RequestedNotAfter { get; set; }
}
