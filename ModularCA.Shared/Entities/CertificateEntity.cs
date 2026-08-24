using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("Certificates")]
public class CertificateEntity
{
    [Key]
    public Guid CertificateId { get; set; }

    [Required]
    [MaxLength(64)]
    public string SerialNumber { get; set; } = string.Empty;

    public string Pem { get; set; } = string.Empty;


    [Required]
    [MaxLength(255)]
    public string SubjectDN { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    public string SubjectAlternativeNamesJson { get; set; } = string.Empty;

    public string KeyUsagesJson { get; set; } = string.Empty;

    public string ExtendedKeyUsagesJson { get; set; } = string.Empty;

    public byte[]? EncryptedPrivateKey { get; set; }

    /// <summary>Serial number of the certificate whose public key was used to encrypt EncryptedPrivateKey.</summary>
    [MaxLength(255)]
    public string? EncryptionCertSerialNumber { get; set; }

    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }

    public string? Thumbprints { get; set; } = string.Empty;

    public bool IsCA { get; set; } = false;

    public bool IsReissued { get; set; } = false;
    public bool Revoked { get; set; } = false;

    /// <summary>
    /// Revocation reason stored as the <see cref="ModularCA.Shared.Enums.RevocationReason"/>
    /// enum name (string). Null when the certificate is not revoked. Arbitrary free-text values are
    /// rejected at API entry so CRL/OCSP consumers get the exact RFC 5280 §5.3.1 reason code.
    /// </summary>
    public string? RevocationReason { get; set; }
    public DateTime? RevocationDate { get; set; }

    /// <summary>
    /// RFC 5280 §5.3.2 invalidity date. Represents the time when compromise
    /// is believed to have actually occurred; may precede <see cref="RevocationDate"/>. Surfaced
    /// as a CRL entry extension when set so long-lived signature validators can distinguish pre-
    /// and post-compromise signatures.
    /// </summary>
    public DateTime? InvalidityDate { get; set; }

    /// <summary>
    /// FK to the CA certificate that issued this certificate. Preferred over the
    /// free-text <see cref="Issuer"/> DN for revocation lookup so two CAs that share a SubjectDN
    /// (renewal, cross-certification) can't have their revoked certs lumped together on the CRL.
    /// Nullable because self-signed CAs and legacy rows don't have a value.
    /// </summary>
    public Guid? IssuerCertificateId { get; set; }

    public byte[]? RawCertificate { get; set; }

    /// <summary>
    /// JSON array of Signed Certificate Timestamps (SCTs) from CT log submissions.
    /// </summary>
    public string? SctJson { get; set; }

    public Guid? SigningProfileId { get; set; }
    public SigningProfileEntity? SigningProfile { get; set; }

    public Guid? CertProfileId { get; set; }
    public CertProfileEntity? CertProfile { get; set; }

    public byte[]? AesKeyEncryptionIv { get; set; }

    public byte[]? EncryptedAesForPrivateKey { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public virtual ICollection<CertificateAccessListEntity> AccessList { get; set; } = new List<CertificateAccessListEntity>();

    /// <summary>
    /// Key-value tags attached to this certificate for dependency tracking and service mapping.
    /// </summary>
    public virtual ICollection<CertificateTagEntity> Tags { get; set; } = new List<CertificateTagEntity>();

    public virtual CertificateAuthorityEntity? CertificateAuthority { get; set; }

}

/// <summary>Predicates over <see cref="CertificateEntity"/> that must not drift between callers.</summary>
public static class CertificateEntityExtensions
{
    /// <summary>
    /// True when this certificate has a stored private key that can be unwrapped and exported
    /// as PKCS#12. All three wrapping components must be present; a partial set is unusable.
    /// </summary>
    /// <remarks>
    /// This is the single definition of "PFX export will work". The admin UI's Export PFX button
    /// and <c>CertificateExportService.ExportPfxAsync</c> both consult it, so the button cannot
    /// offer an export the service will refuse — or, as happened, be hidden for a certificate
    /// that could in fact be exported.
    /// </remarks>
    public static bool HasExportablePrivateKey(this CertificateEntity entity) =>
        entity.EncryptedPrivateKey != null
        && entity.AesKeyEncryptionIv != null
        && entity.EncryptedAesForPrivateKey != null;
}
