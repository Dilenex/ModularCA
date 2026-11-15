using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One certificate a CA has had (<c>docs/architecture/ca-certificate-renewal.md</c>). A CA has
/// one current certificate, the one <see cref="CertificateAuthorityEntity.CertificateId"/> names,
/// and over time several: each renewal adds one and supersedes the one before, which stays
/// valid, stays served at its own serial and is not revoked. A row says, without guessing from
/// names or keys, which CA a certificate belongs to, over which key it was issued, and how and
/// when it became the CA's.
/// <para>
/// Rows are written from the first renewal on: a CA that was never renewed has none, and its
/// one certificate is the one its row names. <see cref="KeyId"/> is there so that a CA can
/// later hold certificates over more than one key.
/// </para>
/// </summary>
[Table("CaCertificates")]
public class CaCertificateEntity
{
    /// <summary>The CA's first certificate, as it was created or as it stood when it was first renewed.</summary>
    public const string OriginInitial = "Initial";

    /// <summary>A certificate made by renewing the CA's certificate over the same key.</summary>
    public const string OriginRenewal = "Renewal";

    /// <summary>The row id (UUID version 7).</summary>
    [Key]
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>The CA the certificate belongs to.</summary>
    public Guid CertificateAuthorityId { get; set; }

    /// <summary>The certificate row. A certificate belongs to one CA.</summary>
    public Guid CertificateId { get; set; }

    /// <summary>The certificate row of <see cref="CertificateId"/>.</summary>
    [ForeignKey(nameof(CertificateId))]
    public CertificateEntity? Certificate { get; set; }

    /// <summary>SHA-256 of the certificate's public key (SubjectPublicKeyInfo, DER), in lower-case hex: the journal's <c>caKey</c>.</summary>
    [Required]
    [MaxLength(64)]
    public string KeyId { get; set; } = string.Empty;

    /// <summary>How the certificate became the CA's: <see cref="OriginInitial"/> or <see cref="OriginRenewal"/>.</summary>
    [Required]
    [MaxLength(20)]
    public string Origin { get; set; } = OriginInitial;

    /// <summary>When the certificate became the CA's current certificate.</summary>
    public DateTime ActivatedAt { get; set; }

    /// <summary>When another certificate took its place as the current one; null while it is current.</summary>
    public DateTime? SupersededAt { get; set; }

    /// <summary>The key ceremony that licensed it, when one did.</summary>
    public Guid? CeremonyId { get; set; }

    /// <summary>Who made it the CA's certificate, when known.</summary>
    [MaxLength(255)]
    public string? Actor { get; set; }
}
