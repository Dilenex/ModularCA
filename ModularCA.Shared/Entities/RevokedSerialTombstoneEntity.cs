using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// A revoked serial number of one CA that has no certificate row behind it: a tombstone
/// (<c>docs/architecture/rollback-continuity.md</c>, section 5). It puts a certificate known only
/// from outside on the CRL, and makes OCSP answer with the recorded date and reason. A serial
/// that has a row in <c>Certificates</c> under the same CA never has one: that certificate is
/// revoked instead, and adopting the certificate later moves the revocation onto its row and
/// removes the tombstone.
/// </summary>
[Table("RevokedSerialTombstones")]
public class RevokedSerialTombstoneEntity
{
    /// <summary>The longest note kept with a tombstone.</summary>
    public const int NoteMaxLength = 1000;

    /// <summary>The row id (UUID version 7).</summary>
    [Key]
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>
    /// The CA certificate whose CRL lists the serial: the CA's current certificate when the
    /// tombstone was recorded. CRL generation and OCSP match it through the same same-key scope
    /// as certificate rows.
    /// </summary>
    public Guid CaCertificateId { get; set; }

    /// <summary>The CA certificate row of <see cref="CaCertificateId"/>.</summary>
    [ForeignKey(nameof(CaCertificateId))]
    public CertificateEntity? CaCertificate { get; set; }

    /// <summary>The CA the tombstone was recorded for; what the console lists it under. Not a foreign key.</summary>
    public Guid CertificateAuthorityId { get; set; }

    /// <summary>The issuer name the serial belongs to: the CA certificate's subject DN.</summary>
    [Required]
    [MaxLength(CertificateEntity.SubjectDnMaxLength)]
    public string IssuerDN { get; set; } = string.Empty;

    /// <summary>The serial, in the form <c>CertificateUtil.FormatSerialNumber</c> gives and <c>Certificates</c> stores.</summary>
    [Required]
    [MaxLength(64)]
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>When the serial was revoked: the moment the tombstone was recorded.</summary>
    public DateTime RevocationDate { get; set; }

    /// <summary>The <see cref="ModularCA.Shared.Enums.RevocationReason"/> name. Never a hold: a tombstone is permanent.</summary>
    [Required]
    [MaxLength(64)]
    public string RevocationReason { get; set; } = string.Empty;

    /// <summary>RFC 5280 §5.3.2 invalidity date, when the administrator gave one.</summary>
    public DateTime? InvalidityDate { get; set; }

    /// <summary>
    /// When the entry leaves the CRL. A tombstone has no <c>notAfter</c>, so this is its date plus
    /// the longest validity the CA's profiles allowed when it was recorded.
    /// </summary>
    public DateTime ListedUntil { get; set; }

    /// <summary>Why the serial was revoked without its certificate, as the administrator wrote it.</summary>
    [Required]
    [MaxLength(NoteMaxLength)]
    public string Note { get; set; } = string.Empty;

    /// <summary>The administrator who recorded it.</summary>
    public Guid? CreatedByUserId { get; set; }

    /// <summary>The administrator's user name when it was recorded.</summary>
    [MaxLength(255)]
    public string CreatedByUsername { get; set; } = string.Empty;

    /// <summary>When the row was written.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
