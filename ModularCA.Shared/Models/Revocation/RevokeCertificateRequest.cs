using System.ComponentModel.DataAnnotations;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Models.Revocation
{
    /// <summary>
    /// Revocation requests now carry a strongly-typed
    /// <see cref="RevocationReason"/> enum rather than a free-text string. Unknown values are
    /// rejected at model binding with HTTP 400 thanks to <see cref="EnumDataTypeAttribute"/>,
    /// closing the audit-fidelity and CRL-reason-smuggling gap. Enum
    /// strings ("Superseded") are accepted because <c>StartModularCA.cs</c> registers a global
    /// <c>JsonStringEnumConverter</c> on <c>AddControllers().AddJsonOptions()</c>.
    /// </summary>
    public class RevokeCertificateRequestByCertId
    {
        /// <summary>
        /// Legacy body copy of the certificate id. The <c>{certId}</c> route segment is
        /// authoritative — it is what the CA-scoped authorization policy is evaluated against —
        /// and a value here that disagrees with it is rejected with 400 rather than honoured.
        /// Kept because existing clients send both, and dropping it would turn a redundant field
        /// into a binding error.
        /// </summary>
        public Guid CertificateId { get; set; }

        [Required]
        [EnumDataType(typeof(RevocationReason))]
        public RevocationReason Reason { get; set; } = RevocationReason.Unspecified;

        /// <summary>
        /// Optional RFC 5280 §5.3.2 invalidity date (the actual time when
        /// compromise is believed to have occurred). When supplied it is written to
        /// <c>CertificateEntity.InvalidityDate</c> and emitted as a CRL entry extension.
        /// </summary>
        public DateTime? InvalidityDate { get; set; }
    }

    public class RevokeCertificateRequestByCertSerial
    {
        [Required, MaxLength(500)]
        public string SerialNumber { get; set; } = string.Empty;

        [Required]
        [EnumDataType(typeof(RevocationReason))]
        public RevocationReason Reason { get; set; } = RevocationReason.Unspecified;

        /// <summary>
        /// Optional RFC 5280 §5.3.2 invalidity date.
        /// </summary>
        public DateTime? InvalidityDate { get; set; }
    }

    /// <summary>
    /// Bulk revocation of several leaf certificates by serial with one shared reason, authorized by a
    /// single step-up token. CA certificates are skipped server-side (they use the RevokeCa op and may
    /// be ceremony-gated) and must be revoked individually.
    /// </summary>
    public class BulkRevokeRequest
    {
        [Required]
        public List<string> SerialNumbers { get; set; } = new();

        [Required]
        [EnumDataType(typeof(RevocationReason))]
        public RevocationReason Reason { get; set; } = RevocationReason.Unspecified;

        /// <summary>Optional RFC 5280 §5.3.2 invalidity date applied to every certificate in the batch.</summary>
        public DateTime? InvalidityDate { get; set; }
    }

    public class HoldCertificateRequestByCertId
    {
        /// <summary>
        /// Legacy body copy of the certificate id. The <c>{certId}</c> route segment is
        /// authoritative — it is what the CA-scoped authorization policy is evaluated against —
        /// and a value here that disagrees with it is rejected with 400 rather than honoured.
        /// Kept because existing clients send both, and dropping it would turn a redundant field
        /// into a binding error.
        /// </summary>
        public Guid CertificateId { get; set; }
    }

    public class HoldCertificateRequestByCertSerial
    {
        [Required, MaxLength(500)]
        public string SerialNumber { get; set; } = string.Empty;
    }
}
