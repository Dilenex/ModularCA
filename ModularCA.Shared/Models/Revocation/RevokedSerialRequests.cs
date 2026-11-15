using System.ComponentModel.DataAnnotations;
using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Models.Revocation
{
    /// <summary>
    /// Records a serial as revoked for a CA with no certificate row behind it (a tombstone): for
    /// a certificate that is known only from outside, for example one issued in time a rollback
    /// took away. The CA comes from the route.
    /// </summary>
    public class RecordRevokedSerialRequest
    {
        /// <summary>The serial in hex, as the certificate shows it. Separators and leading zeros are ignored.</summary>
        [Required, MaxLength(200)]
        public string SerialNumber { get; set; } = string.Empty;

        /// <summary>The RFC 5280 reason. <c>CertificateHold</c> is refused: a tombstone cannot be released.</summary>
        [Required]
        [EnumDataType(typeof(RevocationReason))]
        public RevocationReason Reason { get; set; } = RevocationReason.Unspecified;

        /// <summary>Optional RFC 5280 §5.3.2 invalidity date.</summary>
        public DateTime? InvalidityDate { get; set; }

        /// <summary>Why the serial is revoked without its certificate. Kept with the entry and in the audit trail.</summary>
        [Required, MaxLength(1000)]
        public string Note { get; set; } = string.Empty;
    }

    /// <summary>
    /// Adopts a certificate supplied from outside as a row of the CA in the route, after its
    /// signature is verified under that CA's key. The row has no profile and no known requester.
    /// </summary>
    public class AdoptCertificateRequest
    {
        /// <summary>The certificate, as PEM or as base64 of its DER encoding.</summary>
        [Required, MaxLength(65536)]
        public string Certificate { get; set; } = string.Empty;

        /// <summary>Where the certificate came from and why it is adopted. Kept on the row and in the audit trail.</summary>
        [Required, MaxLength(1000)]
        public string Note { get; set; } = string.Empty;

        /// <summary>
        /// Revoke the certificate in the same step, with this reason. Null adopts it as good. A
        /// tombstone already recorded for its serial revokes it whatever this says.
        /// </summary>
        [EnumDataType(typeof(RevocationReason))]
        public RevocationReason? RevokeReason { get; set; }

        /// <summary>Optional RFC 5280 §5.3.2 invalidity date of that revocation.</summary>
        public DateTime? InvalidityDate { get; set; }
    }
}
