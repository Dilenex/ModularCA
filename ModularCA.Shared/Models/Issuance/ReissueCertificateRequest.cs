using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Models.Issuance
{
    /// <summary>
    /// Request body for reissuing a certificate identified by its certificate ID.
    /// </summary>
    public class ReissueCertificateRequestByCertId
    {
        public Guid CertificateId { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }

        /// <summary>
        /// Optional new subject Distinguished Name (overrides the original CSR's subject).
        /// When set, must still validate against the resolved request profile's SubjectDnRules.
        /// Format: comma-separated RDNs, e.g., "CN=api.example.com,O=Example,C=US".
        /// </summary>
        [MaxLength(500)]
        public string? NewSubjectDn { get; set; }

        /// <summary>
        /// Optional new Subject Alternative Name list (overrides the original CSR's SANs).
        /// When set, must still validate against the resolved request profile's SanRules.
        /// Each entry is prefixed with the type: "DNS:host.example.com" or "IP:10.0.0.1".
        /// Null or absent keeps the current SANs; an empty list removes them all, refused with 400
        /// where a certificate without SANs is not valid (a TLS server certificate, or an empty subject).
        /// </summary>
        public List<string>? NewSans { get; set; }
    }

    /// <summary>
    /// Request body for reissuing a certificate identified by its serial number.
    /// </summary>
    public class ReissueCertificateRequestByCertSn
    {
        [Required, MaxLength(500)]
        public string SerialNumber { get; set; } = string.Empty;

        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }

        /// <summary>
        /// Optional new subject Distinguished Name (overrides the original CSR's subject).
        /// When set, must still validate against the resolved request profile's SubjectDnRules.
        /// Format: comma-separated RDNs, e.g., "CN=api.example.com,O=Example,C=US".
        /// </summary>
        [MaxLength(500)]
        public string? NewSubjectDn { get; set; }

        /// <summary>
        /// Optional new Subject Alternative Name list (overrides the original CSR's SANs).
        /// When set, must still validate against the resolved request profile's SanRules.
        /// Each entry is prefixed with the type: "DNS:host.example.com" or "IP:10.0.0.1".
        /// Null or absent keeps the current SANs; an empty list removes them all, refused with 400
        /// where a certificate without SANs is not valid (a TLS server certificate, or an empty subject).
        /// </summary>
        public List<string>? NewSans { get; set; }
    }

    /// <summary>
    /// Request body for reissuing a certificate identified by its CSR ID.
    /// </summary>
    public class ReissueCertificateRequestByCsrId
    {
        public Guid CsrId { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }

        /// <summary>
        /// Optional new subject Distinguished Name (overrides the original CSR's subject).
        /// When set, must still validate against the resolved request profile's SubjectDnRules.
        /// Format: comma-separated RDNs, e.g., "CN=api.example.com,O=Example,C=US".
        /// </summary>
        [MaxLength(500)]
        public string? NewSubjectDn { get; set; }

        /// <summary>
        /// Optional new Subject Alternative Name list (overrides the original CSR's SANs).
        /// When set, must still validate against the resolved request profile's SanRules.
        /// Each entry is prefixed with the type: "DNS:host.example.com" or "IP:10.0.0.1".
        /// Null or absent keeps the current SANs; an empty list removes them all, refused with 400
        /// where a certificate without SANs is not valid (a TLS server certificate, or an empty subject).
        /// </summary>
        public List<string>? NewSans { get; set; }
    }
}
