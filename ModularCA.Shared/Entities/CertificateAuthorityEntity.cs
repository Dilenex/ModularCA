using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities
{
    /// <summary>
    /// Represents a certificate authority in the PKI hierarchy. May be scoped to a
    /// <see cref="SpaceEntity"/> for delegated administration, or have no space as an
    /// instance CA.
    /// </summary>
    public class CertificateAuthorityEntity
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// The X.509 certificate associated with this CA. Null for SSH-only CAs
        /// which use SSH key pairs instead of X.509 certificates.
        /// </summary>
        public Guid? CertificateId { get; set; }

        [ForeignKey("CertificateId")]
        public virtual CertificateEntity? Certificate { get; set; }

        [Required]
        [MaxLength(255)]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// URL-safe slug used in per-CA route segments (e.g. "myca" → /api/v1/est/myca/simpleenroll).
        /// Must be unique and contain only lowercase alphanumeric characters and hyphens.
        /// </summary>
        [MaxLength(255)]
        public string? Label { get; set; }

        /// <summary>
        /// When true, this CA is used as the default when no explicit label is specified in a request.
        /// Only one CA should be marked as default.
        /// </summary>
        public bool IsDefault { get; set; } = false;

        /// <summary>
        /// CA type: Root, Intermediate, or Issuing.
        /// </summary>
        [MaxLength(20)]
        public string Type { get; set; } = "Root";

        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// Parent CA in the hierarchy. Null for root CAs.
        /// Used to track the CA chain: Root → Intermediate → Issuing.
        /// </summary>
        public Guid? ParentCaId { get; set; }

        [ForeignKey("ParentCaId")]
        public virtual CertificateAuthorityEntity? ParentCa { get; set; }

        /// <summary>
        /// Child CAs issued under this CA.
        /// </summary>
        public virtual ICollection<CertificateAuthorityEntity> ChildCAs { get; set; } = new List<CertificateAuthorityEntity>();

        /// <summary>
        /// Optional delegated OCSP responder certificate. When set, OCSP responses
        /// are signed by this cert instead of the CA key directly (RFC 6960 §4.2.2.2).
        /// The cert must have id-kp-OCSPSigning EKU.
        /// </summary>
        public Guid? OcspResponderCertificateId { get; set; }

        /// <summary>
        /// Per-CA override for the <c>nextUpdate</c> lifetime
        /// of <c>good</c> OCSP responses. Minutes. When <c>null</c>, the
        /// global default in <c>SecurityPolicyEntity.DefaultGoodResponseTtlMinutes</c>
        /// applies. Lower values make clients recheck more often (fresher
        /// revocation status) at the cost of HSM/signer load.
        /// </summary>
        public int? OcspResponseTtlGoodMinutes { get; set; }

        /// <summary>
        /// Per-CA override for the <c>nextUpdate</c> lifetime
        /// of <c>revoked</c> OCSP responses. Minutes. When <c>null</c>, the
        /// global default in <c>SecurityPolicyEntity.DefaultRevokedResponseTtlMinutes</c>
        /// applies. Typically shorter than the good TTL so a newly-revoked
        /// cert's status propagates faster.
        /// </summary>
        public int? OcspResponseTtlRevokedMinutes { get; set; }

        /// <summary>
        /// Dedicated TSA signer certificate. RFC 3161 §2.3 requires the signer cert
        /// to have id-kp-timeStamping (1.3.6.1.5.5.7.3.8) EKU marked as critical.
        /// Issued during bootstrap, signed by this CA.
        /// </summary>
        public Guid? TsaCertificateId { get; set; }

        /// <summary>
        /// Dedicated CMP message-signing certificate. When set, signature-protected CMP responses
        /// (RFC 4210 section 5.1.3.3) are signed with this certificate's key instead of the CA key,
        /// and the certificate is sent in <c>extraCerts</c> so the client can chain it.
        /// </summary>
        /// <remarks>
        /// Without one, responses are signed with the CA certificate itself, whose key usage is
        /// <c>keyCertSign, cRLSign</c> and nothing else. OpenSSL refuses a CMP message signer that
        /// lacks <c>digitalSignature</c> ("no suitable sender cert"), so every signature-protected
        /// exchange failed at the client while PBMAC exchanges, whose responses are MAC-protected,
        /// worked. Found by running <c>openssl cmp</c> against a live CA. Issued on demand from the
        /// CA detail page, beside the OCSP responder and TSA signer.
        /// </remarks>
        public Guid? CmpSigningCertificateId { get; set; }

        /// <summary>
        /// The certificate profile this CA's timestamp signer is issued under, or null for the
        /// seeded default (<see cref="ModularCA.Shared.Utils.SystemCertProfiles.Tsa"/>). A profile
        /// a CA names here cannot be deleted.
        /// </summary>
        public Guid? TsaCertProfileId { get; set; }

        /// <summary>
        /// The certificate profile this CA's OCSP responder is issued under, or null for the
        /// seeded default (<see cref="ModularCA.Shared.Utils.SystemCertProfiles.OcspResponder"/>).
        /// </summary>
        public Guid? OcspResponderCertProfileId { get; set; }

        /// <summary>
        /// The certificate profile this CA's CMP signer is issued under, or null for the seeded
        /// default (<see cref="ModularCA.Shared.Utils.SystemCertProfiles.CmpSigner"/>).
        /// </summary>
        public Guid? CmpSignerCertProfileId { get; set; }

        /// <summary>
        /// Key storage backend: "Software" (encrypted keystore file) or "Pkcs11" (HSM).
        /// </summary>
        [MaxLength(20)]
        public string KeyStorageType { get; set; } = "Software";

        /// <summary>
        /// PKCS#11 key label on the HSM. Only used when KeyStorageType is "Pkcs11".
        /// </summary>
        [MaxLength(255)]
        public string? HsmKeyLabel { get; set; }

        /// <summary>
        /// Whether this CA is an SSH certificate authority (as opposed to X.509).
        /// SSH CAs participate in the same group-role authorization model as X.509 CAs.
        /// </summary>
        public bool IsSshCa { get; set; } = false;

        /// <summary>
        /// The space this CA belongs to, or null for an instance CA such as the system
        /// signing CA or an SSH CA.
        /// </summary>
        public Guid? SpaceId { get; set; }

        /// <summary>Navigation property to the owning space; null for an instance CA.</summary>
        [ForeignKey(nameof(SpaceId))]
        public virtual SpaceEntity? Space { get; set; }

        /// <summary>
        /// Optional per-CA override for the controlled-user ceremony ("user") quorum — how many
        /// approvals a promote/demote/delete of a CA-scoped controlled user requires. Null = inherit
        /// the owning space's value. Capped by the space (a CA may require fewer approvals than its
        /// space, never more). Distinct from the CA admin group's <i>key</i>-ceremony quorum.
        /// </summary>
        public int? UserCeremonyRequiredApprovals { get; set; }

        /// <summary>
        /// Soft-delete flag. When true, the row is hidden by the soft-delete query filter. The
        /// unique indexes on Label and Name cover deleted rows too, so a deleted CA's label is
        /// never reused: it is baked into the URLs of the certificates it issued.
        /// </summary>
        public bool IsDeleted { get; set; } = false;

        /// <summary>Timestamp when <see cref="IsDeleted"/> was flipped to true.</summary>
        public DateTime? DeletedAt { get; set; }
    }
}
