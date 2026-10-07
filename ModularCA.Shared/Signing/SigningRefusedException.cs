namespace ModularCA.Shared.Signing;

/// <summary>
/// Why the signer refused an operation. Every refusal carries one of these so a caller and the
/// audit can tell a policy decision from a key that is simply not there.
/// </summary>
public enum SigningRefusalReason
{
    /// <summary>The signer holds no key for the referenced certificate.</summary>
    UnknownKey,

    /// <summary>The key exists but nothing in the database says what kind of key it is, so no policy row applies.</summary>
    UnknownKeyKind,

    /// <summary>This kind of key never serves this purpose.</summary>
    PurposeNotPermitted,

    /// <summary>The key belongs to a different CA than the operation is for.</summary>
    CaMismatch,

    /// <summary>The key belongs to a different space than the operation is for.</summary>
    TenantMismatch,

    /// <summary>The context is missing something the policy needs, such as the CA an operation is for.</summary>
    ContextRequired,

    /// <summary>The signer has not unlocked its keystore.</summary>
    SignerLocked,

    /// <summary>The caller is not permitted to ask for this operation at all.</summary>
    CallerNotPermitted,

    /// <summary>
    /// Policy would allow it, but the key's backend or state cannot perform the operation: a
    /// PKCS#11 key cannot decrypt, a committed key cannot be retired, an import format is unknown,
    /// an SSH CA key's row or CA is disabled, or the signer predates the call altogether.
    /// </summary>
    OperationUnsupported,

    /// <summary>
    /// The certificate the operation names is missing, or its public key is not the key's, so
    /// the key cannot be committed to or imported for it.
    /// </summary>
    CertificateMismatch,

    /// <summary>
    /// The material offered did not verify: a keystore file whose signature is not the pinned
    /// signer's, or whose pin the signer could not authenticate, or a wrapped secret that does
    /// not authenticate under the key its header names. Nothing was written and nothing was
    /// returned. Also the reason when the signature an SSH CA key made over a certificate does
    /// not verify under that key's public half: the certificate is not handed out.
    /// </summary>
    IntegrityFailure,

    /// <summary>
    /// The signer could not write its audit row, and it does not act unrecorded: the operation
    /// was refused before any result left it. Raised only by a signer that runs fail-closed,
    /// which the signer role does; in process the node's own audit still sees the operation.
    /// </summary>
    AuditUnavailable,

    /// <summary>
    /// The signer could not be reached at all: the channel to the signer role is down, the
    /// handshake was refused, or the call timed out. No decision was taken and nothing was
    /// audited at the signer. The node answers service-unavailable until it reconnects.
    /// </summary>
    SignerUnavailable,

    /// <summary>
    /// The context named a ceremony the signer could not verify: no such ceremony, one that is
    /// not approved, or one that names a different space or CA than the operation.
    /// </summary>
    CeremonyNotApproved,

    /// <summary>
    /// The context named no ceremony, and the space the operation is for requires one: the
    /// space's <c>RequireKeyCeremony</c> is set, or the space is not known to the signer at
    /// all, so no waiver of the requirement can be verified. Key generation, commit and import
    /// for such a space happen only under an approved ceremony the signer can verify.
    /// </summary>
    CeremonyRequired,

    /// <summary>
    /// The bytes offered for signature are not the structure the purpose signs: a certificate
    /// purpose signs a DER v3 TBSCertificate, a CRL purpose a TBSCertList, an OCSP purpose a
    /// ResponseData, and so on. Bytes that do not parse, parse as something else, are not DER,
    /// or carry trailing data are refused before any key is used. For
    /// <see cref="ISigningService.SignSshCertificateAsync"/>, where the signer builds the
    /// structure itself, this is the reason for fields it builds no certificate from: a
    /// certificate type, subject key or validity that does not parse, and any field that breaks
    /// one of the SSH CA key's rules (type, validity, principals, serial, options, subject key).
    /// </summary>
    UntypedData,

    /// <summary>
    /// The structure names a signature algorithm other than the one the request asks the key to
    /// sign with, so the signature would not verify as the structure claims.
    /// </summary>
    AlgorithmMismatch,

    /// <summary>
    /// The structure names an issuer or responder other than the certificate of the key that
    /// would sign it: a TBSCertificate or TBSCertList whose issuer is not the CA's subject, or an
    /// OCSP ResponseData whose responder id is not the signing certificate's.
    /// </summary>
    IssuerMismatch,

    /// <summary>
    /// The structure grants authority the signer has no evidence for: a certificate asserting
    /// <c>cA=TRUE</c> for a key the signer did not generate under a ceremony for a new CA (or
    /// has already certified as one), or an OCSP-signing certificate for a key the signer did
    /// not generate for the signing CA. A ceremony id on the context is not such evidence.
    /// </summary>
    EvidenceRequired,
}

/// <summary>
/// Thrown by <see cref="ISigningService"/> when policy refuses an operation. The refusal is
/// already audited at the signer by the time this is thrown; the caller only has to decide what
/// to tell its own client.
/// </summary>
public sealed class SigningRefusedException : Exception
{
    /// <summary>The reason the signer refused.</summary>
    public SigningRefusalReason Reason { get; }

    /// <summary>Creates a refusal carrying its reason and a message meant for logs.</summary>
    public SigningRefusedException(SigningRefusalReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }
}
