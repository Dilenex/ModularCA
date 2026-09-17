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

    /// <summary>The key belongs to a different tenant than the operation is for.</summary>
    TenantMismatch,

    /// <summary>The context is missing something the policy needs, such as the CA an operation is for.</summary>
    ContextRequired,

    /// <summary>The signer has not unlocked its keystore.</summary>
    SignerLocked,

    /// <summary>The caller is not permitted to ask for this operation at all.</summary>
    CallerNotPermitted,

    /// <summary>
    /// Policy would allow it, but the key's backend or state cannot perform the operation: a
    /// PKCS#11 key cannot decrypt, a committed key cannot be retired, an import format is unknown.
    /// </summary>
    OperationUnsupported,

    /// <summary>
    /// The certificate the operation names is missing, or its public key is not the key's, so
    /// the key cannot be committed to or imported for it.
    /// </summary>
    CertificateMismatch,

    /// <summary>
    /// The material offered did not verify: a keystore file whose signature is not the pinned
    /// signer's, or whose pin the signer could not authenticate. Nothing was written.
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
    /// not approved, or one that names a different tenant or CA than the operation.
    /// </summary>
    CeremonyNotApproved,
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
