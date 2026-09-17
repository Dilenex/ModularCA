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
