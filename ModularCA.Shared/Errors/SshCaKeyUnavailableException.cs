using ModularCA.Shared.Signing;

namespace ModularCA.Shared.Errors;

/// <summary>
/// Raised when an SSH CA key cannot be used now, through no fault of the request: the signer is
/// locked, the signer cannot serve the key (its row or CA was disabled meanwhile, it sits on a
/// backend that signs no SSH certificates, or the signer predates the SSH keystore), or the key
/// is still a file on the node, awaiting its import into the signer.
/// </summary>
/// <remarks>
/// The API answers it with 503 and the message, which is written for the operator. It is not a
/// <see cref="RequestValidationException"/>: that family tells a caller their request was wrong,
/// and here the same request succeeds once the signer is unlocked, upgraded, or holds the key.
/// </remarks>
public sealed class SshCaKeyUnavailableException : Exception
{
    /// <summary>What a key that has not been imported into the signer is refused with.</summary>
    public const string AwaitingImport = "SSH CA key awaiting import into the signer";

    /// <summary>What a signer that predates the SSH keystore is reported as.</summary>
    public const string SignerPredatesSshKeystore = "The signer predates the SSH keystore and must be upgraded first";

    /// <summary>
    /// The signer's reason, when the signer refused; null when the node refused before asking it
    /// (a key awaiting import, or a signer found to predate the SSH keystore).
    /// </summary>
    public SigningRefusalReason? SignerReason { get; }

    /// <summary>
    /// Whether sending the same request again shortly can succeed without anyone doing
    /// anything else: true for a locked signer, which an operator or the unlock at start is
    /// about to open. A key awaiting import, a disabled row, a key on another backend and a
    /// signer that has to be upgraded all stay as they are until someone acts.
    /// </summary>
    public bool RetryMayHelp => SignerReason == SigningRefusalReason.SignerLocked;

    /// <summary>Creates the refusal with the sentence the caller is shown.</summary>
    /// <param name="message">Why the key cannot be used now.</param>
    /// <param name="signerReason">The signer's reason, when the signer refused.</param>
    /// <param name="innerException">The signer's refusal, when there was one.</param>
    public SshCaKeyUnavailableException(string message, SigningRefusalReason? signerReason = null, Exception? innerException = null)
        : base(message, innerException)
    {
        SignerReason = signerReason;
    }
}
