using ModularCA.Shared.Errors;
using ModularCA.Shared.Signing;

namespace ModularCA.Core.Services;

/// <summary>
/// What a refusal from the signer means to the caller of an SSH operation. This is the whole
/// table: a reason that is not named here is not translated, and reaches the caller as the
/// signer's own refusal, which the API answers as it answers one from an X.509 path.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>
/// <see cref="SigningRefusalReason.SignerLocked"/> and
/// <see cref="SigningRefusalReason.OperationUnsupported"/> (the row or its CA was disabled
/// meanwhile, the key is on a backend that signs no SSH certificates, the row is not yet the
/// signer's, or the signer predates the call): <see cref="SshCaKeyUnavailableException"/>, 503
/// with the signer's reason. The request was fine and can be sent again.
/// </item>
/// <item>
/// <see cref="SigningRefusalReason.UntypedData"/>, when signing (a rule of the certificate was
/// broken: no principals, a validity over the key's maximum, an unknown option, a subject key
/// that cannot be certified): <see cref="InvalidRequestException"/>, 400 with the signer's reason.
/// </item>
/// <item>
/// <see cref="SigningRefusalReason.UnknownKey"/>, when signing (the signer holds no key for the
/// row): <see cref="ConfigurationValidationException"/> with
/// <see cref="ErrorCodes.IssuingCaKeyUnavailable"/>, 400, as X.509 issuance reports a CA whose
/// key the signer does not hold.
/// </item>
/// </list>
/// </remarks>
public static class SshSignerRefusals
{
    /// <summary>
    /// The exception a caller of <c>SignUserKeyAsync</c> or <c>SignHostKeyAsync</c> receives for
    /// <paramref name="refusal"/>: the translation in the table above, or the refusal itself.
    /// </summary>
    /// <param name="refusal">What the signer refused with.</param>
    /// <param name="caKeyName">The name of the SSH CA key, for the message.</param>
    public static Exception ForSigning(SigningRefusedException refusal, string caKeyName)
    {
        ArgumentNullException.ThrowIfNull(refusal);
        return refusal.Reason switch
        {
            SigningRefusalReason.SignerLocked or SigningRefusalReason.OperationUnsupported
                => new SshCaKeyUnavailableException(refusal.Message, refusal.Reason, refusal),
            SigningRefusalReason.UntypedData
                => new InvalidRequestException(refusal.Message),
            SigningRefusalReason.UnknownKey
                => new ConfigurationValidationException(
                    $"The signer holds no key for SSH CA key '{caKeyName}', so it cannot sign ({refusal.Message})",
                    ErrorCodes.IssuingCaKeyUnavailable),
            _ => refusal,
        };
    }

    /// <summary>
    /// The exception a caller of <c>GenerateKeyPairAsync</c> receives for <paramref name="refusal"/>:
    /// <see cref="SshCaKeyUnavailableException"/> for a locked signer or one that cannot make or
    /// hold the key, and the refusal itself for anything else.
    /// </summary>
    public static Exception ForKeyCreation(SigningRefusedException refusal)
    {
        ArgumentNullException.ThrowIfNull(refusal);
        return refusal.Reason is SigningRefusalReason.SignerLocked or SigningRefusalReason.OperationUnsupported
            ? new SshCaKeyUnavailableException(refusal.Message, refusal.Reason, refusal)
            : refusal;
    }
}
