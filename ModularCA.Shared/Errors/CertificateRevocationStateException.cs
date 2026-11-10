namespace ModularCA.Shared.Errors;

/// <summary>
/// Raised by the revocation service when a certificate's revocation state does not allow the
/// change asked for: revoking a certificate that is already revoked permanently, holding one again
/// through revoke, holding a permanently revoked one, or releasing one that is not on hold. Answers
/// 409 with <see cref="ErrorCodes.CertificateRevocationState"/>.
/// </summary>
/// <remarks>
/// These used to be bare <see cref="InvalidOperationException"/>s, which reached the global handler
/// as a 500 on every path without its own catch, although the request was well-formed and only the
/// certificate's state stood in the way. As a member of the <see cref="RequestValidationException"/>
/// family it is answered by <c>RequestValidationMiddleware</c>; the anonymous enrollment protocols
/// catch the family at their boundary and keep their own sanitized answers.
/// </remarks>
/// <param name="message">What stood in the way, phrased for the operator.</param>
/// <param name="currentReason">The certificate's revocation reason as stored, or null when it is not revoked.</param>
public sealed class CertificateRevocationStateException(string message, string? currentReason)
    : RequestValidationException(message)
{
    /// <inheritdoc/>
    public override string Title => "Certificate revocation state conflict";

    /// <inheritdoc/>
    public override int Status => 409;

    /// <inheritdoc/>
    public override string Code => ErrorCodes.CertificateRevocationState;

    /// <summary>The certificate's revocation reason as stored, or null when it is not revoked.</summary>
    public string? CurrentReason { get; } = currentReason;
}
