using ModularCA.Shared.Signing;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// One decision the signer took: what was asked, by whom, under which context, and whether it
/// was allowed. Written for every operation the policy judges, allowed or refused, so the
/// signer's own record is complete on its own.
/// </summary>
/// <param name="At">When the decision was taken, UTC.</param>
/// <param name="Operation">The contract operation: <c>Sign</c>, <c>Decrypt</c>, <c>Export</c> and so on.</param>
/// <param name="Context">The context the caller supplied.</param>
/// <param name="Key">The key the operation named, or null for an operation that names none.</param>
/// <param name="Algorithm">The signature algorithm, for a signature.</param>
/// <param name="Allowed">Whether policy allowed the operation.</param>
/// <param name="Reason">The refusal reason, or null when allowed.</param>
/// <param name="DataHash">SHA-256 over what was signed, for a signature; for a wrap or an unwrap, over the wrapped blob, never over the secret.</param>
/// <param name="SecretKind">What kind of secret a wrap or an unwrap was for, including a refused one; null for every other operation.</param>
/// <param name="WrappingKeyId">The id of the key that wrapped, or was asked to unwrap, as the blob names it: lower-case hex. Null for every other operation.</param>
/// <param name="Summary">What a <c>SignSsh</c> decision was asked to certify, as <see cref="SshAuditSummary"/> writes it. Null for every other operation.</param>
public sealed record SignerDecision(
    DateTime At,
    string Operation,
    SigningContext Context,
    KeyRef? Key,
    SignatureAlgorithm? Algorithm,
    bool Allowed,
    string? Reason,
    byte[]? DataHash,
    SecretKind? SecretKind = null,
    string? WrappingKeyId = null,
    string? Summary = null);

/// <summary>
/// Where the signer writes its decisions. The signer records every decision through this before
/// the operation's result is returned to the caller; the sink owns the persistence.
/// </summary>
public interface ISignerAuditSink
{
    /// <summary>Records one decision.</summary>
    Task RecordAsync(SignerDecision decision, CancellationToken cancellationToken = default);
}
