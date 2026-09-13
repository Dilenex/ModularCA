using ModularCA.Shared.Models.Issuance;

namespace ModularCA.Core.Services;

/// <summary>
/// Answers "how long can this pairing of profiles actually issue for, and what is stopping it
/// from being longer" — the pre-flight counterpart to the clamps inside
/// <c>CertificateIssuanceService</c>.
/// </summary>
/// <remarks>
/// Its whole purpose is that the clamp never fires for an operator at a keyboard. Nothing told
/// them about any ceiling until the certificate came back shorter than they asked for, at which
/// point the certificate exists, carries a serial, and has to be revoked and reissued to fix. The
/// same three limits evaluated before submission cost one query.
/// </remarks>
public interface IValidityCeilingService
{
    /// <summary>
    /// Resolves the effective validity ceiling for a signing profile / certificate profile pairing.
    /// </summary>
    /// <param name="signingProfileId">The signing profile, which determines the issuing CA and so the tenant.</param>
    /// <param name="certProfileId">The certificate profile, whose <c>ValidityPeriodMax</c> is the baseline.</param>
    /// <param name="notBefore">
    /// The start the request would carry. Null uses the backdated default that issuance itself
    /// would apply, so the answer matches what the operator would actually get.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The ceiling and the layer that set it, or null when either profile does not exist — the
    /// caller renders that as a 404 rather than guessing.
    /// </returns>
    Task<ValidityCeilingPreflight?> ResolveAsync(
        Guid signingProfileId,
        Guid certProfileId,
        DateTime? notBefore = null,
        CancellationToken cancellationToken = default);
}
