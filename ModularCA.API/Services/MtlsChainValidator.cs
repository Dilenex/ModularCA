using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Services;

/// <summary>
/// Shared mTLS client-certificate chain validation. Replaces the
/// ad-hoc "trust any cert whose thumbprint matches" model used by the login-path
/// mTLS controllers with a full X509Chain build against either:
/// <list type="bullet">
///   <item>the CA identified by <c>MtlsCredential.SigningCaId</c> (when the caller knows
///         which enrolled credential is being asserted), or</item>
///   <item>the system-wide trusted CA list loaded from <c>Mtls.TrustedCaCertPaths</c>
///         (fallback for early-handshake chain validation).</item>
/// </list>
/// Each call builds a fresh chain; OCSP/CRL checks honor
/// <see cref="ModularCA.Shared.Entities.SecurityPolicyEntity.RequireMtlsOcspCheck"/> — fail-closed when enabled, fail-open
/// with an audit warning when not.
/// </summary>
public static class MtlsChainValidator
{
    /// <summary>
    /// Builds a chain for <paramref name="clientCert"/> rooted at <paramref name="expectedCa"/>.
    /// Returns <c>true</c> when the chain is valid (and optionally the OCSP/CRL check
    /// passes). Writes the outcome to <paramref name="chainErrors"/> for audit.
    /// <para>
    /// The chain build itself now lives in
    /// <see cref="ModularCA.Shared.Utils.X509ChainValidationUtil.ValidateAgainstAnchor(X509Certificate2, X509Certificate2, bool, out string?)"/> so the
    /// mTLS login path and the EST re-enrollment path share one implementation. EST lives in
    /// <c>ModularCA.Core</c>, which cannot reference this assembly, so the chain core was pulled
    /// down into <c>ModularCA.Shared</c>; this method stays as the login path's entry point and
    /// is behaviourally unchanged.
    /// </para>
    /// </summary>
    public static bool ValidateAgainstCa(
        X509Certificate2 clientCert,
        X509Certificate2 expectedCa,
        bool requireRevocationCheck,
        out string? chainErrors)
        => X509ChainValidationUtil.ValidateAgainstAnchor(
            clientCert, expectedCa, requireRevocationCheck, out chainErrors);

    /// <summary>
    /// Loads the signing CA's <see cref="X509Certificate2"/> from the DB for the given
    /// mTLS credential, then validates <paramref name="clientCert"/>'s chain against it.
    /// Returns <c>true</c> on success.
    /// <para>
    /// With <paramref name="requireRevocationCheck"/> set and an intermediate signing CA, the CA's
    /// own issuers up to its root are loaded as well where this instance holds them
    /// (<see cref="AnchorIssuerPath"/>) and handed to the validator, which needs a complete chain
    /// to check revocation on every platform. They do not change which certificates count as
    /// issued by the signing CA. Without the revocation requirement nothing more is read than
    /// before.
    /// </para>
    /// </summary>
    /// <param name="db">The context to read the signing CA through.</param>
    /// <param name="signingCaId">The CA recorded as the signer of the credential being asserted.</param>
    /// <param name="clientCert">The certificate the client presented.</param>
    /// <param name="requireRevocationCheck">When true, perform online revocation checking and fail closed.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<bool> ValidateAgainstCredentialCaAsync(
        ModularCADbContext db,
        Guid signingCaId,
        X509Certificate2 clientCert,
        bool requireRevocationCheck,
        CancellationToken ct = default)
    {
        var caCertEntity = await db.CertificateAuthorities
            .AsNoTracking()
            .Where(c => c.Id == signingCaId)
            .Select(c => new { c.CertificateId })
            .FirstOrDefaultAsync(ct);

        if (caCertEntity?.CertificateId == null) return false;

        if (!requireRevocationCheck)
        {
            var caCertRow = await db.Certificates
                .AsNoTracking()
                .Where(c => c.CertificateId == caCertEntity.CertificateId)
                .Select(c => new { c.RawCertificate })
                .FirstOrDefaultAsync(ct);

            if (caCertRow?.RawCertificate == null) return false;

            using var anchor = X509CertificateLoader.LoadCertificate(caCertRow.RawCertificate);
            return ValidateAgainstCa(clientCert, anchor, requireRevocationCheck: false, out _);
        }

        // The whole row this time: the walk up to the root follows its issuer links.
        var caCertFull = await db.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertEntity.CertificateId, ct);

        if (caCertFull?.RawCertificate == null) return false;

        using var caCert = X509CertificateLoader.LoadCertificate(caCertFull.RawCertificate);
        using var caIssuers = await AnchorIssuerPath.LoadAsync(db, caCertFull, requireRevocationCheck: true);
        return X509ChainValidationUtil.ValidateAgainstAnchor(
            clientCert, caCert, caIssuers.Certificates, requireRevocationCheck: true, out _);
    }
}
