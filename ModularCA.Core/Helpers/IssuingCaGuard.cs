using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Helpers;

/// <summary>
/// The single refusal every path that signs beneath a CA runs first: issuance, reissue,
/// auto-renewal and intermediate creation. A CA that is revoked (any reason, including
/// certificateHold), outside its validity window, disabled, deleted or unregistered does not sign.
/// </summary>
public static class IssuingCaGuard
{
    /// <summary>
    /// Refuses with a <see cref="ConfigurationValidationException"/> when the CA whose certificate
    /// row is <paramref name="caCertRow"/> may not sign, and otherwise returns its authority row.
    /// The authority row is looked up past the tenant and soft-delete query filters: the guard
    /// judges the CA's own state, not whether the caller's tenants can see it.
    /// </summary>
    /// <param name="db">Context to resolve the authority row through.</param>
    /// <param name="caCertRow">The issuing CA's certificate row.</param>
    /// <param name="caCert">The parsed issuing CA certificate, authoritative for the validity window.</param>
    /// <param name="requireAuthority">
    /// False only on the CA creation seam, where the new CA's authority row is not committed yet;
    /// every other caller must find one.
    /// </param>
    /// <param name="utcNow">The instant validity is judged at.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authority row, or null when none exists and <paramref name="requireAuthority"/> is false.</returns>
    public static async Task<CertificateAuthorityEntity?> EnsureUsableAsync(
        ModularCADbContext db, CertificateEntity caCertRow, X509Certificate caCert,
        bool requireAuthority, DateTime utcNow, CancellationToken cancellationToken = default)
    {
        if (caCertRow.Revoked)
            throw new ConfigurationValidationException(
                $"The issuing CA '{caCertRow.SubjectDN}' is revoked ({caCertRow.RevocationReason ?? "unspecified"}) and cannot sign.",
                ErrorCodes.IssuingCaRevoked);

        if (!caCert.IsValid(utcNow))
            throw new ConfigurationValidationException(
                $"The issuing CA '{caCertRow.SubjectDN}' is outside its validity ({caCert.NotBefore:O} to {caCert.NotAfter:O}) and cannot sign.",
                ErrorCodes.IssuingCaOutsideValidity);

        var rows = await db.CertificateAuthorities.IgnoreQueryFilters()
            .Where(c => c.CertificateId == caCertRow.CertificateId)
            .ToListAsync(cancellationToken);
        var ca = rows.FirstOrDefault(c => !c.IsDeleted);
        if (ca == null)
        {
            if (rows.Count > 0)
                throw new ConfigurationValidationException(
                    $"The issuing CA '{caCertRow.SubjectDN}' has been deleted and cannot sign.", ErrorCodes.IssuingCaDisabled);
            if (requireAuthority)
                throw new ConfigurationValidationException(
                    $"No certificate authority record names CA certificate {caCertRow.CertificateId}; it cannot sign.",
                    ErrorCodes.IssuingCaUnregistered);
            return null;
        }

        if (!ca.IsEnabled)
            throw new ConfigurationValidationException(
                $"The issuing CA '{ca.Name}' is disabled and cannot sign.", ErrorCodes.IssuingCaDisabled);

        return ca;
    }
}
