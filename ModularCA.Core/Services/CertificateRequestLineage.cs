using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services;

/// <summary>
/// How a renewal or reissue finds the request a certificate came from, and what it takes from it.
/// </summary>
public static class CertificateRequestLineage
{
    /// <summary>
    /// The requests that point at <paramref name="certificateId"/>, the one to read first. A
    /// reissue points both the original request and a link row at the new certificate; rows
    /// recorded under a request profile come first, then the oldest, so the original is read and
    /// not a link row from before link rows carried the profile.
    /// </summary>
    /// <param name="requests">The certificate requests.</param>
    /// <param name="certificateId">The certificate.</param>
    public static IQueryable<CertRequestEntity> ThatIssued(this IQueryable<CertRequestEntity> requests, Guid certificateId)
        => requests
            .Where(r => r.IssuedCertificateId == certificateId)
            .OrderBy(r => r.RequestProfileId == null)
            .ThenBy(r => r.SubmittedAt)
            .ThenBy(r => r.Id);

    /// <summary>
    /// Carries onto <paramref name="next"/> what <paramref name="original"/> held beyond its CSR:
    /// the request profile it was made under, so the profile is enforced again, and the
    /// extensions it asked to be echoed. When <paramref name="reusesCsr"/>, also the subject and
    /// SAN overrides: issuance builds the names from the CSR, and the overrides are how the
    /// profile's fixed and default values and an operator's changes reached the certificate.
    /// </summary>
    /// <param name="original">The request the certificate being renewed or reissued came from; nothing is carried when null.</param>
    /// <param name="next">The new request.</param>
    /// <param name="reusesCsr">Whether <paramref name="next"/> holds the original's CSR rather than one built from the certificate's names.</param>
    public static void CarryForward(CertRequestEntity? original, CertRequestEntity next, bool reusesCsr)
    {
        if (original == null)
            return;
        next.RequestProfileId = original.RequestProfileId;
        next.AdditionalExtensions = original.AdditionalExtensions;
        if (reusesCsr)
        {
            next.SubjectOverrides = original.SubjectOverrides;
            next.SanOverrides = original.SanOverrides;
        }
    }
}
