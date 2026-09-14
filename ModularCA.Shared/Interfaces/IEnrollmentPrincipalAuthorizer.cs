namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Answers whether a username-authenticated protocol caller may enroll at a given CA.
/// </summary>
/// <remarks>
/// <para>
/// EST's HTTP authentication (RFC 7030 section 3.2.3) proves that the caller knows a password. It
/// does not, by itself, say anything about which CAs that account is entitled to use. Before this
/// existed, <c>EnrollmentAuthorizationService</c> checked only <c>IsAuthenticated</c>, so a user
/// whose only entitlement was in tenant B could enroll at tenant A's CA with an ordinary session
/// token. The CSR name binding limited <em>what</em> could be obtained, not <em>from whom</em>.
/// </para>
/// <para>
/// Defined in Shared rather than Core because the group-role model that answers the question lives
/// in <c>ModularCA.Auth</c>, which depends on Core; Core cannot reference it directly. The
/// implementation delegates to the same capability check the admin API uses, so "may enroll here"
/// means the same thing on every path.
/// </para>
/// </remarks>
public interface IEnrollmentPrincipalAuthorizer
{
    /// <summary>
    /// Determines whether the named account holds the enrollment capability on the given CA.
    /// </summary>
    /// <param name="username">The authenticated username.</param>
    /// <param name="caId">The CA the caller is trying to enroll at.</param>
    /// <returns><c>true</c> when the account may request certificates from that CA.</returns>
    Task<bool> MayEnrollAsync(string username, Guid caId);
}
