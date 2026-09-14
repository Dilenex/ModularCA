using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Decides whether a username-authenticated protocol caller may enroll at a CA, using the same
/// capability model as the admin API.
/// </summary>
/// <remarks>
/// The capability is <see cref="Capabilities.CertRequest"/> on the target CA: the entitlement a
/// user needs to submit a certificate request through the portal. Reusing it means an operator
/// who grants "may request certificates from this CA" has granted exactly that, on every path —
/// not a portal-only permission with a wider protocol twin. System administrators pass through the
/// existing <c>system.manage</c> bypass in <see cref="ICaGroupAuthorizationService"/>, with its
/// elevated-access audit.
/// </remarks>
public sealed class EnrollmentPrincipalAuthorizer(
    ModularCADbContext db,
    ICaGroupAuthorizationService authorization) : IEnrollmentPrincipalAuthorizer
{
    /// <inheritdoc />
    public async Task<bool> MayEnrollAsync(string username, Guid caId)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        var userId = await db.Users
            .AsNoTracking()
            .Where(u => u.Username == username && u.IsActive)
            .Select(u => (Guid?)u.Id)
            .FirstOrDefaultAsync();

        if (userId == null)
            return false;

        return await authorization.HasCaCapabilityAsync(userId.Value, caId, Capabilities.CertRequest);
    }
}
