using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Auth.Authorization;

/// <summary>Fence checks that need the database to find a row's scope.</summary>
public static class SpaceFenceQueries
{
    /// <summary>
    /// Whether request profile <paramref name="requestProfileId"/> exists and is inside
    /// <paramref name="fence"/>: an unbound one is instance-wide configuration everyone may use; a
    /// CA-bound one follows its CA's scope, and one bound to a deleted CA is outside.
    /// </summary>
    public static async Task<bool> AllowsRequestProfileAsync(this SpaceFence fence, ModularCADbContext db, Guid requestProfileId)
    {
        var profile = await db.RequestProfiles.AsNoTracking()
            .Where(p => p.Id == requestProfileId)
            .Select(p => new { p.CertificateAuthorityId })
            .FirstOrDefaultAsync();
        if (profile == null)
            return false;
        if (profile.CertificateAuthorityId is not Guid caId)
            return true;
        var ca = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.Id == caId)
            .Select(c => new { c.SpaceId })
            .FirstOrDefaultAsync();
        return ca != null && fence.Allows(ca.SpaceId);
    }
}
