using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Core.Services;

/// <summary>Where a new enrollment token is accepted (<see cref="EnrollmentTokenService.ScopeRefusal"/>).</summary>
public enum EnrollmentTokenScope
{
    /// <summary>The CAs that belong to no space.</summary>
    Instance,
    /// <summary>Every CA of one space.</summary>
    Space,
    /// <summary>One CA.</summary>
    Ca,
}

/// <summary>
/// The CA and space a new enrollment token is stamped with, resolved from the scope the creator
/// chose. A signing profile given alongside must issue from inside that scope.
/// </summary>
/// <param name="CaId">The CA the token is bound to, or null.</param>
/// <param name="SpaceId">The space the token or its CA belongs to, or null for the instance.</param>
/// <param name="NotFound">The scope or the signing profile names nothing.</param>
/// <param name="Error">Why the scope cannot be used with the signing profile, or null.</param>
public sealed record EnrollmentTokenTarget(Guid? CaId, Guid? SpaceId, bool NotFound = false, string? Error = null)
{
    private static readonly EnrollmentTokenTarget Missing = new(null, null, NotFound: true);

    private static EnrollmentTokenTarget Refused(string error) => new(null, null, Error: error);

    /// <summary>
    /// Resolves <paramref name="scope"/> and <paramref name="scopeId"/> (a space id or a CA id;
    /// none for the instance) against the database.
    /// </summary>
    public static async Task<EnrollmentTokenTarget> ResolveAsync(
        ModularCADbContext db, EnrollmentTokenScope scope, Guid? scopeId, Guid? signingProfileId)
    {
        (Guid Id, Guid? SpaceId)? profileCa = null;
        if (signingProfileId is Guid profileId)
        {
            var profile = await db.SigningProfiles.AsNoTracking()
                .Where(p => p.Id == profileId).Select(p => new { p.IssuerId }).FirstOrDefaultAsync();
            if (profile == null)
                return Missing;
            if (profile.IssuerId != null)
            {
                var ca = await db.CertificateAuthorities.AsNoTracking().IgnoreQueryFilters()
                    .Where(c => c.CertificateId == profile.IssuerId).Select(c => new { c.Id, c.SpaceId }).FirstOrDefaultAsync();
                if (ca != null)
                    profileCa = (ca.Id, ca.SpaceId);
            }
        }

        switch (scope)
        {
            case EnrollmentTokenScope.Instance:
                if (scopeId != null)
                    return Refused("An instance token names no space or CA.");
                if (profileCa is { SpaceId: not null })
                    return Refused("The signing profile issues from a CA in a space, where an instance token is not accepted.");
                return new(null, null);

            case EnrollmentTokenScope.Space:
                if (scopeId is not Guid spaceId || !await db.Spaces.AsNoTracking().AnyAsync(s => s.Id == spaceId))
                    return Missing;
                if (profileCa is { } inSpace && inSpace.SpaceId != spaceId)
                    return Refused("The signing profile issues from a CA outside this space.");
                return new(null, spaceId);

            case EnrollmentTokenScope.Ca:
                if (scopeId is not Guid caId)
                    return Missing;
                var target = await db.CertificateAuthorities.AsNoTracking()
                    .Where(c => c.Id == caId && !c.IsSshCa).Select(c => new { c.Id, c.SpaceId }).FirstOrDefaultAsync();
                if (target == null)
                    return Missing;
                if (profileCa is { } atCa && atCa.Id != target.Id)
                    return Refused("The signing profile issues from another CA.");
                return new(target.Id, target.SpaceId);

            default:
                return Missing;
        }
    }
}
