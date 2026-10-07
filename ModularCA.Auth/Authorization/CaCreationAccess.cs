using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Authorization;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Who may create a certificate authority. The creation endpoints take their space and parent
/// from the request body, so the route-driven policy handler cannot scope them; they call this
/// instead.
/// </summary>
/// <remarks>
/// <para>
/// A root is a system act: it needs <c>system.manage</c>. An intermediate belongs to a space, so
/// <c>ca.manage</c> held for that space (space-wide group, space-scoped role or grant, or at
/// system scope) is enough, provided the caller may also sign under the parent. A parent in the
/// same space is covered by the space grant; a parent elsewhere needs <c>ca.manage</c> on that
/// parent, so a space administrator cannot chain a new CA under another space's authority they
/// were never given.
/// </para>
/// </remarks>
public static class CaCreationAccess
{
    /// <summary>
    /// Whether the user may create an intermediate CA in <paramref name="spaceId"/> (null for an
    /// instance CA, which needs <c>ca.manage</c> at system scope) signed by
    /// <paramref name="parentCaId"/>. False when the parent does not exist.
    /// </summary>
    public static async Task<bool> MayCreateIntermediateAsync(
        ICaGroupAuthorizationService auth, ModularCADbContext db, Guid userId, Guid? spaceId, Guid parentCaId)
    {
        if (await auth.IsSystemAdminAsync(userId))
            return true;
        if (!await auth.HasScopeCapabilityAsync(userId, spaceId, Capabilities.CaManage))
            return false;

        var parent = await db.CertificateAuthorities
            .AsNoTracking()
            .Where(ca => ca.Id == parentCaId)
            .Select(ca => new { ca.Id, ca.SpaceId })
            .FirstOrDefaultAsync();
        if (parent == null)
            return false;

        return parent.SpaceId == spaceId
            || await auth.HasCaCapabilityAsync(userId, parent.Id, Capabilities.CaManage);
    }

    /// <summary>
    /// Whether the user may create a root CA in <paramref name="spaceId"/> (null for the
    /// instance): only a holder of <c>system.manage</c> at system scope. The space is accepted
    /// for symmetry with the intermediate check and for callers that resolve the operation type
    /// at runtime.
    /// </summary>
    public static Task<bool> MayCreateRootAsync(ICaGroupAuthorizationService auth, Guid userId, Guid? spaceId)
        => auth.IsSystemAdminAsync(userId);
}
