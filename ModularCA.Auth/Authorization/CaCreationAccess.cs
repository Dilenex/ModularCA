using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Authorization;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Who may create a certificate authority. The creation endpoints take their tenant and parent
/// from the request body, so the route-driven policy handler cannot scope them; they call this
/// instead.
/// </summary>
/// <remarks>
/// <para>
/// A root is a system act: it needs <c>system.manage</c>. An intermediate belongs to a tenant, so
/// <c>ca.manage</c> held for that tenant (tenant-wide group, tenant-scoped role or grant, or at
/// system scope) is enough, provided the caller may also sign under the parent. A parent in the
/// same tenant is covered by the tenant grant; a parent elsewhere needs <c>ca.manage</c> on that
/// parent, so a tenant administrator cannot chain a new CA under another tenant's authority they
/// were never given.
/// </para>
/// </remarks>
public static class CaCreationAccess
{
    /// <summary>
    /// Whether the user may create an intermediate CA in <paramref name="tenantId"/> signed by
    /// <paramref name="parentCaId"/>. False when the parent does not exist.
    /// </summary>
    public static async Task<bool> MayCreateIntermediateAsync(
        ICaGroupAuthorizationService auth, ModularCADbContext db, Guid userId, Guid tenantId, Guid parentCaId)
    {
        if (await auth.IsSystemAdminAsync(userId))
            return true;
        if (!await auth.HasTenantCapabilityAsync(userId, tenantId, Capabilities.CaManage))
            return false;

        var parent = await db.CertificateAuthorities
            .AsNoTracking()
            .IgnoreQueryFilters()
            .Where(ca => ca.Id == parentCaId)
            .Select(ca => new { ca.Id, ca.TenantId })
            .FirstOrDefaultAsync();
        if (parent == null)
            return false;

        return parent.TenantId == tenantId
            || await auth.HasCaCapabilityAsync(userId, parent.Id, Capabilities.CaManage);
    }

    /// <summary>
    /// Whether the user may create a root CA in <paramref name="tenantId"/>: only a holder of
    /// <c>system.manage</c> at system scope. The tenant is accepted for symmetry with the
    /// intermediate check and for callers that resolve the operation type at runtime.
    /// </summary>
    public static Task<bool> MayCreateRootAsync(ICaGroupAuthorizationService auth, Guid userId, Guid tenantId)
        => auth.IsSystemAdminAsync(userId);
}
