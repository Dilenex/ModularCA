using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Authorization;

namespace ModularCA.Core.Services;

/// <summary>
/// Names the accounts that hold <c>ca.manage</c> at instance scope through a direct grant or a
/// role assigned to the account itself, rather than through the system-operator group. Since 0.4.0
/// S5 that rank is the controlled system-operator tier, so granting, removing or deleting such an
/// account needs a controlled-user ceremony. Read-only; two small queries.
/// </summary>
public static class InstanceOperatorHolderCheck
{
    /// <summary>The startup warning naming those accounts, or null when there are none.</summary>
    public static async Task<string?> WarningAsync(ModularCADbContext db, CancellationToken ct = default)
    {
        var viaGrants = await db.UserCapabilityGrants.AsNoTracking()
            .Where(ug => ug.TenantId == null && ug.CertificateAuthorityId == null && ug.ResourceType == null
                && ug.Capability == Capabilities.CaManage)
            .Select(ug => ug.UserId)
            .ToListAsync(ct);
        var viaRoles = await db.RoleAssignments.AsNoTracking()
            .Where(ra => ra.UserId != null && ra.GroupId == null && ra.TenantId == null && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.ResourceType == null && rc.Capability == Capabilities.CaManage))
            .Select(ra => ra.UserId!.Value)
            .ToListAsync(ct);

        var ids = viaGrants.Concat(viaRoles).Distinct().ToList();
        if (ids.Count == 0) return null;
        var names = await db.Users.AsNoTracking()
            .Where(u => ids.Contains(u.Id))
            .OrderBy(u => u.Username)
            .Select(u => u.Username)
            .ToListAsync(ct);
        if (names.Count == 0) return null;

        return $"{names.Count} account(s) hold ca.manage at instance scope through a direct grant or role assignment, "
            + $"not the system-operator group: {string.Join(", ", names)}. This rank is now a controlled system-operator "
            + "tier: granting it, removing it, or deleting these accounts needs a controlled-user ceremony unless a "
            + "system-super acts.";
    }
}
