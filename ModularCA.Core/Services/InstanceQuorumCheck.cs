using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Authorization;

namespace ModularCA.Core.Services;

/// <summary>
/// Warns when the instance's key-ceremony quorum cannot be met: a ceremony on an instance CA is
/// approved by holders of <c>system.manage</c> or system-scoped <c>ca.manage</c>, and the
/// initiator never counts, so a quorum of N needs N + 1 eligible accounts.
/// </summary>
public static class InstanceQuorumCheck
{
    /// <summary>The warning for <paramref name="required"/> approvals and <paramref name="eligible"/> eligible accounts, or null when the quorum can be met.</summary>
    public static string? Warning(int required, int eligible)
    {
        var needed = Math.Max(1, required) + 1;
        return eligible >= needed
            ? null
            : $"The instance requires {Math.Max(1, required)} approval(s) for key ceremonies on instance CAs, but only {eligible} "
              + $"account(s) can approve one. The initiator never counts, so {needed} are needed. Lower "
              + "CeremonyRequiredApprovals in the security policy, or give more accounts ca.manage at system scope.";
    }

    /// <summary>
    /// Reads the instance quorum and counts the active, unlocked, non-service accounts eligible to
    /// approve. Null when the instance does not require key ceremonies.
    /// </summary>
    public static async Task<string?> WarningAsync(ModularCADbContext db, CancellationToken ct = default)
    {
        var policy = await new EffectivePolicyResolver(db).ResolveAsync(null, ct);
        if (!policy.RequireKeyCeremony)
            return null;
        var caps = new[] { Capabilities.SystemManage, Capabilities.CaManage };

        var viaGroupGrants = db.CapabilityGrants
            .Where(g => g.Group.IsSystemGroup && g.ResourceType == null && caps.Contains(g.Capability))
            .SelectMany(g => g.Group.Members.Select(m => m.UserId));
        var viaGroupRoles = db.RoleAssignments
            .Where(ra => ra.GroupId != null && ra.Group!.IsSystemGroup
                && ra.Role.Capabilities.Any(rc => rc.ResourceType == null && caps.Contains(rc.Capability)))
            .SelectMany(ra => ra.Group!.Members.Select(m => m.UserId));
        var viaUserGrants = db.UserCapabilityGrants
            .Where(ug => ug.SpaceId == null && ug.CertificateAuthorityId == null && ug.ResourceType == null && caps.Contains(ug.Capability))
            .Select(ug => ug.UserId);
        var viaUserRoles = db.RoleAssignments
            .Where(ra => ra.UserId != null && ra.GroupId == null && ra.SpaceId == null && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.ResourceType == null && caps.Contains(rc.Capability)))
            .Select(ra => ra.UserId!.Value);

        var holders = (await viaGroupGrants.ToListAsync(ct))
            .Concat(await viaGroupRoles.ToListAsync(ct))
            .Concat(await viaUserGrants.ToListAsync(ct))
            .Concat(await viaUserRoles.ToListAsync(ct))
            .Distinct()
            .ToList();
        var eligible = await db.Users.AsNoTracking()
            .CountAsync(u => holders.Contains(u.Id) && u.IsActive && !u.IsLocked && !u.IsServiceIdentity, ct);
        return Warning(policy.CeremonyRequiredApprovals, eligible);
    }
}
