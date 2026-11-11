using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Authorization;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// The scopes an account holds anything in. An account is owned by no CA and no space; what ties
/// it to one is what it holds there. <see cref="Instance"/> is set by anything held at instance
/// scope: a system group, an instance group, a global grant or role, an instance-wide service
/// identity, or a holding whose scope cannot be resolved.
/// </summary>
/// <param name="Instance">The account holds something at instance scope.</param>
/// <param name="SpaceIds">The spaces the account holds something space-wide in.</param>
/// <param name="CaIds">The CAs the account holds something on.</param>
public sealed record AccountFootprint(bool Instance, IReadOnlyCollection<Guid> SpaceIds, IReadOnlyCollection<Guid> CaIds)
{
    /// <summary>The account holds nothing anywhere: no membership, grant, role or access.</summary>
    public bool IsEmpty => !Instance && SpaceIds.Count == 0 && CaIds.Count == 0;
}

/// <summary>
/// Who may administer a user account (change its identity or state, reset its password, delete
/// it) below system scope. The routes that do so carry only a user id, so no CA-scoped policy
/// can decide them; this is the decision, made against the target account.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>A system-super, and a holder of <c>user.manage</c> at system scope (or a system admin),
/// passes this check for any account. The controlled-tier rules still apply after it.</item>
/// <item>Anyone else must hold <c>user.manage</c> on every scope of the account's
/// <see cref="AccountFootprint"/>: on each CA (held there, across its space, or at system scope)
/// and across each space it holds something space-wide in.</item>
/// <item>An account that holds anything at instance scope, or nothing at all, is a system
/// matter: no scope below the system owns it, so no scoped administrator may take it over.</item>
/// </list>
/// One holding outside the caller's scopes is enough to refuse. Without that, an administrator
/// of one small CA could reset the password of an account that is also an operator in another
/// space, sign in as it, and act there.
/// </remarks>
public static class UserAdministrationAccess
{
    /// <summary>
    /// The scopes <paramref name="userId"/> holds anything in: group memberships (the group's
    /// own scope), capability grants and roles on the user (resource-scoped ones included),
    /// per-certificate access entries, SSH login names granted to the user, and a service
    /// identity's confinement. With <paramref name="exceptGroupId"/>, as it would be without
    /// the membership of that group: what removing it would leave.
    /// </summary>
    public static async Task<AccountFootprint> FootprintAsync(ModularCADbContext db, Guid userId, Guid? exceptGroupId = null)
    {
        var instance = false;
        var spaces = new HashSet<Guid>();
        var cas = new HashSet<Guid>();

        void Add(Guid? spaceId, Guid? caId)
        {
            if (caId is Guid ca) cas.Add(ca);
            else if (spaceId is Guid space) spaces.Add(space);
            else instance = true;
        }

        var groups = await db.CaGroupMembers.AsNoTracking()
            .Where(m => m.UserId == userId && (exceptGroupId == null || m.GroupId != exceptGroupId))
            .Select(m => new { m.Group.IsSystemGroup, m.Group.SpaceId, m.Group.CertificateAuthorityId })
            .ToListAsync();
        foreach (var g in groups)
        {
            if (g.IsSystemGroup) instance = true;
            else Add(g.SpaceId, g.CertificateAuthorityId);
        }

        var grants = await db.UserCapabilityGrants.AsNoTracking()
            .Where(g => g.UserId == userId)
            .Select(g => new { g.SpaceId, g.CertificateAuthorityId })
            .ToListAsync();
        foreach (var g in grants)
            Add(g.SpaceId, g.CertificateAuthorityId);

        var roles = await db.RoleAssignments.AsNoTracking()
            .Where(r => r.UserId == userId && r.GroupId == null)
            .Select(r => new { r.SpaceId, r.CertificateAuthorityId })
            .ToListAsync();
        foreach (var r in roles)
            Add(r.SpaceId, r.CertificateAuthorityId);

        var service = await db.Users.AsNoTracking()
            .Where(u => u.Id == userId && u.IsServiceIdentity)
            .Select(u => new { u.ServiceScopeSpaceId, u.ServiceScopeCaId })
            .FirstOrDefaultAsync();
        if (service != null)
            Add(service.ServiceScopeSpaceId, service.ServiceScopeCaId);

        // Access to single certificates and SSH login names are held on a CA too. One that
        // cannot be resolved to a CA counts as an instance holding, so it is never ignored.
        var certificateIds = await db.CertificateAccessLists.AsNoTracking()
            .Where(a => a.UserId == userId)
            .Select(a => a.CertificateId)
            .Distinct()
            .ToListAsync();
        if (certificateIds.Count > 0)
        {
            var resolver = new CaTargetResolver(db);
            foreach (var certificateId in certificateIds)
            {
                var resolution = await resolver.ResolveAsync(CaTarget.Certificate, certificateId);
                if (resolution.NotFound || resolution.Unscoped || resolution.CaIds.Count == 0)
                    instance = true;
                foreach (var caId in resolution.CaIds)
                    cas.Add(caId);
            }
        }

        var loginNameCas = await db.SshLoginNameGrants.AsNoTracking()
            .Where(g => g.UserId == userId)
            .Select(g => (Guid?)g.SshCaKey.CertificateAuthorityId)
            .Distinct()
            .ToListAsync();
        foreach (var caId in loginNameCas)
            Add(null, caId);

        return new AccountFootprint(instance, spaces, cas);
    }

    /// <summary>
    /// True when <paramref name="userId"/>, the request's own user, holds
    /// <paramref name="capability"/> at system scope or is a system admin, under the badge worn.
    /// </summary>
    public static async Task<bool> HoldsAtSystemScopeAsync(ICaGroupAuthorizationService auth, Guid userId, string capability)
        => await auth.HasSystemCapabilityAsync(userId, capability) || await auth.IsSystemAdminAsync(userId);

    /// <summary>
    /// True when <paramref name="userId"/>, the request's own user, holds
    /// <paramref name="capability"/> at system scope, space-wide in some space, or on some CA.
    /// This is the route gate only (<see cref="AnyScopeCapabilityRequirement"/>); it says nothing
    /// about any particular account.
    /// </summary>
    public static async Task<bool> HoldsAtSomeScopeAsync(ICaGroupAuthorizationService auth, Guid userId, string capability)
        => await HoldsAtSystemScopeAsync(auth, userId, capability)
           || (await auth.GetSpaceIdsWithCapabilityAsync(userId, capability)).Count > 0
           || (await auth.GetAccessibleCaIdsAsync(userId, capability)).Count > 0;

    /// <summary>
    /// Why <paramref name="callerId"/> may not administer the account <paramref name="targetUserId"/>,
    /// or null when their scope covers it. <paramref name="callerId"/> must be the request's own
    /// user, so the worn badge applies. With <paramref name="systemScopeOnly"/> only a system-super
    /// or a holder of <c>user.manage</c> at system scope passes, whatever the account holds.
    /// The text never names the scopes the caller does not cover.
    /// </summary>
    public static async Task<string?> RefusalAsync(
        ModularCADbContext db, ICaGroupAuthorizationService auth, IControlledUserCeremonyService controlled,
        Guid callerId, Guid targetUserId, bool systemScopeOnly = false)
    {
        if (await controlled.IsSuperAsync(callerId))
            return null;
        if (await HoldsAtSystemScopeAsync(auth, callerId, Capabilities.UserManage))
            return null;
        if (systemScopeOnly)
            return "This change needs user.manage at system scope.";

        var footprint = await FootprintAsync(db, targetUserId);
        if (footprint.IsEmpty)
            return "This account belongs to no scope, so only a system administrator can change it.";

        var covered = !footprint.Instance;
        foreach (var spaceId in footprint.SpaceIds)
            covered = covered && await auth.HasSpaceCapabilityAsync(callerId, spaceId, Capabilities.UserManage);
        foreach (var caId in footprint.CaIds)
            covered = covered && await auth.HasCaCapabilityAsync(callerId, caId, Capabilities.UserManage);

        return covered
            ? null
            : "You need user.manage on every scope this account belongs to. It holds memberships, grants or roles "
              + "outside the scopes you administer; ask an administrator of all of them, or a system administrator.";
    }

    /// <summary>
    /// Whether <paramref name="callerId"/>, the request's own user, may create or leave behind an
    /// account that holds nothing anywhere: a system-super, or a holder of <c>user.manage</c> at
    /// system scope (or a system admin). Such an account belongs to no scope, so nobody below
    /// system scope can administer it afterwards; an administrator of a CA or a space therefore
    /// must create an account in a group, and may not remove an account's last holding.
    /// </summary>
    public static async Task<bool> MayHandleUnscopedAccountsAsync(
        ICaGroupAuthorizationService auth, IControlledUserCeremonyService controlled, Guid callerId)
        => await controlled.IsSuperAsync(callerId) || await HoldsAtSystemScopeAsync(auth, callerId, Capabilities.UserManage);

    /// <summary>The scopes of <paramref name="footprint"/> as text: <c>instance</c>, <c>space:{id}</c>, <c>ca:{id}</c>.</summary>
    public static List<string> ScopeKeys(AccountFootprint footprint)
    {
        var keys = new List<string>();
        if (footprint.Instance) keys.Add("instance");
        keys.AddRange(footprint.SpaceIds.OrderBy(id => id).Select(id => $"space:{id}"));
        keys.AddRange(footprint.CaIds.OrderBy(id => id).Select(id => $"ca:{id}"));
        return keys;
    }

    /// <summary>
    /// What a ceremony for an account change records about its target when
    /// <paramref name="callerId"/>, the request's own user, opens it: null for a system-super or a
    /// holder of <c>user.manage</c> at system scope, who covers every scope; otherwise the scopes
    /// the account holds anything in now (<see cref="ScopeKeys"/>), which the caller was just
    /// checked to cover. <see cref="HoldsOutsideAsync"/> compares against them at execute.
    /// </summary>
    public static async Task<List<string>?> ScopesToPinAsync(
        ModularCADbContext db, ICaGroupAuthorizationService auth, IControlledUserCeremonyService controlled, Guid callerId, Guid targetUserId)
    {
        if (await controlled.IsSuperAsync(callerId) || await HoldsAtSystemScopeAsync(auth, callerId, Capabilities.UserManage))
            return null;
        return ScopeKeys(await FootprintAsync(db, targetUserId));
    }

    /// <summary>
    /// True when <paramref name="userId"/> now holds something in a scope that is not among
    /// <paramref name="pinnedScopes"/>: the account has moved into a scope the administrator who
    /// opened the change was never checked against.
    /// </summary>
    public static async Task<bool> HoldsOutsideAsync(ModularCADbContext db, Guid userId, IReadOnlyCollection<string> pinnedScopes)
        => ScopeKeys(await FootprintAsync(db, userId)).Any(key => !pinnedScopes.Contains(key, StringComparer.Ordinal));
}
