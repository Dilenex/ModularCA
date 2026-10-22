using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Thrown when any sign-in path is asked to mint a token for a service identity. A service
/// identity holds permissions and nothing else; it has no password, no second factor and no
/// session, so this is a programming error at the call site, not a user error.
/// </summary>
public sealed class ServiceIdentityCannotSignInException()
    : InvalidOperationException("A service identity cannot sign in; it only holds permissions.");

/// <summary>
/// Where a service identity lives and who may manage it: the system (both null), one space, or
/// one CA. Managing it needs <c>ca.manage</c> at that scope or above, and its groups must lie
/// within the scope, so a CA administrator can only ever create an identity that is confined to
/// their CA.
/// </summary>
public sealed record ServiceIdentityScope(Guid? SpaceId, Guid? CaId)
{
    public static readonly ServiceIdentityScope System = new(null, null);
    public bool IsSystem => SpaceId == null && CaId == null;
}

/// <summary>What a caller asks for when creating a service identity.</summary>
public sealed record ServiceIdentitySpec(
    string Username,
    string? DisplayName,
    string? Description,
    ServiceIdentityScope Scope,
    IReadOnlyList<Guid> GroupIds);

/// <summary>
/// Service identities: user rows that hold group memberships and capability grants for a
/// non-person caller such as a Kerberos realm binding, and that can never sign in. Every
/// existing authorization check works on them unchanged because they are users; every sign-in
/// path refuses them because <see cref="UserEntity.IsServiceIdentity"/> is set. Disabling or
/// deleting one, or taking it out of a group, revokes SSH certificates issued for it as for any
/// user, through <paramref name="sshLoginNames"/>.
/// </summary>
public sealed class ServiceIdentityService(ModularCADbContext db, ICaGroupAuthorizationService auth, IControlledUserCeremonyService? controlledUsers = null,
    ModularCA.Shared.Interfaces.ISshLoginNameService? sshLoginNames = null)
{
    /// <summary>The synthetic mail domain given to service identities, which have no mailbox.</summary>
    public const string MailDomain = "service-identity.invalid";

    /// <summary>
    /// Whether the caller may create, change or delete an identity of <paramref name="scope"/>:
    /// <c>system.manage</c> anywhere; <c>ca.manage</c> at system scope for a system identity;
    /// space-wide <c>ca.manage</c> for a space identity; <c>ca.manage</c> on the CA for a CA
    /// identity (space-wide and system holders pass that check too).
    /// </summary>
    public async Task<bool> MayManageAsync(Guid callerId, ServiceIdentityScope scope)
    {
        if (await auth.IsSystemAdminAsync(callerId)) return true;
        if (scope.IsSystem) return await auth.HasSystemCapabilityAsync(callerId, Capabilities.CaManage);
        if (scope.CaId is Guid caId) return await auth.HasCaCapabilityAsync(callerId, caId, Capabilities.CaManage);
        return await auth.HasSpaceCapabilityAsync(callerId, scope.SpaceId!.Value, Capabilities.CaManage);
    }

    /// <summary>
    /// Whether a group may be held by an identity of <paramref name="scope"/>. Never a system
    /// group and never an instance group (<paramref name="groupIsInstance"/>: no space, as the
    /// system signing CA's and the SSH CAs' groups, which were the system tenant's before 0.4.0): a service
    /// identity cannot be given system-tier rights by any route. A CA-scoped group fits a system
    /// identity, an identity of the group's space, or an identity of that CA. A space-wide group
    /// fits a system identity or an identity of that space.
    /// </summary>
    public static bool GroupFitsScope(CaGroupEntity group, ServiceIdentityScope scope, bool groupIsInstance)
    {
        if (group.IsSystemGroup || group.IsSystemTierSuper || groupIsInstance || group.SpaceId == null) return false;
        if (scope.IsSystem) return true;
        if (group.CertificateAuthorityId is Guid groupCa)
            return scope.CaId == groupCa || (scope.CaId == null && scope.SpaceId == group.SpaceId);
        return scope.CaId == null && scope.SpaceId == group.SpaceId;
    }

    /// <summary>The identities the caller may manage, with their groups, ordered by username.</summary>
    public async Task<List<UserEntity>> ListAsync(Guid callerId)
    {
        var query = db.Users.AsNoTracking()
            .Include(u => u.GroupMemberships).ThenInclude(m => m.Group)
            .Where(u => u.IsServiceIdentity);

        if (!await auth.IsSystemAdminAsync(callerId) && !await auth.HasSystemCapabilityAsync(callerId, Capabilities.CaManage))
        {
            var spaces = await auth.GetSpaceIdsWithCapabilityAsync(callerId, Capabilities.CaManage);
            var cas = await auth.GetAccessibleCaIdsAsync(callerId, Capabilities.CaManage);
            var spaceCas = await db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.SpaceId != null && spaces.Contains(ca.SpaceId.Value)).Select(ca => ca.Id).ToListAsync();
            var visibleCas = cas.Concat(spaceCas).Distinct().ToList();
            query = query.Where(u =>
                (u.ServiceScopeCaId != null && visibleCas.Contains(u.ServiceScopeCaId.Value))
                || (u.ServiceScopeCaId == null && u.ServiceScopeSpaceId != null && spaces.Contains(u.ServiceScopeSpaceId.Value)));
        }

        return await query.OrderBy(u => u.Username).ToListAsync();
    }

    /// <summary>One identity with its groups, or null when it does not exist or is not a service identity.</summary>
    public Task<UserEntity?> GetAsync(Guid id)
        => db.Users.AsNoTracking().Include(u => u.GroupMemberships).ThenInclude(m => m.Group)
            .FirstOrDefaultAsync(u => u.Id == id && u.IsServiceIdentity);

    /// <summary>Creates an identity in the caller's scope with the requested groups. No password is ever set. Controlled groups need system-super.</summary>
    public async Task<UserEntity> CreateAsync(Guid callerId, ServiceIdentitySpec spec)
    {
        var username = NormalizeUsername(spec.Username);
        var scope = await NormalizeScopeAsync(spec.Scope);
        if (!await MayManageAsync(callerId, scope))
            throw new UnauthorizedAccessException("You need ca.manage at the identity's scope.");
        if (await db.Users.AnyAsync(u => u.Username == username))
            throw new InvalidOperationException($"Username '{username}' is taken.");

        var groups = await AssignableGroupsAsync(callerId, scope, spec.GroupIds);
        await EnsureMayChangeControlledMembershipAsync(callerId, groups);

        var user = new UserEntity
        {
            Username = username,
            Email = $"{username}@{MailDomain}",
            DisplayName = string.IsNullOrWhiteSpace(spec.DisplayName) ? username : spec.DisplayName.Trim(),
            Description = spec.Description?.Trim(),
            IsServiceIdentity = true,
            ServiceScopeSpaceId = scope.SpaceId,
            ServiceScopeCaId = scope.CaId,
            PasswordHash = string.Empty,
            PasswordNeverExpires = true,
            PasswordExpirationDate = null,
            PasswordChangeOnNextLogon = false,
            IsActive = true,
        };
        db.Users.Add(user);
        foreach (var g in groups)
            db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = g.Id, UserId = user.Id, AddedByUserId = callerId });
        await db.SaveChangesAsync();
        return user;
    }

    /// <summary>
    /// Changes the display name, description and active flag. Scope and username are fixed.
    /// Disabling the identity revokes every live SSH certificate issued for it.
    /// </summary>
    public async Task<UserEntity> UpdateAsync(Guid callerId, Guid id, string? displayName, string? description, bool isActive)
    {
        var user = await LoadAsync(id);
        if (!await MayManageAsync(callerId, ScopeOf(user)))
            throw new UnauthorizedAccessException("You need ca.manage at the identity's scope.");
        var wasActive = user.IsActive;
        user.DisplayName = string.IsNullOrWhiteSpace(displayName) ? user.Username : displayName.Trim();
        user.Description = description?.Trim();
        user.IsActive = isActive;
        await db.SaveChangesAsync();
        if (wasActive && !isActive && sshLoginNames != null)
            await sshLoginNames.RevokeAllOfUserAsync(id, "the user was disabled");
        return user;
    }

    /// <summary>
    /// Replaces the identity's group memberships. Every group added or removed must fit the
    /// identity's scope and be one the caller administers; adding or removing a controlled group
    /// needs system-super. SSH certificates that carried a login name the identity held through a
    /// group it leaves are revoked.
    /// </summary>
    public async Task<UserEntity> SetGroupsAsync(Guid callerId, Guid id, IReadOnlyList<Guid> groupIds)
    {
        var user = await LoadAsync(id);
        var scope = ScopeOf(user);
        if (!await MayManageAsync(callerId, scope))
            throw new UnauthorizedAccessException("You need ca.manage at the identity's scope.");

        var wanted = await AssignableGroupsAsync(callerId, scope, groupIds);
        var wantedIds = wanted.Select(g => g.Id).ToHashSet();
        var current = await db.CaGroupMembers.Include(m => m.Group).Where(m => m.UserId == id).ToListAsync();
        var currentIds = current.Select(m => m.GroupId).ToHashSet();
        await EnsureMayChangeControlledMembershipAsync(callerId,
            current.Where(m => !wantedIds.Contains(m.GroupId) && m.Group != null).Select(m => m.Group!)
                .Concat(wanted.Where(g => !currentIds.Contains(g.Id))));

        var left = false;
        foreach (var m in current.Where(m => !wantedIds.Contains(m.GroupId)))
        {
            if (m.Group != null && !await MayAssignGroupAsync(callerId, m.Group))
                throw new UnauthorizedAccessException($"You cannot remove membership of '{m.Group.DisplayName}'.");
            db.CaGroupMembers.Remove(m);
            left = true;
        }
        foreach (var g in wanted.Where(g => !currentIds.Contains(g.Id)))
            db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = g.Id, UserId = id, AddedByUserId = callerId });

        await db.SaveChangesAsync();
        if (left && sshLoginNames != null)
            await sshLoginNames.ReconcileUsersAsync([id], "the user left a group");
        return (await GetAsync(id))!;
    }

    /// <summary>
    /// Deletes the identity. Refused while a Kerberos realm binding acts as it, and for non-super
    /// callers while it holds a controlled group. Every live SSH certificate issued for it is
    /// revoked first, and the SSH login names granted to it are removed.
    /// </summary>
    public async Task DeleteAsync(Guid callerId, Guid id)
    {
        var user = await LoadAsync(id);
        if (!await MayManageAsync(callerId, ScopeOf(user)))
            throw new UnauthorizedAccessException("You need ca.manage at the identity's scope.");
        var realms = await db.KerberosRealms.Where(r => r.EnrollmentUserId == id).Select(r => r.Realm).ToListAsync();
        if (realms.Count > 0)
            throw new InvalidOperationException($"Kerberos realm {string.Join(", ", realms)} acts as this identity; point the realm elsewhere first.");
        var memberships = await db.CaGroupMembers.Include(m => m.Group).Where(m => m.UserId == id).ToListAsync();
        await EnsureMayChangeControlledMembershipAsync(callerId, memberships.Where(m => m.Group != null).Select(m => m.Group!));
        if (sshLoginNames != null)
            await sshLoginNames.UserDeletingAsync(id);
        db.CaGroupMembers.RemoveRange(memberships);
        db.Users.Remove(user);
        await db.SaveChangesAsync();
    }

    /// <summary>The scope an existing identity was created with.</summary>
    public static ServiceIdentityScope ScopeOf(UserEntity user) => new(user.ServiceScopeSpaceId, user.ServiceScopeCaId);

    // ── Internals ──

    private async Task<UserEntity> LoadAsync(Guid id)
        => await db.Users.FirstOrDefaultAsync(u => u.Id == id && u.IsServiceIdentity)
            ?? throw new KeyNotFoundException("Service identity not found.");

    /// <summary>A CA scope carries its space; a space scope must name a real space. A deleted CA or space is refused.</summary>
    private async Task<ServiceIdentityScope> NormalizeScopeAsync(ServiceIdentityScope scope)
    {
        if (scope.CaId is Guid caId)
        {
            var ca = await db.CertificateAuthorities.AsNoTracking()
                .Where(c => c.Id == caId).Select(c => new { c.SpaceId }).FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("The CA does not exist.");
            return new ServiceIdentityScope(ca.SpaceId, caId);
        }
        if (scope.SpaceId is Guid spaceId && !await db.Spaces.AnyAsync(t => t.Id == spaceId))
            throw new InvalidOperationException("The space does not exist.");
        return scope;
    }

    /// <summary>The groups a caller may put an identity of this scope into: each must fit the scope and be administered by the caller.</summary>
    private async Task<List<CaGroupEntity>> AssignableGroupsAsync(Guid callerId, ServiceIdentityScope scope, IReadOnlyList<Guid> groupIds)
    {
        var ids = groupIds.Distinct().ToList();
        var groups = await db.CaGroups.Where(g => ids.Contains(g.Id)).ToListAsync();
        if (groups.Count != ids.Count)
            throw new InvalidOperationException("A requested group does not exist.");
        foreach (var g in groups)
        {
            if (!GroupFitsScope(g, scope, g.SpaceId == null))
                throw new InvalidOperationException($"Group '{g.DisplayName}' is outside the identity's scope.");
            if (!await MayAssignGroupAsync(callerId, g))
                throw new UnauthorizedAccessException($"You do not administer group '{g.DisplayName}'.");
        }
        return groups;
    }

    /// <summary>
    /// Adding an identity to, or removing it from, a privilege-controlled group (structure or
    /// capability, see <see cref="ControlledTierResolver.ClassifyGroupAsync"/>) is reserved to
    /// system-super (as the caller's worn badge allows); anyone else is refused with <see cref="UnauthorizedAccessException"/>. Service
    /// identities have no ceremony path.
    /// </summary>
    private async Task EnsureMayChangeControlledMembershipAsync(Guid callerId, IEnumerable<CaGroupEntity> changedGroups)
    {
        CaGroupEntity? controlled = null;
        foreach (var g in changedGroups)
        {
            if (await ControlledTierResolver.ClassifyGroupAsync(db, g) != null) { controlled = g; break; }
        }
        if (controlled == null) return;
        var isSuper = controlledUsers != null
            ? await controlledUsers.IsSuperAsync(callerId)
            : await db.CaGroupMembers.AnyAsync(m => m.UserId == callerId && m.Group.IsSystemTierSuper);
        if (isSuper) return;
        throw new UnauthorizedAccessException(
            $"Group '{controlled.DisplayName}' confers a privileged tier; only a system-super can add a service identity to it, remove one from it, or delete an identity that holds it.");
    }

    /// <summary>System groups are never assignable here; otherwise ca.manage on the group's CA, or space-wide for its space.</summary>
    private async Task<bool> MayAssignGroupAsync(Guid callerId, CaGroupEntity group)
    {
        if (group.IsSystemGroup) return false;
        if (await auth.IsSystemAdminAsync(callerId)) return true;
        if (group.CertificateAuthorityId is Guid caId)
            return await auth.HasCaCapabilityAsync(callerId, caId, Capabilities.CaManage);
        return group.SpaceId is Guid spaceId
            && await auth.HasSpaceCapabilityAsync(callerId, spaceId, Capabilities.CaManage);
    }

    internal static string NormalizeUsername(string username)
    {
        var u = (username ?? string.Empty).Trim();
        if (u.Length < 3 || u.Length > 64 || u.Any(c => char.IsWhiteSpace(c) || c == '@'))
            throw new InvalidOperationException("Username must be 3 to 64 characters with no spaces or '@'.");
        return u;
    }
}
