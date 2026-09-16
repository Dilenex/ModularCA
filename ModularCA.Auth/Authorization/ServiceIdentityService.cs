using Microsoft.EntityFrameworkCore;
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
/// Where a service identity lives and who may manage it: the system (both null), one tenant, or
/// one CA. Managing it needs <c>ca.manage</c> at that scope or above, and its groups must lie
/// within the scope, so a CA administrator can only ever create an identity that is confined to
/// their CA.
/// </summary>
public sealed record ServiceIdentityScope(Guid? TenantId, Guid? CaId)
{
    public static readonly ServiceIdentityScope System = new(null, null);
    public bool IsSystem => TenantId == null && CaId == null;
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
/// path refuses them because <see cref="UserEntity.IsServiceIdentity"/> is set.
/// </summary>
public sealed class ServiceIdentityService(ModularCADbContext db, ICaGroupAuthorizationService auth)
{
    /// <summary>The synthetic mail domain given to service identities, which have no mailbox.</summary>
    public const string MailDomain = "service-identity.invalid";

    /// <summary>
    /// Whether the caller may create, change or delete an identity of <paramref name="scope"/>:
    /// <c>system.manage</c> anywhere; <c>ca.manage</c> at system scope for a system identity;
    /// tenant-wide <c>ca.manage</c> for a tenant identity; <c>ca.manage</c> on the CA for a CA
    /// identity (tenant-wide and system holders pass that check too).
    /// </summary>
    public async Task<bool> MayManageAsync(Guid callerId, ServiceIdentityScope scope)
    {
        if (await auth.IsSystemAdminAsync(callerId)) return true;
        if (scope.IsSystem) return await auth.HasSystemCapabilityAsync(callerId, Capabilities.CaManage);
        if (scope.CaId is Guid caId) return await auth.HasCaCapabilityAsync(callerId, caId, Capabilities.CaManage);
        return await auth.HasTenantCapabilityAsync(callerId, scope.TenantId!.Value, Capabilities.CaManage);
    }

    /// <summary>
    /// Whether a group may be held by an identity of <paramref name="scope"/>. Never a system
    /// group and never a group of the System tenant (its CAs are system infrastructure): a
    /// service identity cannot be given system-tier rights by any route. A CA-scoped group fits
    /// a system identity, an identity of the group's tenant, or an identity of that CA. A
    /// tenant-wide group fits a system identity or an identity of that tenant.
    /// </summary>
    public static bool GroupFitsScope(CaGroupEntity group, ServiceIdentityScope scope, bool groupTenantIsSystem)
    {
        if (group.IsSystemGroup || group.IsSystemTierSuper || groupTenantIsSystem) return false;
        if (scope.IsSystem) return true;
        if (group.CertificateAuthorityId is Guid groupCa)
            return scope.CaId == groupCa || (scope.CaId == null && scope.TenantId == group.TenantId);
        return scope.CaId == null && scope.TenantId == group.TenantId;
    }

    /// <summary>The identities the caller may manage, with their groups, ordered by username.</summary>
    public async Task<List<UserEntity>> ListAsync(Guid callerId)
    {
        var query = db.Users.AsNoTracking()
            .Include(u => u.GroupMemberships).ThenInclude(m => m.Group)
            .Where(u => u.IsServiceIdentity);

        if (!await auth.IsSystemAdminAsync(callerId) && !await auth.HasSystemCapabilityAsync(callerId, Capabilities.CaManage))
        {
            var tenants = await auth.GetTenantIdsWithCapabilityAsync(callerId, Capabilities.CaManage);
            var cas = await auth.GetAccessibleCaIdsAsync(callerId, Capabilities.CaManage);
            var tenantCas = await db.CertificateAuthorities.AsNoTracking().IgnoreQueryFilters()
                .Where(ca => tenants.Contains(ca.TenantId)).Select(ca => ca.Id).ToListAsync();
            var visibleCas = cas.Concat(tenantCas).Distinct().ToList();
            query = query.Where(u =>
                (u.ServiceScopeCaId != null && visibleCas.Contains(u.ServiceScopeCaId.Value))
                || (u.ServiceScopeCaId == null && u.ServiceScopeTenantId != null && tenants.Contains(u.ServiceScopeTenantId.Value)));
        }

        return await query.OrderBy(u => u.Username).ToListAsync();
    }

    /// <summary>One identity with its groups, or null when it does not exist or is not a service identity.</summary>
    public Task<UserEntity?> GetAsync(Guid id)
        => db.Users.AsNoTracking().Include(u => u.GroupMemberships).ThenInclude(m => m.Group)
            .FirstOrDefaultAsync(u => u.Id == id && u.IsServiceIdentity);

    /// <summary>Creates an identity in the caller's scope with the requested groups. No password is ever set.</summary>
    public async Task<UserEntity> CreateAsync(Guid callerId, ServiceIdentitySpec spec)
    {
        var username = NormalizeUsername(spec.Username);
        var scope = await NormalizeScopeAsync(spec.Scope);
        if (!await MayManageAsync(callerId, scope))
            throw new UnauthorizedAccessException("You need ca.manage at the identity's scope.");
        if (await db.Users.AnyAsync(u => u.Username == username))
            throw new InvalidOperationException($"Username '{username}' is taken.");

        var groups = await AssignableGroupsAsync(callerId, scope, spec.GroupIds);

        var user = new UserEntity
        {
            Username = username,
            Email = $"{username}@{MailDomain}",
            DisplayName = string.IsNullOrWhiteSpace(spec.DisplayName) ? username : spec.DisplayName.Trim(),
            Description = spec.Description?.Trim(),
            IsServiceIdentity = true,
            ServiceScopeTenantId = scope.TenantId,
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

    /// <summary>Changes the display name, description and active flag. Scope and username are fixed.</summary>
    public async Task<UserEntity> UpdateAsync(Guid callerId, Guid id, string? displayName, string? description, bool isActive)
    {
        var user = await LoadAsync(id);
        if (!await MayManageAsync(callerId, ScopeOf(user)))
            throw new UnauthorizedAccessException("You need ca.manage at the identity's scope.");
        user.DisplayName = string.IsNullOrWhiteSpace(displayName) ? user.Username : displayName.Trim();
        user.Description = description?.Trim();
        user.IsActive = isActive;
        await db.SaveChangesAsync();
        return user;
    }

    /// <summary>
    /// Replaces the identity's group memberships. Every group added or removed must fit the
    /// identity's scope and be one the caller administers.
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

        foreach (var m in current.Where(m => !wantedIds.Contains(m.GroupId)))
        {
            if (m.Group != null && !await MayAssignGroupAsync(callerId, m.Group))
                throw new UnauthorizedAccessException($"You cannot remove membership of '{m.Group.DisplayName}'.");
            db.CaGroupMembers.Remove(m);
        }
        var currentIds = current.Select(m => m.GroupId).ToHashSet();
        foreach (var g in wanted.Where(g => !currentIds.Contains(g.Id)))
            db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = g.Id, UserId = id, AddedByUserId = callerId });

        await db.SaveChangesAsync();
        return (await GetAsync(id))!;
    }

    /// <summary>Deletes the identity. Refused while a Kerberos realm binding acts as it.</summary>
    public async Task DeleteAsync(Guid callerId, Guid id)
    {
        var user = await LoadAsync(id);
        if (!await MayManageAsync(callerId, ScopeOf(user)))
            throw new UnauthorizedAccessException("You need ca.manage at the identity's scope.");
        var realms = await db.KerberosRealms.Where(r => r.EnrollmentUserId == id).Select(r => r.Realm).ToListAsync();
        if (realms.Count > 0)
            throw new InvalidOperationException($"Kerberos realm {string.Join(", ", realms)} acts as this identity; point the realm elsewhere first.");
        var memberships = await db.CaGroupMembers.Where(m => m.UserId == id).ToListAsync();
        db.CaGroupMembers.RemoveRange(memberships);
        db.Users.Remove(user);
        await db.SaveChangesAsync();
    }

    /// <summary>The scope an existing identity was created with.</summary>
    public static ServiceIdentityScope ScopeOf(UserEntity user) => new(user.ServiceScopeTenantId, user.ServiceScopeCaId);

    // ── Internals ──

    private async Task<UserEntity> LoadAsync(Guid id)
        => await db.Users.FirstOrDefaultAsync(u => u.Id == id && u.IsServiceIdentity)
            ?? throw new KeyNotFoundException("Service identity not found.");

    /// <summary>A CA scope carries its tenant; a tenant scope must name a real tenant.</summary>
    private async Task<ServiceIdentityScope> NormalizeScopeAsync(ServiceIdentityScope scope)
    {
        if (scope.CaId is Guid caId)
        {
            var ca = await db.CertificateAuthorities.AsNoTracking().IgnoreQueryFilters()
                .Where(c => c.Id == caId).Select(c => new { c.TenantId }).FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("The CA does not exist.");
            return new ServiceIdentityScope(ca.TenantId, caId);
        }
        if (scope.TenantId is Guid tenantId && !await db.Tenants.IgnoreQueryFilters().AnyAsync(t => t.Id == tenantId))
            throw new InvalidOperationException("The tenant does not exist.");
        return scope;
    }

    /// <summary>The groups a caller may put an identity of this scope into: each must fit the scope and be administered by the caller.</summary>
    private async Task<List<CaGroupEntity>> AssignableGroupsAsync(Guid callerId, ServiceIdentityScope scope, IReadOnlyList<Guid> groupIds)
    {
        var ids = groupIds.Distinct().ToList();
        var groups = await db.CaGroups.Where(g => ids.Contains(g.Id)).ToListAsync();
        if (groups.Count != ids.Count)
            throw new InvalidOperationException("A requested group does not exist.");
        var systemTenants = await db.Tenants.IgnoreQueryFilters().Where(t => t.IsSystemTenant).Select(t => t.Id).ToListAsync();
        foreach (var g in groups)
        {
            if (!GroupFitsScope(g, scope, systemTenants.Contains(g.TenantId)))
                throw new InvalidOperationException($"Group '{g.DisplayName}' is outside the identity's scope.");
            if (!await MayAssignGroupAsync(callerId, g))
                throw new UnauthorizedAccessException($"You do not administer group '{g.DisplayName}'.");
        }
        return groups;
    }

    /// <summary>System groups are never assignable here; otherwise ca.manage on the group's CA, or tenant-wide for its tenant.</summary>
    private async Task<bool> MayAssignGroupAsync(Guid callerId, CaGroupEntity group)
    {
        if (group.IsSystemGroup) return false;
        if (await auth.IsSystemAdminAsync(callerId)) return true;
        if (group.CertificateAuthorityId is Guid caId)
            return await auth.HasCaCapabilityAsync(callerId, caId, Capabilities.CaManage);
        return await auth.HasTenantCapabilityAsync(callerId, group.TenantId, Capabilities.CaManage);
    }

    internal static string NormalizeUsername(string username)
    {
        var u = (username ?? string.Empty).Trim();
        if (u.Length < 3 || u.Length > 64 || u.Any(c => char.IsWhiteSpace(c) || c == '@'))
            throw new InvalidOperationException("Username must be 3 to 64 characters with no spaces or '@'.");
        return u;
    }
}
