using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// EF Core implementation of the capability-based authorization resolver.
/// Checks four grant sources for each capability query:
/// 1. Direct group grants (CapabilityGrants via group membership)
/// 2. Role grants via group (RoleAssignments on groups → RoleCapabilities)
/// 3. Direct user grants (UserCapabilityGrants)
/// 4. Role grants via user (RoleAssignments on user → RoleCapabilities)
/// </summary>
public class CaGroupAuthorizationService : ICaGroupAuthorizationService
{
    private readonly ModularCADbContext _db;
    private readonly ILogger<CaGroupAuthorizationService> _logger;
    private readonly IAuditService? _audit;
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public CaGroupAuthorizationService(
        ModularCADbContext db,
        ILogger<CaGroupAuthorizationService> logger,
        IAuditService? audit = null,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _db = db;
        _logger = logger;
        _audit = audit;
        _httpContextAccessor = httpContextAccessor;
    }

    // ── Helpers: check a single capability across all 4 sources ──

    /// <summary>
    /// Checks if the user has the capability via any system group (direct grant or role).
    /// </summary>
    private async Task<bool> HasCapabilityViaSystemGroupsAsync(Guid userId, string capability)
    {
        // Source 1: direct group grants
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.IsSystemGroup
                && g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == capability
                && g.ResourceType == null))
            return true;

        // Source 2: role grants via system group
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.IsSystemGroup
                && ra.Group.Members.Any(m => m.UserId == userId)
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)))
            return true;

        return false;
    }

    /// <summary>
    /// Checks if the user has the capability via direct user grants or user role assignments
    /// that match the given scope (global, tenant, or CA).
    /// </summary>
    private async Task<bool> HasCapabilityViaUserGrantsAsync(Guid userId, string capability, Guid? tenantId, Guid? caId)
    {
        // Source 3: direct user grants — match global, tenant, or CA scope
        if (await _db.UserCapabilityGrants
            .AnyAsync(ug => ug.UserId == userId
                && ug.Capability == capability
                && ug.ResourceType == null
                && (
                    // Global grant
                    (ug.TenantId == null && ug.CertificateAuthorityId == null)
                    // Tenant grant (if tenantId known)
                    || (tenantId != null && ug.TenantId == tenantId && ug.CertificateAuthorityId == null)
                    // CA grant (if caId known)
                    || (caId != null && ug.CertificateAuthorityId == caId)
                )))
            return true;

        // Source 4: role grants via user role assignments — match scope
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.UserId == userId
                && ra.GroupId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)
                && (
                    // Global assignment
                    (ra.TenantId == null && ra.CertificateAuthorityId == null)
                    // Tenant assignment
                    || (tenantId != null && ra.TenantId == tenantId && ra.CertificateAuthorityId == null)
                    // CA assignment
                    || (caId != null && ra.CertificateAuthorityId == caId)
                )))
            return true;

        return false;
    }

    // ── Public API ──

    /// <inheritdoc />
    public async Task<bool> HasSystemCapabilityAsync(Guid userId, string capability)
    {
        // System group grants + roles
        if (await HasCapabilityViaSystemGroupsAsync(userId, capability))
            return true;

        // User-level grants with global scope
        return await HasCapabilityViaUserGrantsAsync(userId, capability, tenantId: null, caId: null);
    }

    /// <inheritdoc />
    public async Task<bool> HasCaCapabilityAsync(Guid userId, Guid caId, string capability)
    {
        // system.manage holders bypass all CA-scoped checks
        if (await IsSystemAdminAsync(userId))
        {
            _logger.LogDebug(
                "System admin {UserId} accessing CA {CaId} via system.manage bypass (capability: {Capability})",
                userId, caId, capability);

            // Emit SystemAdminElevatedAccess when the bypass is
            // actually load-bearing — i.e. the user is NOT already a member of a
            // CA-scoped group that would have granted the capability. Otherwise
            // every request from a system admin that would have passed normal
            // RBAC would also flood the audit log. We still emit when the user
            // holds system.manage but has no direct CA group membership, which
            // is the forensically meaningful case: "admin reached into a CA they
            // don't belong to."
            var isDirectCaMember = await _db.CaGroupMembers
                .AnyAsync(m => m.UserId == userId
                    && (m.Group.CertificateAuthorityId == caId || m.Group.IsSystemGroup));
            if (!isDirectCaMember && _audit != null)
            {
                var httpContext = _httpContextAccessor?.HttpContext;
                var username = await _db.Users
                    .Where(u => u.Id == userId)
                    .Select(u => u.Username)
                    .FirstOrDefaultAsync();
                var targetCa = await _db.CertificateAuthorities.FindAsync(caId);
                try
                {
                    await _audit.LogAsync(
                        AuditActionType.SystemAdminElevatedAccess,
                        actorUserId: userId,
                        actorUsername: username,
                        targetEntityType: "CertificateAuthority",
                        targetEntityId: caId.ToString(),
                        sourceIp: httpContext?.Connection.RemoteIpAddress?.ToString(),
                        details: new
                        {
                            Capability = capability,
                            CaLabel = targetCa?.Label,
                            Path = httpContext?.Request.Path.Value,
                            Method = httpContext?.Request.Method,
                        },
                        certificateAuthorityId: caId,
                        tenantId: targetCa?.TenantId);
                }
                catch (Exception ex)
                {
                    // Audit failure must not block the bypass itself (the audit
                    // layer is already responsible for its own fail-closed policy
                    // via IsSecurityCriticalAction). Log and continue.
                    _logger.LogWarning(ex, "Failed to record SystemAdminElevatedAccess audit event for user {UserId} on CA {CaId}", userId, caId);
                }
            }

            return true;
        }

        var ca = await _db.CertificateAuthorities.FindAsync(caId);
        var tenantId = ca?.TenantId;

        // Source 1: direct group grants (system, tenant, CA-scoped)
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == capability
                && g.ResourceType == null
                && (
                    g.Group.IsSystemGroup
                    || g.Group.CertificateAuthorityId == caId
                    || (tenantId != null && g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup && g.Group.TenantId == tenantId)
                )))
            return true;

        // Source 2: role grants via group membership
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.Members.Any(m => m.UserId == userId)
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)
                && (
                    ra.Group.IsSystemGroup
                    || ra.Group.CertificateAuthorityId == caId
                    || (tenantId != null && ra.Group.CertificateAuthorityId == null && !ra.Group.IsSystemGroup && ra.Group.TenantId == tenantId)
                )))
            return true;

        // Sources 3+4: user grants and user role assignments
        return await HasCapabilityViaUserGrantsAsync(userId, capability, tenantId, caId);
    }

    /// <inheritdoc />
    public async Task<bool> IsSystemAdminAsync(Guid userId)
    {
        // Direct group grant
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.IsSystemGroup
                && g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == Capabilities.SystemManage
                && g.ResourceType == null))
            return true;

        // Role via system group
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.IsSystemGroup
                && ra.Group.Members.Any(m => m.UserId == userId)
                && ra.Role.Capabilities.Any(rc => rc.Capability == Capabilities.SystemManage && rc.ResourceType == null)))
            return true;

        // Direct user grant (global scope)
        if (await _db.UserCapabilityGrants
            .AnyAsync(ug => ug.UserId == userId
                && ug.Capability == Capabilities.SystemManage
                && ug.TenantId == null && ug.CertificateAuthorityId == null
                && ug.ResourceType == null))
            return true;

        // User role assignment (global scope)
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.UserId == userId
                && ra.GroupId == null
                && ra.TenantId == null && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == Capabilities.SystemManage && rc.ResourceType == null)))
            return true;

        return false;
    }

    /// <inheritdoc />
    public async Task<List<CaGroupEntity>> GetUserGroupsAsync(Guid userId)
    {
        return await _db.CaGroupMembers
            .Where(gm => gm.UserId == userId)
            .Select(gm => gm.Group)
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<EffectiveCapabilities> GetEffectiveCapabilitiesAsync(Guid userId)
    {
        // Load the user's grant sources once and fold them in memory. The per-capability
        // checks above each run several queries; walking them per capability per CA would be
        // hundreds of round trips for one page load.
        var memberGroupIds = await _db.CaGroupMembers
            .AsNoTracking()
            .Where(m => m.UserId == userId)
            .Select(m => m.GroupId)
            .ToListAsync();

        var groups = await _db.CaGroups
            .AsNoTracking()
            .Where(g => memberGroupIds.Contains(g.Id))
            .Select(g => new { g.Id, g.IsSystemGroup, g.CertificateAuthorityId, g.TenantId })
            .ToListAsync();
        var groupById = groups.ToDictionary(g => g.Id);

        // (capability, scope) pairs. Scope is one of: system, a tenant, or a CA.
        var systemCaps = new HashSet<string>(StringComparer.Ordinal);
        var tenantCaps = new Dictionary<Guid, HashSet<string>>();
        var caCaps = new Dictionary<Guid, HashSet<string>>();

        void AddGroupScoped(Guid groupId, string capability)
        {
            if (!groupById.TryGetValue(groupId, out var g)) return;
            if (g.IsSystemGroup) systemCaps.Add(capability);
            else if (g.CertificateAuthorityId is Guid caId) Bucket(caCaps, caId).Add(capability);
            else Bucket(tenantCaps, g.TenantId).Add(capability);
        }

        void AddUserScoped(string capability, Guid? tenantId, Guid? certificateAuthorityId)
        {
            if (certificateAuthorityId is Guid caId) Bucket(caCaps, caId).Add(capability);
            else if (tenantId is Guid tid) Bucket(tenantCaps, tid).Add(capability);
            else systemCaps.Add(capability);
        }

        // Source 1: direct group grants.
        var groupGrants = await _db.CapabilityGrants
            .AsNoTracking()
            .Where(g => memberGroupIds.Contains(g.GroupId) && g.ResourceType == null)
            .Select(g => new { g.GroupId, g.Capability })
            .ToListAsync();
        foreach (var g in groupGrants) AddGroupScoped(g.GroupId, g.Capability);

        // Source 2: roles assigned to the user's groups.
        var groupRoles = await _db.RoleAssignments
            .AsNoTracking()
            .Include(ra => ra.Role).ThenInclude(r => r.Capabilities)
            .Where(ra => ra.GroupId != null && memberGroupIds.Contains(ra.GroupId.Value))
            .ToListAsync();
        foreach (var ra in groupRoles)
            foreach (var rc in ra.Role.Capabilities.Where(rc => rc.ResourceType == null))
                AddGroupScoped(ra.GroupId!.Value, rc.Capability);

        // Source 3: grants on the user directly, at global, tenant or CA scope.
        var userGrants = await _db.UserCapabilityGrants
            .AsNoTracking()
            .Where(ug => ug.UserId == userId && ug.ResourceType == null)
            .Select(ug => new { ug.Capability, ug.TenantId, ug.CertificateAuthorityId })
            .ToListAsync();
        foreach (var ug in userGrants) AddUserScoped(ug.Capability, ug.TenantId, ug.CertificateAuthorityId);

        // Source 4: roles assigned to the user directly, at global, tenant or CA scope.
        var userRoles = await _db.RoleAssignments
            .AsNoTracking()
            .Include(ra => ra.Role).ThenInclude(r => r.Capabilities)
            .Where(ra => ra.UserId == userId && ra.GroupId == null)
            .ToListAsync();
        foreach (var ra in userRoles)
            foreach (var rc in ra.Role.Capabilities.Where(rc => rc.ResourceType == null))
                AddUserScoped(rc.Capability, ra.TenantId, ra.CertificateAuthorityId);

        // system.manage at system scope passes every check (see HasCaCapabilityAsync), so
        // report it as everything rather than as the literal grants.
        if (systemCaps.Contains(Capabilities.SystemManage))
            systemCaps.UnionWith(Capabilities.All);

        var cas = await _db.CertificateAuthorities
            .AsNoTracking()
            .Select(ca => new { ca.Id, ca.Label, ca.Name, ca.IsSshCa, ca.TenantId })
            .ToListAsync();

        var perCa = new List<CaCapabilities>();
        foreach (var ca in cas)
        {
            var caps = new HashSet<string>(systemCaps, StringComparer.Ordinal);
            if (tenantCaps.TryGetValue(ca.TenantId, out var t)) caps.UnionWith(t);
            if (caCaps.TryGetValue(ca.Id, out var c)) caps.UnionWith(c);
            if (caps.Count == 0) continue;
            perCa.Add(new CaCapabilities(ca.Id, ca.Label ?? string.Empty, ca.Name, ca.IsSshCa,
                caps.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        return new EffectiveCapabilities(
            systemCaps.OrderBy(x => x, StringComparer.Ordinal).ToList(),
            perCa.OrderBy(x => x.Label, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToList());

        static HashSet<string> Bucket(Dictionary<Guid, HashSet<string>> map, Guid key)
        {
            if (!map.TryGetValue(key, out var set))
            {
                set = new HashSet<string>(StringComparer.Ordinal);
                map[key] = set;
            }
            return set;
        }
    }

    /// <inheritdoc />
    public async Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability)
    {
        if (await IsSystemAdminAsync(userId))
        {
            return await _db.CertificateAuthorities.Select(ca => ca.Id).ToListAsync();
        }

        // System-level capability → all CAs
        if (await HasSystemCapabilityAsync(userId, capability))
        {
            return await _db.CertificateAuthorities.Select(ca => ca.Id).ToListAsync();
        }

        var caIds = new HashSet<Guid>();

        // Tenant-level group grants → all CAs in those tenants
        var tenantIdsFromGroups = await _db.CapabilityGrants
            .Where(g => g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup
                && g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == capability && g.ResourceType == null)
            .Select(g => g.Group.TenantId)
            .Distinct().ToListAsync();

        // Tenant-level group role assignments
        var tenantIdsFromGroupRoles = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null
                && ra.Group!.CertificateAuthorityId == null && !ra.Group.IsSystemGroup
                && ra.Group.Members.Any(m => m.UserId == userId)
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.Group!.TenantId)
            .Distinct().ToListAsync();

        // Tenant-level user grants
        var tenantIdsFromUserGrants = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && ug.Capability == capability
                && ug.ResourceType == null && ug.TenantId != null && ug.CertificateAuthorityId == null)
            .Select(ug => ug.TenantId!.Value)
            .Distinct().ToListAsync();

        // Tenant-level user role assignments
        var tenantIdsFromUserRoles = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null
                && ra.TenantId != null && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.TenantId!.Value)
            .Distinct().ToListAsync();

        var allTenantIds = tenantIdsFromGroups
            .Union(tenantIdsFromGroupRoles)
            .Union(tenantIdsFromUserGrants)
            .Union(tenantIdsFromUserRoles)
            .Distinct().ToList();

        if (allTenantIds.Count > 0)
        {
            var tenantCaIds = await _db.CertificateAuthorities
                .Where(ca => allTenantIds.Contains(ca.TenantId))
                .Select(ca => ca.Id).ToListAsync();
            foreach (var id in tenantCaIds) caIds.Add(id);
        }

        // CA-scoped group grants
        var directFromGroups = await _db.CapabilityGrants
            .Where(g => g.Group.CertificateAuthorityId != null
                && g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == capability && g.ResourceType == null)
            .Select(g => g.Group.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromGroups) caIds.Add(id);

        // CA-scoped group role assignments
        var directFromGroupRoles = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null && ra.Group!.CertificateAuthorityId != null
                && ra.Group.Members.Any(m => m.UserId == userId)
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.Group!.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromGroupRoles) caIds.Add(id);

        // CA-scoped user grants
        var directFromUserGrants = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && ug.Capability == capability
                && ug.ResourceType == null && ug.CertificateAuthorityId != null)
            .Select(ug => ug.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromUserGrants) caIds.Add(id);

        // CA-scoped user role assignments
        var directFromUserRoles = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null
                && ra.CertificateAuthorityId != null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromUserRoles) caIds.Add(id);

        return caIds.ToList();
    }

    /// <inheritdoc />
    public async Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability, Guid? tenantId)
    {
        if (await IsSystemAdminAsync(userId))
        {
            return await _db.CertificateAuthorities
                .Where(ca => ca.TenantId == tenantId)
                .Select(ca => ca.Id).ToListAsync();
        }

        if (await HasSystemCapabilityAsync(userId, capability))
        {
            return await _db.CertificateAuthorities
                .Where(ca => ca.TenantId == tenantId)
                .Select(ca => ca.Id).ToListAsync();
        }

        // Tenant-level access from any source → all CAs in tenant
        var hasTenantAccess =
            // Group grant
            await _db.CapabilityGrants.AnyAsync(g =>
                g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup
                && g.Group.TenantId == tenantId
                && g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == capability && g.ResourceType == null)
            // Group role
            || await _db.RoleAssignments.AnyAsync(ra =>
                ra.GroupId != null && ra.Group!.CertificateAuthorityId == null && !ra.Group.IsSystemGroup
                && ra.Group.TenantId == tenantId
                && ra.Group.Members.Any(m => m.UserId == userId)
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            // User grant
            || await _db.UserCapabilityGrants.AnyAsync(ug =>
                ug.UserId == userId && ug.Capability == capability && ug.ResourceType == null
                && ug.TenantId == tenantId && ug.CertificateAuthorityId == null)
            // User role
            || await _db.RoleAssignments.AnyAsync(ra =>
                ra.UserId == userId && ra.GroupId == null
                && ra.TenantId == tenantId && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null));

        if (hasTenantAccess)
        {
            return await _db.CertificateAuthorities
                .Where(ca => ca.TenantId == tenantId)
                .Select(ca => ca.Id).ToListAsync();
        }

        // CA-scoped from all sources within this tenant
        var caIds = new HashSet<Guid>();

        var fromGroups = await _db.CapabilityGrants
            .Where(g => g.Group.CertificateAuthorityId != null
                && g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == capability && g.ResourceType == null)
            .Where(g => g.Group.CertificateAuthority != null && g.Group.CertificateAuthority.TenantId == tenantId)
            .Select(g => g.Group.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromGroups) caIds.Add(id);

        var fromGroupRoles = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null && ra.Group!.CertificateAuthorityId != null
                && ra.Group.Members.Any(m => m.UserId == userId)
                && ra.Group.CertificateAuthority != null && ra.Group.CertificateAuthority.TenantId == tenantId
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.Group!.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromGroupRoles) caIds.Add(id);

        var fromUserGrants = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && ug.Capability == capability
                && ug.ResourceType == null && ug.CertificateAuthorityId != null
                && ug.CertificateAuthority != null && ug.CertificateAuthority.TenantId == tenantId)
            .Select(ug => ug.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromUserGrants) caIds.Add(id);

        var fromUserRoles = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null
                && ra.CertificateAuthorityId != null
                && ra.CertificateAuthority != null && ra.CertificateAuthority.TenantId == tenantId
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromUserRoles) caIds.Add(id);

        return caIds.ToList();
    }

    /// <inheritdoc />
    public async Task<bool> HasResourceCapabilityAsync(Guid userId, string capability, string resourceType, Guid resourceId)
    {
        if (capability.StartsWith("profile.") && await IsSystemAdminAsync(userId))
            return true;

        // Source 1: group direct grants (exact match OR wildcard where ResourceId is null)
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability == capability
                && g.ResourceType == resourceType
                && (g.ResourceId == resourceId || g.ResourceId == null)))
            return true;

        // Source 2: role via group (exact match OR wildcard where ResourceId is null)
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.Members.Any(m => m.UserId == userId)
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability
                    && rc.ResourceType == resourceType
                    && (rc.ResourceId == resourceId || rc.ResourceId == null))))
            return true;

        // Source 3: direct user grants (exact match OR wildcard where ResourceId is null)
        if (await _db.UserCapabilityGrants
            .AnyAsync(ug => ug.UserId == userId
                && ug.Capability == capability
                && ug.ResourceType == resourceType
                && (ug.ResourceId == resourceId || ug.ResourceId == null)))
            return true;

        // Source 4: role via user (exact match OR wildcard where ResourceId is null)
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.UserId == userId && ra.GroupId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability
                    && rc.ResourceType == resourceType
                    && (rc.ResourceId == resourceId || rc.ResourceId == null))))
            return true;

        return false;
    }

    /// <inheritdoc />
    public async Task<(List<Guid> ResourceIds, bool HasWildcard)> GetGrantedResourceIdsAsync(
        Guid userId, string capabilityPrefix, string resourceType)
    {
        if (await IsSystemAdminAsync(userId))
            return (new List<Guid>(), true);

        var resourceIds = new HashSet<Guid>();
        bool hasWildcard = false;

        // Source 1: group direct grants
        var s1 = await _db.CapabilityGrants
            .Where(g => g.Group.Members.Any(m => m.UserId == userId)
                && g.Capability.StartsWith(capabilityPrefix)
                && g.ResourceType == resourceType)
            .Select(g => g.ResourceId)
            .ToListAsync();
        foreach (var id in s1) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        // Source 2: role via group
        var s2 = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null && ra.Group!.Members.Any(m => m.UserId == userId))
            .SelectMany(ra => ra.Role.Capabilities)
            .Where(rc => rc.Capability.StartsWith(capabilityPrefix) && rc.ResourceType == resourceType)
            .Select(rc => rc.ResourceId)
            .ToListAsync();
        foreach (var id in s2) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        // Source 3: direct user grants
        var s3 = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId
                && ug.Capability.StartsWith(capabilityPrefix)
                && ug.ResourceType == resourceType)
            .Select(ug => ug.ResourceId)
            .ToListAsync();
        foreach (var id in s3) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        // Source 4: role via user
        var s4 = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null)
            .SelectMany(ra => ra.Role.Capabilities)
            .Where(rc => rc.Capability.StartsWith(capabilityPrefix) && rc.ResourceType == resourceType)
            .Select(rc => rc.ResourceId)
            .ToListAsync();
        foreach (var id in s4) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        return (resourceIds.ToList(), hasWildcard);
    }
}
