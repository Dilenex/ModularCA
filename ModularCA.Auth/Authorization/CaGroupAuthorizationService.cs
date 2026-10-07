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
    private readonly IAccessBadgeContext? _badges;

    public CaGroupAuthorizationService(
        ModularCADbContext db,
        ILogger<CaGroupAuthorizationService> logger,
        IAuditService? audit = null,
        IHttpContextAccessor? httpContextAccessor = null,
        IAccessBadgeContext? badges = null)
    {
        _db = db;
        _logger = logger;
        _audit = audit;
        _httpContextAccessor = httpContextAccessor;
        _badges = badges;
    }

    /// <summary>
    /// The worn badge as query filters. Every grant-source query below carries
    /// <c>(!worn || &lt;ids&gt;.Contains(...))</c>: badgeless (<c>worn == false</c>) walks every
    /// source, which is today's behaviour, and a worn badge keeps only the sources it names.
    /// The resolver reads the badge from the caller's token, so a badge is enforced on every
    /// request, including ones the console never makes. Jobs and protocol clients wear none.
    /// </summary>
    private async Task<(bool worn, List<Guid> bGroups, List<Guid> bRas, List<Guid> bGrants)> BadgeAsync(Guid userId)
    {
        var filter = _badges == null ? null : await _badges.GetWornAsync(userId);
        if (filter == null) return (false, [], [], []);
        return (true, filter.GroupIds.ToList(), filter.RoleAssignmentIds.ToList(), filter.CapabilityGrantIds.ToList());
    }

    // ── Helpers: check a single capability across all 4 sources ──

    /// <summary>
    /// Checks if the user has the capability via any system group (direct grant or role).
    /// </summary>
    private async Task<bool> HasCapabilityViaSystemGroupsAsync(Guid userId, string capability)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        // Source 1: direct group grants
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.IsSystemGroup
                && g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability
                && g.ResourceType == null))
            return true;

        // Source 2: role grants via system group
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.IsSystemGroup
                && ra.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)))
            return true;

        return false;
    }

    /// <summary>
    /// Checks if the user has the capability via direct user grants or user role assignments
    /// that match the given scope (global, space, or CA).
    /// </summary>
    private async Task<bool> HasCapabilityViaUserGrantsAsync(Guid userId, string capability, Guid? spaceId, Guid? caId)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        // Source 3: direct user grants — match global, space, or CA scope
        if (await _db.UserCapabilityGrants
            .AnyAsync(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id))
                && ug.Capability == capability
                && ug.ResourceType == null
                && (
                    // Global grant
                    (ug.SpaceId == null && ug.CertificateAuthorityId == null)
                    // Space grant (if spaceId known)
                    || (spaceId != null && ug.SpaceId == spaceId && ug.CertificateAuthorityId == null)
                    // CA grant (if caId known)
                    || (caId != null && ug.CertificateAuthorityId == caId)
                )))
            return true;

        // Source 4: role grants via user role assignments — match scope
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.UserId == userId
                && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)
                && (
                    // Global assignment
                    (ra.SpaceId == null && ra.CertificateAuthorityId == null)
                    // Space assignment
                    || (spaceId != null && ra.SpaceId == spaceId && ra.CertificateAuthorityId == null)
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
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        // System group grants + roles
        if (await HasCapabilityViaSystemGroupsAsync(userId, capability))
            return true;

        // User-level grants with global scope
        return await HasCapabilityViaUserGrantsAsync(userId, capability, spaceId: null, caId: null);
    }

    /// <inheritdoc />
    public async Task<bool> HasCaCapabilityAsync(Guid userId, Guid caId, string capability)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
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
                        spaceId: targetCa?.SpaceId);
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
        var spaceId = ca?.SpaceId;

        // Source 1: direct group grants (system, space, CA-scoped)
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability
                && g.ResourceType == null
                && (
                    g.Group.IsSystemGroup
                    || g.Group.CertificateAuthorityId == caId
                    || (spaceId != null && g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup && g.Group.SpaceId == spaceId)
                )))
            return true;

        // Source 2: role grants via group membership
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)
                && (
                    ra.Group.IsSystemGroup
                    || ra.Group.CertificateAuthorityId == caId
                    || (spaceId != null && ra.Group.CertificateAuthorityId == null && !ra.Group.IsSystemGroup && ra.Group.SpaceId == spaceId)
                )))
            return true;

        // Sources 3+4: user grants and user role assignments
        return await HasCapabilityViaUserGrantsAsync(userId, capability, spaceId, caId);
    }

    /// <inheritdoc />
    public async Task<bool> HasSpaceCapabilityAsync(Guid userId, Guid spaceId, string capability)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);

        // system.manage holders bypass every scoped check; a system-scoped holder of the
        // capability itself holds it for every space.
        if (await IsSystemAdminAsync(userId) || await HasCapabilityViaSystemGroupsAsync(userId, capability))
            return true;

        // Source 1: direct grants on a space-wide group of this space
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability
                && g.ResourceType == null
                && !g.Group.IsSystemGroup
                && g.Group.CertificateAuthorityId == null
                && g.Group.SpaceId == spaceId))
            return true;

        // Source 2: roles on a space-wide group of this space
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)
                && !ra.Group.IsSystemGroup
                && ra.Group.CertificateAuthorityId == null
                && ra.Group.SpaceId == spaceId))
            return true;

        // Sources 3+4: grants and roles on the user at global or space scope. No CA is passed,
        // so a CA-scoped grant inside the space cannot satisfy this.
        return await HasCapabilityViaUserGrantsAsync(userId, capability, spaceId, caId: null);
    }

    /// <inheritdoc />
    public async Task<List<Guid>> GetSpaceIdsWithCapabilityAsync(Guid userId, string capability)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        var ids = new HashSet<Guid>();

        // Source 1: direct grants on space-wide groups
        ids.UnionWith(await _db.CapabilityGrants
            .Where(g => g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability && g.ResourceType == null
                && !g.Group.IsSystemGroup && g.Group.CertificateAuthorityId == null && g.Group.SpaceId != null)
            .Select(g => g.Group.SpaceId!.Value)
            .ToListAsync());

        // Source 2: roles on space-wide groups
        ids.UnionWith(await _db.RoleAssignments
            .Where(ra => ra.GroupId != null
                && ra.Group!.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)
                && !ra.Group.IsSystemGroup && ra.Group.CertificateAuthorityId == null && ra.Group.SpaceId != null)
            .Select(ra => ra.Group!.SpaceId!.Value)
            .ToListAsync());

        // Source 3: space-scoped grants on the user
        ids.UnionWith(await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id))
                && ug.Capability == capability && ug.ResourceType == null
                && ug.SpaceId != null && ug.CertificateAuthorityId == null)
            .Select(ug => ug.SpaceId!.Value)
            .ToListAsync());

        // Source 4: space-scoped roles on the user
        ids.UnionWith(await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)
                && ra.SpaceId != null && ra.CertificateAuthorityId == null)
            .Select(ra => ra.SpaceId!.Value)
            .ToListAsync());

        return ids.ToList();
    }

    /// <inheritdoc />
    public async Task<bool> IsSystemAdminAsync(Guid userId)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        // Direct group grant
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.IsSystemGroup
                && g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == Capabilities.SystemManage
                && g.ResourceType == null))
            return true;

        // Role via system group
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.IsSystemGroup
                && ra.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == Capabilities.SystemManage && rc.ResourceType == null)))
            return true;

        // Direct user grant (global scope)
        if (await _db.UserCapabilityGrants
            .AnyAsync(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id))
                && ug.Capability == Capabilities.SystemManage
                && ug.SpaceId == null && ug.CertificateAuthorityId == null
                && ug.ResourceType == null))
            return true;

        // User role assignment (global scope)
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.UserId == userId
                && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
                && ra.SpaceId == null && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == Capabilities.SystemManage && rc.ResourceType == null)))
            return true;

        return false;
    }

    /// <inheritdoc />
    public async Task<SpaceFence> GetFenceAsync(Guid userId)
    {
        if (await IsSystemAdminAsync(userId))
            return SpaceFence.Of([], instanceScope: true, isSystemAdmin: true);

        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);

        var groups = (await _db.CaGroupMembers
                .Where(m => m.UserId == userId && (!worn || bGroups.Contains(m.GroupId)))
                .Select(m => new { m.GroupId, m.Group.SpaceId, m.Group.IsSystemGroup, m.Group.CertificateAuthorityId })
                .ToListAsync())
            .DistinctBy(g => g.GroupId).ToList();
        var groupIds = groups.Select(g => g.GroupId).ToList();

        var groupCaps = await _db.CapabilityGrants
            .Where(g => groupIds.Contains(g.GroupId) && g.ResourceType == null)
            .Select(g => new { g.GroupId, g.Capability })
            .ToListAsync();
        groupCaps.AddRange(await _db.RoleAssignments
            .Where(ra => ra.GroupId != null && groupIds.Contains(ra.GroupId.Value))
            .SelectMany(ra => ra.Role.Capabilities.Where(rc => rc.ResourceType == null)
                .Select(rc => new { GroupId = ra.GroupId!.Value, rc.Capability }))
            .ToListAsync());

        var userCaps = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id)) && ug.ResourceType == null)
            .Select(ug => new { ug.Capability, ug.SpaceId, ug.CertificateAuthorityId })
            .ToListAsync();
        userCaps.AddRange(await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id)))
            .SelectMany(ra => ra.Role.Capabilities.Where(rc => rc.ResourceType == null)
                .Select(rc => new { rc.Capability, ra.SpaceId, ra.CertificateAuthorityId }))
            .ToListAsync());

        var caIds = userCaps.Where(u => u.CertificateAuthorityId != null).Select(u => u.CertificateAuthorityId!.Value).Distinct().ToList();
        var caSpaces = caIds.Count == 0 ? new Dictionary<Guid, Guid?>()
            : await _db.CertificateAuthorities
                .Where(ca => caIds.Contains(ca.Id))
                .ToDictionaryAsync(ca => ca.Id, ca => ca.SpaceId);

        var systemCaps = new HashSet<string>(StringComparer.Ordinal);
        var spaceIds = new HashSet<Guid>();
        var instanceScope = false;
        var systemMember = false;
        var spacesByCapability = new Dictionary<string, HashSet<Guid>>(StringComparer.Ordinal);
        var instanceCaps = new HashSet<string>(StringComparer.Ordinal);

        void Confer(string capability, Guid? spaceId)
        {
            if (spaceId is not Guid t)
            {
                instanceCaps.Add(capability);
                return;
            }
            if (!spacesByCapability.TryGetValue(capability, out var set))
                spacesByCapability[capability] = set = [];
            set.Add(t);
        }

        foreach (var g in groups)
        {
            if (g.SpaceId is Guid t) spaceIds.Add(t);
            else if (g.IsSystemGroup) systemMember = true;
            else if (g.CertificateAuthorityId != null) instanceScope = true;
        }

        var groupById = groups.ToDictionary(g => g.GroupId);
        foreach (var gc in groupCaps)
        {
            var g = groupById[gc.GroupId];
            if (g.IsSystemGroup) systemCaps.Add(gc.Capability);
            else if (g.SpaceId != null || g.CertificateAuthorityId != null) Confer(gc.Capability, g.SpaceId);
        }

        foreach (var uc in userCaps)
        {
            if (uc.CertificateAuthorityId is Guid caId)
            {
                if (!caSpaces.TryGetValue(caId, out var caSpace))
                    continue;
                if (caSpace is Guid t) spaceIds.Add(t);
                else instanceScope = true;
                Confer(uc.Capability, caSpace);
            }
            else if (uc.SpaceId is Guid t)
            {
                spaceIds.Add(t);
                Confer(uc.Capability, t);
            }
            else systemCaps.Add(uc.Capability);
        }

        return SpaceFence.Of(spaceIds, instanceScope, systemCapabilities: systemCaps, systemMember: systemMember,
            spacesByCapability: spacesByCapability, instanceCapabilities: instanceCaps);
    }

    /// <inheritdoc />
    public async Task<List<CaGroupEntity>> GetUserGroupsAsync(Guid userId)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        return await _db.CaGroupMembers
            .Where(gm => gm.UserId == userId && (!worn || bGroups.Contains(gm.GroupId)))
            .Select(gm => gm.Group)
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<EffectiveCapabilities> GetEffectiveCapabilitiesAsync(Guid userId)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        // Load the user's grant sources once and fold them in memory. The per-capability
        // checks above each run several queries; walking them per capability per CA would be
        // hundreds of round trips for one page load.
        var memberGroupIds = await _db.CaGroupMembers
            .AsNoTracking()
            .Where(m => m.UserId == userId && (!worn || bGroups.Contains(m.GroupId)))
            .Select(m => m.GroupId)
            .ToListAsync();

        var groups = await _db.CaGroups
            .AsNoTracking()
            .Where(g => memberGroupIds.Contains(g.Id))
            .Select(g => new { g.Id, g.IsSystemGroup, g.CertificateAuthorityId, g.SpaceId })
            .ToListAsync();
        var groupById = groups.ToDictionary(g => g.Id);

        // (capability, scope) pairs. Scope is one of: system, a space, or a CA.
        var systemCaps = new HashSet<string>(StringComparer.Ordinal);
        var spaceCaps = new Dictionary<Guid, HashSet<string>>();
        var caCaps = new Dictionary<Guid, HashSet<string>>();

        void AddGroupScoped(Guid groupId, string capability)
        {
            if (!groupById.TryGetValue(groupId, out var g)) return;
            if (g.IsSystemGroup) systemCaps.Add(capability);
            else if (g.CertificateAuthorityId is Guid caId) Bucket(caCaps, caId).Add(capability);
            // Only a space's space-wide group has a bucket; a non-system group with neither
            // space nor CA confers nothing, and never system scope.
            else if (g.SpaceId is Guid tid) Bucket(spaceCaps, tid).Add(capability);
        }

        void AddUserScoped(string capability, Guid? spaceId, Guid? certificateAuthorityId)
        {
            if (certificateAuthorityId is Guid caId) Bucket(caCaps, caId).Add(capability);
            else if (spaceId is Guid tid) Bucket(spaceCaps, tid).Add(capability);
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

        // Source 3: grants on the user directly, at global, space or CA scope.
        var userGrants = await _db.UserCapabilityGrants
            .AsNoTracking()
            .Where(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id)) && ug.ResourceType == null)
            .Select(ug => new { ug.Capability, ug.SpaceId, ug.CertificateAuthorityId })
            .ToListAsync();
        foreach (var ug in userGrants) AddUserScoped(ug.Capability, ug.SpaceId, ug.CertificateAuthorityId);

        // Source 4: roles assigned to the user directly, at global, space or CA scope.
        var userRoles = await _db.RoleAssignments
            .AsNoTracking()
            .Include(ra => ra.Role).ThenInclude(r => r.Capabilities)
            .Where(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id)))
            .ToListAsync();
        foreach (var ra in userRoles)
            foreach (var rc in ra.Role.Capabilities.Where(rc => rc.ResourceType == null))
                AddUserScoped(rc.Capability, ra.SpaceId, ra.CertificateAuthorityId);

        // system.manage at system scope passes every check (see HasCaCapabilityAsync), so
        // report it as everything rather than as the literal grants.
        if (systemCaps.Contains(Capabilities.SystemManage))
            systemCaps.UnionWith(Capabilities.All);

        var cas = await _db.CertificateAuthorities
            .AsNoTracking()
            .Select(ca => new { ca.Id, ca.Label, ca.Name, ca.IsSshCa, ca.SpaceId })
            .ToListAsync();
        var spaces = await _db.Spaces
            .AsNoTracking()
            .Select(t => new { t.Id, t.Name, t.Slug })
            .ToDictionaryAsync(t => t.Id, t => t);

        var perCa = new List<CaCapabilities>();
        foreach (var ca in cas)
        {
            var caps = new HashSet<string>(systemCaps, StringComparer.Ordinal);
            if (ca.SpaceId is Guid caSpaceId && spaceCaps.TryGetValue(caSpaceId, out var t)) caps.UnionWith(t);
            if (caCaps.TryGetValue(ca.Id, out var c)) caps.UnionWith(c);
            if (caps.Count == 0) continue;
            // An instance CA carries no space, so an empty name and slug.
            var space = ca.SpaceId is Guid tid && spaces.TryGetValue(tid, out var found) ? found : null;
            perCa.Add(new CaCapabilities(ca.Id, ca.Label ?? string.Empty, ca.Name, ca.IsSshCa,
                ca.SpaceId, space?.Name ?? string.Empty,
                ca.SpaceId == null ? string.Empty : space?.Slug ?? ca.SpaceId.Value.ToString(),
                caps.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        // Space-wide grants, so the console knows where the user may create a CA even before
        // the space has one. System-scoped holders are not expanded to every space here; the
        // client reads `System` for that, as it does for CAs.
        var perSpace = new List<SpaceCapabilities>();
        foreach (var (spaceId, granted) in spaceCaps)
        {
            var caps = new HashSet<string>(systemCaps, StringComparer.Ordinal);
            caps.UnionWith(granted);
            if (caps.Count == 0) continue;
            spaces.TryGetValue(spaceId, out var space);
            perSpace.Add(new SpaceCapabilities(spaceId, space?.Name ?? string.Empty, space?.Slug ?? spaceId.ToString(),
                caps.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        return new EffectiveCapabilities(
            systemCaps.OrderBy(x => x, StringComparer.Ordinal).ToList(),
            perCa.OrderBy(x => x.Label, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            perSpace.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Slug, StringComparer.OrdinalIgnoreCase).ToList());

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
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
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

        // Space-level group grants → all CAs in those spaces
        var spaceIdsFromGroups = await _db.CapabilityGrants
            .Where(g => g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup && g.Group.SpaceId != null
                && g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability && g.ResourceType == null)
            .Select(g => g.Group.SpaceId!.Value)
            .Distinct().ToListAsync();

        // Space-level group role assignments
        var spaceIdsFromGroupRoles = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null
                && ra.Group!.CertificateAuthorityId == null && !ra.Group.IsSystemGroup && ra.Group.SpaceId != null
                && ra.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.Group!.SpaceId!.Value)
            .Distinct().ToListAsync();

        // Space-level user grants
        var spaceIdsFromUserGrants = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id)) && ug.Capability == capability
                && ug.ResourceType == null && ug.SpaceId != null && ug.CertificateAuthorityId == null)
            .Select(ug => ug.SpaceId!.Value)
            .Distinct().ToListAsync();

        // Space-level user role assignments
        var spaceIdsFromUserRoles = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
                && ra.SpaceId != null && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.SpaceId!.Value)
            .Distinct().ToListAsync();

        var allSpaceIds = spaceIdsFromGroups
            .Union(spaceIdsFromGroupRoles)
            .Union(spaceIdsFromUserGrants)
            .Union(spaceIdsFromUserRoles)
            .Distinct().ToList();

        if (allSpaceIds.Count > 0)
        {
            var spaceCaIds = await _db.CertificateAuthorities
                .Where(ca => ca.SpaceId != null && allSpaceIds.Contains(ca.SpaceId.Value))
                .Select(ca => ca.Id).ToListAsync();
            foreach (var id in spaceCaIds) caIds.Add(id);
        }

        // CA-scoped group grants
        var directFromGroups = await _db.CapabilityGrants
            .Where(g => g.Group.CertificateAuthorityId != null
                && g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability && g.ResourceType == null)
            .Select(g => g.Group.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromGroups) caIds.Add(id);

        // CA-scoped group role assignments
        var directFromGroupRoles = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null && ra.Group!.CertificateAuthorityId != null
                && ra.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.Group!.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromGroupRoles) caIds.Add(id);

        // CA-scoped user grants
        var directFromUserGrants = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id)) && ug.Capability == capability
                && ug.ResourceType == null && ug.CertificateAuthorityId != null)
            .Select(ug => ug.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromUserGrants) caIds.Add(id);

        // CA-scoped user role assignments
        var directFromUserRoles = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
                && ra.CertificateAuthorityId != null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.CertificateAuthorityId!.Value)
            .Distinct().ToListAsync();
        foreach (var id in directFromUserRoles) caIds.Add(id);

        return caIds.ToList();
    }

    /// <inheritdoc />
    public async Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability, Guid? spaceId)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        if (await IsSystemAdminAsync(userId))
        {
            return await _db.CertificateAuthorities
                .Where(ca => ca.SpaceId == spaceId)
                .Select(ca => ca.Id).ToListAsync();
        }

        if (await HasSystemCapabilityAsync(userId, capability))
        {
            return await _db.CertificateAuthorities
                .Where(ca => ca.SpaceId == spaceId)
                .Select(ca => ca.Id).ToListAsync();
        }

        // Space-level access from any source → all CAs in space. The instance (null) has no
        // space-level sources; a global grant is a system capability, checked above.
        var hasSpaceAccess = spaceId != null && (
            // Group grant
            await _db.CapabilityGrants.AnyAsync(g =>
                g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup
                && g.Group.SpaceId == spaceId
                && g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability && g.ResourceType == null)
            // Group role
            || await _db.RoleAssignments.AnyAsync(ra =>
                ra.GroupId != null && ra.Group!.CertificateAuthorityId == null && !ra.Group.IsSystemGroup
                && ra.Group.SpaceId == spaceId
                && ra.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            // User grant
            || await _db.UserCapabilityGrants.AnyAsync(ug =>
                ug.UserId == userId && (!worn || bGrants.Contains(ug.Id)) && ug.Capability == capability && ug.ResourceType == null
                && ug.SpaceId == spaceId && ug.CertificateAuthorityId == null)
            // User role
            || await _db.RoleAssignments.AnyAsync(ra =>
                ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
                && ra.SpaceId == spaceId && ra.CertificateAuthorityId == null
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null)));

        if (hasSpaceAccess)
        {
            return await _db.CertificateAuthorities
                .Where(ca => ca.SpaceId == spaceId)
                .Select(ca => ca.Id).ToListAsync();
        }

        // CA-scoped from all sources within this space
        var caIds = new HashSet<Guid>();

        var fromGroups = await _db.CapabilityGrants
            .Where(g => g.Group.CertificateAuthorityId != null
                && g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability && g.ResourceType == null)
            .Where(g => g.Group.CertificateAuthority != null && g.Group.CertificateAuthority.SpaceId == spaceId)
            .Select(g => g.Group.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromGroups) caIds.Add(id);

        var fromGroupRoles = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null && ra.Group!.CertificateAuthorityId != null
                && ra.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Group.CertificateAuthority != null && ra.Group.CertificateAuthority.SpaceId == spaceId
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.Group!.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromGroupRoles) caIds.Add(id);

        var fromUserGrants = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id)) && ug.Capability == capability
                && ug.ResourceType == null && ug.CertificateAuthorityId != null
                && ug.CertificateAuthority != null && ug.CertificateAuthority.SpaceId == spaceId)
            .Select(ug => ug.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromUserGrants) caIds.Add(id);

        var fromUserRoles = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
                && ra.CertificateAuthorityId != null
                && ra.CertificateAuthority != null && ra.CertificateAuthority.SpaceId == spaceId
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null))
            .Select(ra => ra.CertificateAuthorityId!.Value).Distinct().ToListAsync();
        foreach (var id in fromUserRoles) caIds.Add(id);

        return caIds.ToList();
    }

    /// <inheritdoc />
    public async Task<bool> HasResourceCapabilityAsync(Guid userId, string capability, string resourceType, Guid resourceId)
    {
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        if (capability.StartsWith("profile.") && await IsSystemAdminAsync(userId))
            return true;

        // Source 1: group direct grants (exact match OR wildcard where ResourceId is null)
        if (await _db.CapabilityGrants
            .AnyAsync(g => g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability == capability
                && g.ResourceType == resourceType
                && (g.ResourceId == resourceId || g.ResourceId == null)))
            return true;

        // Source 2: role via group (exact match OR wildcard where ResourceId is null)
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.GroupId != null
                && ra.Group!.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value))
                && ra.Role.Capabilities.Any(rc => rc.Capability == capability
                    && rc.ResourceType == resourceType
                    && (rc.ResourceId == resourceId || rc.ResourceId == null))))
            return true;

        // Source 3: direct user grants (exact match OR wildcard where ResourceId is null)
        if (await _db.UserCapabilityGrants
            .AnyAsync(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id))
                && ug.Capability == capability
                && ug.ResourceType == resourceType
                && (ug.ResourceId == resourceId || ug.ResourceId == null)))
            return true;

        // Source 4: role via user (exact match OR wildcard where ResourceId is null)
        if (await _db.RoleAssignments
            .AnyAsync(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id))
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
        var (worn, bGroups, bRas, bGrants) = await BadgeAsync(userId);
        if (await IsSystemAdminAsync(userId))
            return (new List<Guid>(), true);

        var resourceIds = new HashSet<Guid>();
        bool hasWildcard = false;

        // Source 1: group direct grants
        var s1 = await _db.CapabilityGrants
            .Where(g => g.Group.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(g.GroupId))
                && g.Capability.StartsWith(capabilityPrefix)
                && g.ResourceType == resourceType)
            .Select(g => g.ResourceId)
            .ToListAsync();
        foreach (var id in s1) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        // Source 2: role via group
        var s2 = await _db.RoleAssignments
            .Where(ra => ra.GroupId != null && ra.Group!.Members.Any(m => m.UserId == userId) && (!worn || bGroups.Contains(ra.GroupId!.Value)))
            .SelectMany(ra => ra.Role.Capabilities)
            .Where(rc => rc.Capability.StartsWith(capabilityPrefix) && rc.ResourceType == resourceType)
            .Select(rc => rc.ResourceId)
            .ToListAsync();
        foreach (var id in s2) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        // Source 3: direct user grants
        var s3 = await _db.UserCapabilityGrants
            .Where(ug => ug.UserId == userId && (!worn || bGrants.Contains(ug.Id))
                && ug.Capability.StartsWith(capabilityPrefix)
                && ug.ResourceType == resourceType)
            .Select(ug => ug.ResourceId)
            .ToListAsync();
        foreach (var id in s3) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        // Source 4: role via user
        var s4 = await _db.RoleAssignments
            .Where(ra => ra.UserId == userId && ra.GroupId == null && (!worn || bRas.Contains(ra.Id)))
            .SelectMany(ra => ra.Role.Capabilities)
            .Where(rc => rc.Capability.StartsWith(capabilityPrefix) && rc.ResourceType == resourceType)
            .Select(rc => rc.ResourceId)
            .ToListAsync();
        foreach (var id in s4) { if (id == null) hasWildcard = true; else resourceIds.Add(id.Value); }

        return (resourceIds.ToList(), hasWildcard);
    }
}
