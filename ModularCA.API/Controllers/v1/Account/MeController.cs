using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using System.Text.Json;

namespace ModularCA.API.Controllers.v1.Account
{
    /// <summary>
    /// Lightweight whoami endpoint. Returns the authenticated
    /// user's id, username, email, group memberships (with role levels and CA scope), MFA
    /// enrollment status, and tenant id. The frontends use this to populate an AuthContext
    /// instead of decoding the JWT body client-side. The endpoint is read-only and does
    /// not require any new schema.
    /// </summary>
    [ApiController]
    [Route("api/v1/me")]
    [Authorize]
    public class MeController(
        ICurrentUserService currentUser,
        ModularCADbContext db,
        ICaGroupAuthorizationService groupAuth) : ControllerBase
    {
        private readonly ICurrentUserService _currentUser = currentUser;
        private readonly ModularCADbContext _db = db;
        private readonly ICaGroupAuthorizationService _groupAuth = groupAuth;

        /// <summary>
        /// Returns identity, group memberships, effective capabilities (system-scoped and per
        /// CA), MFA enrollment, and primary tenant for the caller. The console derives its
        /// navigation, page gates and CA scope switcher from <c>capabilities</c>; the group
        /// list is informational.
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> GetMe()
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            var user = _currentUser.User;

            var groups = await _db.CaGroupMembers
                .Where(gm => gm.UserId == user.Id)
                .Include(gm => gm.Group)
                .ThenInclude(g => g!.CertificateAuthority)
                .Select(gm => new
                {
                    id = gm.Group!.Id,
                    name = gm.Group.Name,
                    displayName = gm.Group.DisplayName,
                    templateName = gm.Group.TemplateName ?? "Custom",
                    isSystemGroup = gm.Group.IsSystemGroup,
                    isSystemTierSuper = gm.Group.IsSystemTierSuper,
                    certificateAuthorityId = gm.Group.CertificateAuthorityId,
                    caLabel = gm.Group.CertificateAuthority != null ? gm.Group.CertificateAuthority.Label : null,
                    tenantId = gm.Group.TenantId,
                })
                .ToListAsync();

            // Whether the caller is a system super-administrator (member of an IsSystemTierSuper group).
            // The SPA uses this to gate super-only controls (e.g. the System approval-quorum card).
            var isSuper = groups.Any(g => g.isSystemTierSuper);

            // Effective scopes — flat list of strings the SPA can use for ProtectedRoute
            // checks. Format: "system:Admin", "system:Operator", "ca:<caId>:Admin", etc.
            var scopes = groups
                .Select(g => g.isSystemGroup
                    ? $"system:{g.templateName}"
                    : $"ca:{g.certificateAuthorityId}:{g.templateName}")
                .Distinct()
                .ToList();

            var hasTotp = await _db.TotpSecrets
                .AnyAsync(t => t.UserId == user.Id && t.IsVerified);
            var hasWebAuthn = await _db.Fido2Credentials
                .AnyAsync(c => c.UserId == user.Id);
            var hasMtls = await _db.MtlsCredentials
                .AnyAsync(c => c.UserId == user.Id && !c.IsRevoked && c.ExpiresAt > DateTime.UtcNow);

            var mfaConfigured = hasTotp || hasWebAuthn || hasMtls;

            var effective = await _groupAuth.GetEffectiveCapabilitiesAsync(user.Id);
            var capabilities = new
            {
                system = effective.System,
                cas = effective.Cas.Select(c => new
                {
                    id = c.Id,
                    label = c.Label,
                    name = c.Name,
                    isSshCa = c.IsSshCa,
                    capabilities = c.Capabilities,
                }),
            };

            // Pick a primary tenant from the user's group memberships. System groups have
            // a TenantId pointing at the System tenant — prefer a non-system tenant if any
            // is present, otherwise fall back to the system tenant.
            var primaryTenantId = groups
                .Where(g => !g.isSystemGroup)
                .Select(g => (Guid?)g.tenantId)
                .FirstOrDefault()
                ?? groups.Select(g => (Guid?)g.tenantId).FirstOrDefault();

            return Ok(new
            {
                id = user.Id,
                username = user.Username,
                email = user.Email,
                displayName = user.DisplayName,
                firstName = user.FirstName,
                lastName = user.LastName,
                isActive = user.IsActive,
                isSuper,
                groups,
                scopes,
                capabilities,
                mfa = new
                {
                    configured = mfaConfigured,
                    totp = hasTotp,
                    webauthn = hasWebAuthn,
                    mtls = hasMtls,
                },
                tenantId = primaryTenantId,
            });
        }

        /// <summary>
        /// Returns the calling user's effective permissions aggregated from all sources:
        /// direct capability grants, direct role assignments, group memberships with their
        /// capability grants, and group role assignments.
        /// </summary>
        [HttpGet("effective-permissions")]
        public async Task<IActionResult> GetEffectivePermissions()
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            var userId = _currentUser.User.Id;

            // 1. Direct user grants
            var directGrants = await _db.UserCapabilityGrants
                .AsNoTracking()
                .Where(g => g.UserId == userId)
                .Select(g => new
                {
                    g.Capability,
                    g.TenantId,
                    g.CertificateAuthorityId,
                    g.ResourceType,
                    g.ResourceId
                })
                .ToListAsync();

            // 2. Direct role assignments on the user
            var userRoleAssignments = await _db.RoleAssignments
                .AsNoTracking()
                .Include(ra => ra.Role)
                    .ThenInclude(r => r.Capabilities)
                .Where(ra => ra.UserId == userId && ra.GroupId == null)
                .ToListAsync();

            var roleAssignments = userRoleAssignments.Select(ra => new
            {
                RoleName = ra.Role.Name,
                Scope = new
                {
                    ra.TenantId,
                    ra.CertificateAuthorityId
                },
                Capabilities = ra.Role.Capabilities.Select(c => c.Capability).ToList()
            }).ToList();

            // 3. Group memberships -> group direct grants + group role assignments
            var groupMembershipIds = await _db.CaGroupMembers
                .AsNoTracking()
                .Where(m => m.UserId == userId)
                .Select(m => m.GroupId)
                .ToListAsync();

            var groups = await _db.CaGroups
                .AsNoTracking()
                .Where(g => groupMembershipIds.Contains(g.Id))
                .ToListAsync();

            var groupDirectGrants = await _db.CapabilityGrants
                .AsNoTracking()
                .Where(cg => groupMembershipIds.Contains(cg.GroupId))
                .ToListAsync();

            var groupRoleAssignments = await _db.RoleAssignments
                .AsNoTracking()
                .Include(ra => ra.Role)
                    .ThenInclude(r => r.Capabilities)
                .Where(ra => ra.GroupId != null && groupMembershipIds.Contains(ra.GroupId.Value))
                .ToListAsync();

            var groupMemberships = groups.Select(g => new
            {
                GroupName = g.DisplayName ?? g.Name,
                GroupId = g.Id,
                DirectCapabilities = groupDirectGrants
                    .Where(cg => cg.GroupId == g.Id)
                    .Select(cg => cg.Capability)
                    .ToList(),
                RoleAssignments = groupRoleAssignments
                    .Where(ra => ra.GroupId == g.Id)
                    .Select(ra => new
                    {
                        RoleName = ra.Role.Name,
                        Capabilities = ra.Role.Capabilities.Select(c => c.Capability).ToList()
                    })
                    .ToList()
            }).ToList();

            return Ok(new
            {
                UserId = userId,
                DirectGrants = directGrants,
                RoleAssignments = roleAssignments,
                GroupMemberships = groupMemberships
            });
        }

        /// <summary>
        /// Returns all of the calling user's stored UI preferences as a map of key → JSON value.
        /// Client features (e.g. the table component) read this once on load to hydrate their
        /// cross-device state; the localStorage copy is the fast path used before this resolves.
        /// </summary>
        [HttpGet("preferences")]
        public async Task<IActionResult> GetPreferences()
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            var rows = await _db.UserPreferences
                .AsNoTracking()
                .Where(p => p.UserId == _currentUser.User.Id)
                .ToListAsync();

            // Project each stored ValueJson back into live JSON so the response is a nested object,
            // not a map of escaped strings. Skip rows whose value somehow isn't valid JSON.
            var result = new Dictionary<string, JsonElement>();
            foreach (var row in rows)
            {
                try { result[row.Key] = JsonSerializer.Deserialize<JsonElement>(row.ValueJson); }
                catch (JsonException) { /* ignore corrupt row */ }
            }
            return Ok(result);
        }

        /// <summary>
        /// Upserts a single UI preference for the calling user. The body is an opaque JSON value
        /// owned by the client feature (stored verbatim). Used to sync table column layouts across
        /// browsers/devices.
        /// </summary>
        /// <param name="key">App-defined preference key, e.g. "table:certificates" (max 200 chars).</param>
        /// <param name="value">The JSON value to store for this key.</param>
        [HttpPut("preferences/{key}")]
        public async Task<IActionResult> PutPreference(string key, [FromBody] JsonElement value)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            if (string.IsNullOrWhiteSpace(key) || key.Length > 200)
                return BadRequest(new { error = "Preference key is required and must be 200 characters or fewer." });

            var userId = _currentUser.User.Id;
            var json = value.GetRawText();

            var existing = await _db.UserPreferences.FirstOrDefaultAsync(p => p.UserId == userId && p.Key == key);
            if (existing == null)
            {
                _db.UserPreferences.Add(new UserPreferenceEntity
                {
                    UserId = userId,
                    Key = key,
                    ValueJson = json,
                    UpdatedAt = DateTime.UtcNow
                });
            }
            else
            {
                existing.ValueJson = json;
                existing.UpdatedAt = DateTime.UtcNow;
            }
            await _db.SaveChangesAsync();
            return NoContent();
        }
    }
}
