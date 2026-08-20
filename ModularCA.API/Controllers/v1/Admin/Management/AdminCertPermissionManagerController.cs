using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Management;
using ModularCA.Core.Helpers;

namespace ModularCA.API.Controllers.v1.Admin.Management
{
    /// <summary>
    /// Admin endpoints for managing certificate access permissions (view/manage grants per user).
    /// </summary>
    [ApiController]
    [Route("api/v1/admin/manage/cert-permissions")]
    [Authorize(Policy = "CaOperator")]
    public class AdminCertPermissionManagerController(ICertificateStore certStore, ICurrentUserService currentUser, ICertificateAccessAssignment accessAssignment, IAuditService audit, ModularCADbContext db) : ControllerBase
    {
        private readonly ICertificateStore _certStore = certStore;
        private readonly ICurrentUserService _currentUser = currentUser;
        private readonly ICertificateAccessAssignment _accessAssignment = accessAssignment;
        private readonly IAuditService _audit = audit;
        private readonly ModularCADbContext _db = db;

        /// <summary>
        /// Lists the explicit per-certificate ACL entries for a certificate (resolved by serial — the
        /// detail page is serial-based). Each entry is a user with View or Manage access. The original
        /// requestor (who always has implicit view) is surfaced separately for context. Note: users who
        /// can already see/manage the cert via CA-scoped RBAC capabilities are NOT listed here — this is
        /// only the supplementary ACL.
        /// </summary>
        [HttpGet("serial/{serial}")]
        public async Task<IActionResult> GetBySerial(string serial)
        {
            var cert = await _db.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial);
            if (cert == null) return NotFound(new { error = "Certificate not found." });

            // The cert→CA navigation is a shadow FK that isn't populated, so resolve the CA via real
            // columns: the cert's own CertificateId (CA certs) then IssuerCertificateId (leaf certs).
            // Otherwise the scope is null and the hint over-matches every tenant.
            var ca = await _db.CertificateAuthorities.AsNoTracking().FirstOrDefaultAsync(a => a.CertificateId == cert.CertificateId)
                ?? (cert.IssuerCertificateId != null ? await _db.CertificateAuthorities.AsNoTracking().FirstOrDefaultAsync(a => a.CertificateId == cert.IssuerCertificateId) : null);

            var entries = await _db.CertificateAccessLists.AsNoTracking()
                .Where(a => a.CertificateId == cert.CertificateId)
                .Join(_db.Users, a => a.UserId, u => u.Id, (a, u) => new
                {
                    userId = a.UserId,
                    username = u.Username,
                    email = u.Email,
                    accessLevel = a.AccessLevel,
                })
                .OrderBy(x => x.username)
                .ToListAsync();

            var requestorUserId = await _db.CertificateRequests.AsNoTracking()
                .Where(r => r.IssuedCertificateId == cert.CertificateId)
                .Select(r => r.RequestorUserId)
                .FirstOrDefaultAsync();

            // Read-only RBAC hint: groups that confer view/manage on this cert via CA-scoped capabilities
            // (the supplementary ACL above is separate). Covers group capability grants + roles assigned
            // to groups; direct per-user grants are not enumerated.
            var rbac = await BuildRbacHintAsync(ca?.Id, ca?.TenantId, ca?.Label);

            return Ok(new { serialNumber = serial, certificateId = cert.CertificateId, requestorUserId, entries, rbac });
        }

        /// <summary>
        /// Builds the read-only RBAC hint for the cert's CA scope: which groups grant View/Manage and
        /// how many members each has. Mirrors the group sources of <c>CertificateAccessEvaluator</c>
        /// (cert.view → View; cert.revoke / system.manage → Manage), scoped to system / this tenant /
        /// this CA. Direct per-user grants/roles aren't included (rare; would need 4-source enumeration).
        /// </summary>
        private async Task<object> BuildRbacHintAsync(Guid? caId, Guid? tenantId, string? caLabel)
        {
            var relevant = new[] { Capabilities.CertView, Capabilities.CertRevoke, Capabilities.SystemManage };

            // Source 1 — direct capability grants on in-scope groups.
            var s1 = await _db.CapabilityGrants.AsNoTracking()
                .Where(g => g.ResourceType == null && relevant.Contains(g.Capability)
                    && (g.Group.IsSystemGroup
                        || (caId != null && g.Group.CertificateAuthorityId == caId)
                        || (tenantId != null && g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup && g.Group.TenantId == tenantId)))
                .Select(g => new { g.GroupId, g.Group.Name, g.Group.DisplayName, g.Capability })
                .ToListAsync();

            // Source 2 — roles assigned to in-scope groups that grant a relevant capability.
            var s2 = await _db.RoleAssignments.AsNoTracking()
                .Where(ra => ra.GroupId != null
                    && ra.Role.Capabilities.Any(rc => rc.ResourceType == null && relevant.Contains(rc.Capability))
                    && (ra.Group!.IsSystemGroup
                        || (caId != null && ra.Group.CertificateAuthorityId == caId)
                        || (tenantId != null && ra.Group.CertificateAuthorityId == null && !ra.Group.IsSystemGroup && ra.Group.TenantId == tenantId)))
                .Select(ra => new
                {
                    GroupId = ra.GroupId!.Value,
                    ra.Group!.Name,
                    ra.Group.DisplayName,
                    Manage = ra.Role.Capabilities.Any(rc => rc.ResourceType == null && (rc.Capability == Capabilities.CertRevoke || rc.Capability == Capabilities.SystemManage)),
                    View = ra.Role.Capabilities.Any(rc => rc.ResourceType == null && rc.Capability == Capabilities.CertView),
                })
                .ToListAsync();

            // Merge to one entry per group; Manage wins over View.
            var merged = new Dictionary<Guid, (string Name, string Display, bool Manage)>();
            void Add(Guid gid, string name, string? display, bool manage)
            {
                if (merged.TryGetValue(gid, out var cur)) merged[gid] = (cur.Name, cur.Display, cur.Manage || manage);
                else merged[gid] = (name, display ?? name, manage);
            }
            foreach (var g in s1) Add(g.GroupId, g.Name, g.DisplayName, g.Capability == Capabilities.CertRevoke || g.Capability == Capabilities.SystemManage);
            foreach (var g in s2) { if (g.Manage || g.View) Add(g.GroupId, g.Name, g.DisplayName, g.Manage); }

            var groupIds = merged.Keys.ToList();
            var counts = await _db.CaGroupMembers.AsNoTracking()
                .Where(m => groupIds.Contains(m.GroupId))
                .GroupBy(m => m.GroupId)
                .Select(x => new { GroupId = x.Key, Count = x.Select(m => m.UserId).Distinct().Count() })
                .ToDictionaryAsync(x => x.GroupId, x => x.Count);

            var groups = merged
                .Select(kv => new
                {
                    groupId = kv.Key,
                    name = kv.Value.Name,
                    displayName = kv.Value.Display,
                    level = kv.Value.Manage ? "Manage" : "View",
                    memberCount = counts.GetValueOrDefault(kv.Key, 0),
                })
                .OrderByDescending(x => x.level == "Manage")
                .ThenBy(x => x.name)
                .ToList();

            return new { caLabel, groups };
        }

        /// <summary>
        /// Sets (grants or changes) a user's ACL access level on a certificate (by serial). Level
        /// "Manage" grants revoke/reissue rights; "View" (default) grants read-only. Granting View when
        /// the user currently has Manage is a downgrade; granting Manage is an upgrade.
        /// </summary>
        [HttpPost("serial/{serial}/set")]
        [RequireStepUp(StepUpOps.UpdateCertAcl, "serial")]
        public async Task<IActionResult> SetBySerial(string serial, [FromBody] SetCertPermissionRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null) return Unauthorized();
            if (!Guid.TryParse(request.UserId, out var targetUserId))
                return BadRequest(new { error = "A valid userId is required." });

            var cert = await _db.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial);
            if (cert == null) return NotFound(new { error = "Certificate not found." });

            var manage = string.Equals(request.AccessLevel, "Manage", StringComparison.OrdinalIgnoreCase);
            var ok = manage
                ? await _accessAssignment.AssignCertificateManageAccessAsync(targetUserId, cert.CertificateId)
                : await _accessAssignment.AssignCertificateViewAccessAsync(targetUserId, cert.CertificateId);
            if (!ok) return BadRequest(new { error = "Failed to set permission — the user may not exist." });

            await _audit.LogAsync(manage ? AuditActionType.CertPermissionManageGranted : AuditActionType.CertPermissionViewGranted,
                _currentUser.User?.Id, _currentUser.User?.Username,
                "Certificate", cert.CertificateId.ToString(),
                new { TargetUserId = targetUserId, SerialNumber = serial, PermissionLevel = manage ? "Manage" : "View" },
                HttpContext.Connection.RemoteIpAddress?.ToString());

            return Ok(new { message = $"Set {(manage ? "manage" : "view")} access for user {targetUserId}.", userId = targetUserId, accessLevel = manage ? "Manage" : "View" });
        }

        /// <summary>Removes a user's ACL entry on a certificate (by serial). Implicit access via RBAC or
        /// being the original requestor is unaffected.</summary>
        [HttpPost("serial/{serial}/revoke-user")]
        [RequireStepUp(StepUpOps.UpdateCertAcl, "serial")]
        public async Task<IActionResult> RevokeBySerial(string serial, [FromBody] SetCertPermissionRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null) return Unauthorized();
            if (!Guid.TryParse(request.UserId, out var targetUserId))
                return BadRequest(new { error = "A valid userId is required." });

            var cert = await _db.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial);
            if (cert == null) return NotFound(new { error = "Certificate not found." });

            var ok = await _accessAssignment.RevokeCertificateAccessAsync(targetUserId, cert.CertificateId);
            if (!ok) return NotFound(new { error = "No ACL entry to revoke for this user." });

            await _audit.LogAsync(AuditActionType.CertPermissionRevoked, _currentUser.User?.Id, _currentUser.User?.Username,
                "Certificate", cert.CertificateId.ToString(),
                new { TargetUserId = targetUserId, SerialNumber = serial },
                HttpContext.Connection.RemoteIpAddress?.ToString());

            return Ok(new { message = $"Revoked ACL access for user {targetUserId}.", userId = targetUserId });
        }

        // Grant read or manage access
        [HttpPost("allow/view")]
        public async Task<IActionResult> GrantViewPermission([FromBody] PermissionChangeRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();
            Guid certId = new Guid(request.CertId);
            /*
            var cert = await _certStore.GetCertificateByIdAsync(certId);
            
            if (cert == null)
                return NotFound();
            */

            var result = await _accessAssignment.AssignCertificateViewAccessAsync(_currentUser.User.Id, certId);
            if (result)
            {
                await _audit.LogAsync(AuditActionType.CertPermissionViewGranted, _currentUser.User?.Id, _currentUser.User?.Username,
                    "Certificate", certId.ToString(),
                    new { TargetUserId = request.UserId, CertificateId = request.CertId, PermissionLevel = "View" },
                    HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"Granted view access to user {request.UserId} for cert {request.CertId}" });
            }
            return BadRequest();
        }

        [HttpPost("allow/manage")]
        public async Task<IActionResult> GrantManagePermission([FromBody] PermissionChangeRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();
            Guid certId = new Guid(request.CertId);


            var result = await _accessAssignment.AssignCertificateManageAccessAsync(_currentUser.User.Id, certId);
            if (result)
            {
                await _audit.LogAsync(AuditActionType.CertPermissionManageGranted, _currentUser.User?.Id, _currentUser.User?.Username,
                    "Certificate", certId.ToString(),
                    new { TargetUserId = request.UserId, CertificateId = request.CertId, PermissionLevel = "Manage" },
                    HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"Granted manage access to user {request.UserId} for cert {request.CertId}" });
            }
            return BadRequest();
        }

        // Downgrade manage to read
        [HttpPost("downgrade")]
        public async Task<IActionResult> DowngradePermission([FromBody] PermissionChangeRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();
            Guid certId = new Guid(request.CertId);


            var result = await _accessAssignment.DowngradeCertificateManageAccessAsync(_currentUser.User.Id, certId);
            if (result)
            {
                await _audit.LogAsync(AuditActionType.CertPermissionDowngraded, _currentUser.User?.Id, _currentUser.User?.Username,
                    "Certificate", certId.ToString(),
                    new { TargetUserId = request.UserId, CertificateId = request.CertId, FromLevel = "Manage", ToLevel = "View" },
                    HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"Downgraded access to view only for user {request.UserId} for cert {request.CertId}" });
            }
            return BadRequest();
        }

        // Revoke access
        [HttpPost("revoke")]
        public async Task<IActionResult> RevokePermission([FromBody] PermissionChangeRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();
            Guid certId = new Guid(request.CertId);


            var result = await _accessAssignment.RevokeCertificateAccessAsync(_currentUser.User.Id, certId);
            if (result)
            {
                await _audit.LogAsync(AuditActionType.CertPermissionRevoked, _currentUser.User?.Id, _currentUser.User?.Username,
                    "Certificate", certId.ToString(),
                    new { TargetUserId = request.UserId, CertificateId = request.CertId },
                    HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"Revoked access to view only for user {request.UserId} for cert {request.CertId}" });
            }
            return BadRequest();
        }
    }


}
