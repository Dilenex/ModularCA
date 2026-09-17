using ModularCA.Shared.Authorization;
using ModularCA.API.Filters;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.API.Middleware;
using ModularCA.API.Validation.Users;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Management;
using ModularCA.API.Startup;


namespace ModularCA.API.Controllers.v1.Admin.Management
{
    /// <summary>
    /// Admin endpoints for managing user accounts including creation, role assignment, and deletion.
    /// </summary>
    [ApiController]
    [Route("api/v1/admin/users")]
    [Authorize]
    [NodeRole(ProcessRole.Control)]
    public class AdminUserManagerController(
        ModularCADbContext dbContext,
        IUserManagementService userService,
        ICurrentUserService currentUser,
        IAuditService auditService,
        IDistributedCache cache,
        ISecurityAlertService alertService,
        IValidator<CreateUserRequest> createValidator,
        IValidator<UpdateUserRequest> updateValidator,
        IControlledUserCeremonyService controlledUserSvc) : ControllerBase
    {
        private readonly ModularCADbContext _dbContext = dbContext;
        private readonly IUserManagementService _userService = userService;
        private readonly IControlledUserCeremonyService _controlledUserSvc = controlledUserSvc;
        private readonly ICurrentUserService _currentUser = currentUser;
        private readonly IAuditService _audit = auditService;
        private readonly IDistributedCache _cache = cache;
        private readonly ISecurityAlertService _alertService = alertService;
        private readonly IValidator<CreateUserRequest> _createValidator = createValidator;
        private readonly IValidator<UpdateUserRequest> _updateValidator = updateValidator;

        /// <summary>
        /// Retrieves all user accounts. Read-only; accessible to auditors.
        /// </summary>
        [HttpGet]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetUsers()
        {
            // Scoped to the caller's tenants. The policy is CaAuditor with no CA in the route, which
            // the handler satisfies for a GET when the capability is held on ANY CA; and the service
            // has no tenant predicate. A single-CA auditor in one tenant could list every account
            // in every tenant, with group memberships (system groups included) and password expiry
            // dates: a ready-made target list for password spraying.
            var users = await ScopeToCallerAsync(await _userService.GetAllUsers());
            return Ok(users);
        }

        /// <summary>
        /// Retrieves a single user account by ID. Read-only; accessible to auditors.
        /// </summary>
        [HttpGet("{id:guid}")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetUserById(Guid id)
        {
            var user = await ScopeToCallerAsync(await _userService.GetUserById(id));
            if (user == null)
                return NotFound(new { message = $"User with ID {id} not found" });
            return Ok(user);
        }

        /// <summary>
        /// Retrieves a single user account by username. Read-only; accessible to auditors.
        /// </summary>
        [HttpGet("by-username/{username}")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetUserByUsername(string username)
        {
            var user = await ScopeToCallerAsync(await _userService.GetUserByUsername(username));
            if (user == null)
                return NotFound(new { message = $"User with username {username} not found" });
            return Ok(user);
        }

        /// <summary>
        /// Retrieves a single user account by email address. Read-only; accessible to auditors.
        /// </summary>
        [HttpGet("by-email")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetUserByEmail([FromQuery] string email)
        {
            var user = await ScopeToCallerAsync(await _userService.GetUserByEmail(email));
            if (user == null)
                return NotFound(new { message = $"User with email {email} not found" });
            return Ok(user);
        }

        /// <summary>
        /// Restricts a user list to accounts that share a tenant with the caller. System
        /// administrators see everyone.
        /// </summary>
        /// <remarks>
        /// Users carry no tenant of their own; tenancy is a property of the groups they belong to.
        /// An account is visible when at least one of its group memberships is in a group whose
        /// tenant the caller can access. An account with no memberships at all is visible only to
        /// system administrators, since nothing places it in any tenant.
        /// </remarks>
        private async Task<List<UserEntityDto>> ScopeToCallerAsync(List<UserEntityDto> users)
        {
            var tenantContext = HttpContext.RequestServices.GetRequiredService<ITenantContext>();
            if (tenantContext.IsSystemAdmin)
                return users;

            var accessible = tenantContext.AccessibleTenantIds;
            if (accessible.Count == 0)
                return [];

            var visibleGroupIds = await _dbContext.CaGroups
                .AsNoTracking()
                .Where(g => accessible.Contains(g.TenantId))
                .Select(g => g.Id)
                .ToHashSetAsync();

            return users
                .Where(u => u.Groups != null && u.Groups.Any(g => visibleGroupIds.Contains(g.GroupId)))
                .ToList();
        }

        /// <summary>
        /// Single-user form of <see cref="ScopeToCallerAsync(List{UserEntityDto})"/>. An account
        /// outside the caller's scope comes back as null, which the endpoints report as not found
        /// rather than forbidden, so a lookup by username or email cannot confirm that an account
        /// exists in another tenant.
        /// </summary>
        private async Task<UserEntityDto?> ScopeToCallerAsync(UserEntityDto? user)
        {
            if (user == null)
                return null;
            var visible = await ScopeToCallerAsync(new List<UserEntityDto> { user });
            return visible.Count == 1 ? user : null;
        }

        /// <summary>
        /// Creates a new user account. Requires CaAdmin policy and step-up MFA verification via X-MFA-Token header.
        /// </summary>
        [HttpPost]
        [Authorize]
        [RequireCaCapability(Capabilities.CaManage, CaTarget.AnyCa)]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.CreateUser))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            // Shape-validate username/email/name before touching the service.
            // Normalize identity fields to NFC so the DB row matches the form the login path will see.
            request.Username = UserFieldValidators.NormalizeIdentity(request.Username) ?? request.Username;
            request.Email = UserFieldValidators.NormalizeIdentity(request.Email) ?? request.Email;
            var createValidation = await _createValidator.ValidateAsync(request);
            if (!createValidation.IsValid)
                return BadRequest(new { error = string.Join("; ", createValidation.Errors.Select(e => e.ErrorMessage)) });

            // Membership assigned at creation goes through the same tier gate as every other
            // membership write. Checked BEFORE the account is created so a refusal cannot leave a
            // half-provisioned user behind.
            foreach (var groupId in request.GroupIds ?? new List<Guid>())
            {
                if (await AuthorizeGroupAssignmentAsync(groupId) is { } denied)
                    return denied;
            }

            var (success, error) = await _userService.CreateUser(request);
            if (success)
            {
                // Look up the created user to return their ID
                var created = await _userService.GetUserByUsername(request.Username);
                await _audit.LogAsync(AuditActionType.UserCreated, _currentUser.User?.Id, _currentUser.User?.Username,
                    "User", created?.Id.ToString(), new { request.Username, request.Email, request.GroupIds },
                    HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"User {request.Username} created", id = created?.Id });
            }
            return BadRequest(new { error = error ?? $"Failed to create user {request.Username}" });
        }

        /// <summary>
        /// Updates a user account (e.g. activate/deactivate). Requires CaAdmin policy and step-up MFA verification.
        /// </summary>
        [HttpPut("{id:guid}")]
        [Authorize(Policy = "CaAdmin")]
        public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserRequest request,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UpdateUser, id.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            // Shape-validate any username/email that the caller is changing.
            request.Username = UserFieldValidators.NormalizeIdentity(request.Username);
            request.Email = UserFieldValidators.NormalizeIdentity(request.Email);
            var updateValidation = await _updateValidator.ValidateAsync(request);
            if (!updateValidation.IsValid)
                return BadRequest(new { error = string.Join("; ", updateValidation.Errors.Select(e => e.ErrorMessage)) });

            if (_currentUser.User?.Id == id && request.IsActive == false)
                return BadRequest(new { error = "You cannot deactivate your own account" });
            if (!(await _userService.UpdateUser(id, request)))
                return NotFound(new { message = $"User with ID {id} not found" });
            // Drop any cached stamp so the disable/lock change propagates
            // to the next authenticated request instead of waiting 30 s for the cache TTL.
            await TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, id);
            await _audit.LogAsync(AuditActionType.UserUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                "User", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
            return Ok(new { message = $"User {id} updated" });
        }

        /// <summary>
        /// Deletes a user account. Self-deletion is blocked. Requires CaAdmin policy and step-up MFA verification.
        /// </summary>
        [HttpDelete("{id:guid}")]
        [Authorize(Policy = "CaAdmin")]
        public async Task<IActionResult> DeleteUser(Guid id,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.DeleteUser, id.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            if (_currentUser.User?.Id == id)
                return BadRequest(new { error = "You cannot delete your own account" });

            // Controlled-user gate: deleting a user who holds a controlled tier (admin/CA-admin)
            // requires a ceremony for non-super, with the last-controlled-user guard.
            var delTier = await _controlledUserSvc.GetDeletionTierAsync(id);
            if (delTier != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User!.Id))
            {
                if (await _controlledUserSvc.CountDominatingControlledUsersAsync(delTier.Value, id) == 0)
                    return BadRequest(new { error = "Refusing to delete the last controlled user of this scope." });
                if (!await _controlledUserSvc.CanInitiateAsync(_currentUser.User.Id, delTier.Value))
                    return StatusCode(403, new { error = "You cannot delete a user above your own tier." });

                var targetUsername = (await _userService.GetUserById(id))?.Username;
                var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                    new ModularCA.Shared.Models.ControlledUserChangeParameters
                    {
                        ChangeType = "DeleteUser",
                        TargetUserId = id,
                        TargetUsername = targetUsername,
                    },
                    delTier.Value,
                    _currentUser.User!.Id,
                    _currentUser.User!.Username ?? string.Empty);

                return Accepted(new
                {
                    ceremonyId,
                    requiresCeremony = true,
                    message = "Deleting this controlled user requires a controlled-user ceremony. "
                              + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
                });
            }

            if (await _userService.DeleteUser(id))
            {
                await _audit.LogAsync(AuditActionType.UserDeleted, _currentUser.User?.Id, _currentUser.User?.Username,
                    "User", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"User {id} deleted" });
            }
            return NotFound(new { message = $"User with ID {id} not found" });
        }

        /// <summary>
        /// Resets another user's password. Requires CaAdmin policy and step-up MFA verification via X-MFA-Token header.
        /// </summary>
        [HttpPost("{id:guid}/reset-password")]
        [Authorize(Policy = "CaAdmin")]
        public async Task<IActionResult> ResetUserPassword(Guid id,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();

            // Require step-up MFA verification for resetting another user's password
            if (_currentUser.User == null)
                return Unauthorized();
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ResetPassword, id.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            var newPassword = await _userService.ResetUserPassword(id);
            if (newPassword != null)
            {
                // Rotate the stamp cache so outstanding JWTs are rejected
                // on the next request rather than waiting out the TTL.
                await TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, id);
                await _audit.LogAsync(AuditActionType.UserPasswordReset, _currentUser.User?.Id, _currentUser.User?.Username,
                    "User", id.ToString(), sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
                _ = _alertService.RaiseAlertAsync("AdminPasswordReset", AlertSeverity.Warning, $"Password reset for user {id} by {_currentUser.User?.Username}", new { TargetUserId = id });
                return Ok(new { message = $"User {id} password reset", newPassword });
            }
            return NotFound(new { message = $"User with ID {id} not found" });
        }

        /// <summary>
        /// Removes all MFA methods (TOTP secrets and WebAuthn credentials) for a user,
        /// forcing them to re-enroll on next login. Requires step-up MFA verification
        /// via X-MFA-Token header. Requires SystemOperator authorization policy.
        /// </summary>
        [HttpPost("{id:guid}/reset-mfa")]
        [Authorize(Policy = "SystemOperator")]
        public async Task<IActionResult> ResetUserMfa(Guid id,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();

            if (_currentUser.User == null)
                return Unauthorized();
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ResetMfa, id.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            var user = await _dbContext.Users.FindAsync(id);
            if (user == null)
                return NotFound(new { message = $"User with ID {id} not found" });

            // Remove all TOTP secrets
            var totpSecrets = await _dbContext.TotpSecrets.Where(t => t.UserId == id).ToListAsync();
            if (totpSecrets.Count > 0)
                _dbContext.TotpSecrets.RemoveRange(totpSecrets);

            // Remove all WebAuthn credentials
            var webAuthnCreds = await _dbContext.Fido2Credentials.Where(c => c.UserId == id).ToListAsync();
            if (webAuthnCreds.Count > 0)
                _dbContext.Fido2Credentials.RemoveRange(webAuthnCreds);

            // Reset MFA enrollment timestamp so user is forced to re-enroll
            user.MfaEnrolledAt = null;

            await _dbContext.SaveChangesAsync();

            await _audit.LogAsync(AuditActionType.UserUpdated, _currentUser.User.Id, _currentUser.User.Username,
                "User", id.ToString(),
                new { Action = "MfaReset", TotpSecretsRemoved = totpSecrets.Count, WebAuthnCredentialsRemoved = webAuthnCreds.Count },
                HttpContext.Connection.RemoteIpAddress?.ToString());

            _ = _alertService.RaiseAlertAsync("UserMfaReset", AlertSeverity.Critical, $"MFA reset for user {id} by {_currentUser.User?.Username}", new { TargetUserId = id, TotpSecretsRemoved = totpSecrets.Count, WebAuthnCredentialsRemoved = webAuthnCreds.Count });
            return Ok(new
            {
                message = $"MFA reset for user {id}",
                totpSecretsRemoved = totpSecrets.Count,
                webAuthnCredentialsRemoved = webAuthnCreds.Count
            });
        }

        /// <summary>
        /// Tiered authorization for membership writes.
        /// <list type="number">
        /// <item><b>Self-assignment always refused</b> — prevents bypass loops where a user
        /// grants themselves into a higher tier.</item>
        /// <item><b>system-super</b> members: may modify any group (system or CA-scoped).</item>
        /// <item><b>system-admin</b> members (system-tenant, Administrator template): may
        /// modify any org-tenant CA-scoped group. Cannot touch system-tenant groups — that
        /// requires system-super.</item>
        /// <item><b>CA-scoped admins</b> (org_&lt;ca&gt;_admin): may modify only groups whose
        /// <c>CertificateAuthorityId</c> equals the CA they themselves admin. Cross-CA
        /// promotion is refused — Alice, admin of CA-A, cannot add Bob to the admin group
        /// of CA-B even though both groups are "non-system".</item>
        /// </list>
        /// Matches the industry norm (EJBCA per-CA access rules, ADCS per-CA Certificate
        /// Manager scope, OpenXPKI per-realm admins): within-CA delegation works, cross-CA
        /// and system-tier require explicit elevation.
        /// </summary>
        private async Task<IActionResult?> AuthorizeUserGroupChangeAsync(Guid groupId, Guid targetUserId)
        {
            if (_currentUser.User == null) return Unauthorized();
            if (targetUserId == _currentUser.User.Id)
                return BadRequest(new { error = "You cannot modify your own group membership. Ask a system-super admin to do it." });

            return await AuthorizeGroupAssignmentAsync(groupId);
        }

        /// <summary>
        /// The tier check itself, without the self-modification guard — that guard is meaningless
        /// when the target user does not exist yet.
        /// <para>
        /// Extracted so account creation can run the same gate. <c>CreateUser</c> assigns
        /// <c>GroupIds</c> at creation time and previously validated only that each group
        /// <em>existed</em>, while every other membership-write path (add, remove, and both bulk
        /// endpoints) called <see cref="AuthorizeUserGroupChangeAsync"/>. That made creation the
        /// one way to obtain a membership the caller is not entitled to grant: a CA-scoped
        /// operator could create an account directly in a system-tier group with a password of
        /// their choosing, then authenticate as it.
        /// </para>
        /// </summary>
        private async Task<IActionResult?> AuthorizeGroupAssignmentAsync(Guid groupId)
        {
            if (_currentUser.User == null) return Unauthorized();

            var group = await _dbContext.CaGroups.FindAsync(groupId);
            if (group == null) return NotFound(new { error = "Group not found" });

            // Resolve the caller's relevant memberships once.
            var callerId = _currentUser.User.Id;
            var callerGroups = await _dbContext.CaGroupMembers
                .Where(m => m.UserId == callerId)
                .Include(m => m.Group)
                .Select(m => new { m.Group!.Name, m.Group.IsSystemGroup, m.Group.IsSystemTierSuper, m.Group.CertificateAuthorityId, m.Group.TemplateName })
                .ToListAsync();

            // Tier checks read structural flags rather than literal group names so a
            // future bootstrap rename doesn't silently bypass the gate.
            var isSuper = callerGroups.Any(g => g.IsSystemTierSuper);
            if (isSuper) return null; // global override

            // System-tenant groups are only writable by system-super.
            if (group.IsSystemGroup)
                return StatusCode(403, new { error = "Modifying system-tenant group memberships requires system-super. system-admin/CaAdmin cannot grant system-tier access." });

            // system-admin members (Administrator template on a system-tenant group) retain
            // authority over ANY org-tenant CA-scoped group. Everyone else must be an admin
            // on the specific CA that owns the target group. system-admin tier = any system
            // group that is NOT the super tier.
            var isSystemAdmin = callerGroups.Any(g => g.IsSystemGroup && !g.IsSystemTierSuper);
            if (isSystemAdmin) return null;

            var targetCaId = group.CertificateAuthorityId;
            if (targetCaId == null)
                return StatusCode(403, new { error = "This group is not CA-scoped and requires system-admin or system-super to modify." });

            // CA-scoped admins: caller must be in an Administrator-template group for the
            // same CA as the target. This is the within-CA delegation path.
            var isAdminOnTargetCa = callerGroups.Any(g =>
                g.CertificateAuthorityId == targetCaId
                && string.Equals(g.TemplateName, "Administrator", StringComparison.OrdinalIgnoreCase));
            if (!isAdminOnTargetCa)
                return StatusCode(403, new { error = "Cross-CA group modification is not permitted. You can only manage memberships for groups on CAs where you are an admin." });

            return null;
        }

        /// <summary>
        /// Adds a user to a CA group by group ID. Requires CaAdmin policy and step-up MFA verification.
        /// </summary>
        [HttpPost("{id:guid}/groups/{groupId:guid}")]
        [Authorize(Policy = "CaAdmin")]
        public async Task<IActionResult> AddUserToGroup(Guid id, Guid groupId,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.AddGroupMember, id.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            var tierCheck = await AuthorizeUserGroupChangeAsync(groupId, id);
            if (tierCheck != null) return tierCheck;

            // Controlled-user gate: adding to a privilege-controlled group promotes a controlled
            // user — a non-super routes it through a ceremony (mirrors AdminGroupController.AddMember).
            var addGroup = await _dbContext.CaGroups.FindAsync(groupId);
            var addTier = addGroup != null ? _controlledUserSvc.ClassifyGroup(addGroup) : null;
            if (addTier != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User!.Id))
            {
                var targetUsername = (await _dbContext.Users.FindAsync(id))?.Username;
                var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                    new ModularCA.Shared.Models.ControlledUserChangeParameters
                    {
                        ChangeType = "AddGroupMember",
                        TargetUserId = id,
                        TargetUsername = targetUsername,
                        GroupId = groupId,
                        CertificateAuthorityId = addGroup!.CertificateAuthorityId,
                    },
                    addTier.Value, _currentUser.User!.Id, _currentUser.User!.Username ?? string.Empty);
                return Accepted(new
                {
                    ceremonyId,
                    requiresCeremony = true,
                    message = "Adding this member promotes a controlled user and requires a controlled-user ceremony. "
                              + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
                });
            }

            if (await _userService.AddUserToGroup(id, groupId, _currentUser.User?.Id))
            {
                // Group change rotates stamp — drop the cached entry.
                await TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, id);
                await _audit.LogAsync(AuditActionType.GroupMemberAdded, _currentUser.User?.Id, _currentUser.User?.Username,
                    "User", id.ToString(), new { GroupId = groupId },
                    HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"User {id} added to group {groupId}" });
            }
            return BadRequest(new { message = $"Failed to add user {id} to group {groupId}" });
        }

        /// <summary>
        /// Removes a user from a CA group by group ID. Requires CaAdmin policy and step-up MFA verification.
        /// </summary>
        [HttpDelete("{id:guid}/groups/{groupId:guid}")]
        [Authorize(Policy = "CaAdmin")]
        public async Task<IActionResult> RemoveUserFromGroup(Guid id, Guid groupId,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.RemoveGroupMember, id.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            var tierCheck = await AuthorizeUserGroupChangeAsync(groupId, id);
            if (tierCheck != null) return tierCheck;

            // Controlled-user gate: removing from a privilege-controlled group demotes a controlled
            // user — non-super routes it through a ceremony, with the last-controlled-user guard.
            var remGroup = await _dbContext.CaGroups.FindAsync(groupId);
            var remTier = remGroup != null ? _controlledUserSvc.ClassifyGroup(remGroup) : null;
            if (remTier != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User!.Id))
            {
                if (await _controlledUserSvc.CountDominatingControlledUsersAsync(remTier.Value, id) == 0)
                    return BadRequest(new { error = "Refusing to remove the last controlled user of this scope." });

                var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                    new ModularCA.Shared.Models.ControlledUserChangeParameters
                    {
                        ChangeType = "RemoveGroupMember",
                        TargetUserId = id,
                        GroupId = groupId,
                        CertificateAuthorityId = remGroup!.CertificateAuthorityId,
                    },
                    remTier.Value, _currentUser.User!.Id, _currentUser.User!.Username ?? string.Empty);
                return Accepted(new
                {
                    ceremonyId,
                    requiresCeremony = true,
                    message = "Removing this member demotes a controlled user and requires a controlled-user ceremony. "
                              + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
                });
            }

            if (await _userService.RemoveUserFromGroup(id, groupId))
            {
                // Group change rotates stamp — drop the cached entry.
                await TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, id);
                await _audit.LogAsync(AuditActionType.GroupMemberRemoved, _currentUser.User?.Id, _currentUser.User?.Username,
                    "User", id.ToString(), new { GroupId = groupId },
                    HttpContext.Connection.RemoteIpAddress?.ToString());
                return Ok(new { message = $"User {id} removed from group {groupId}" });
            }
            return BadRequest(new { message = $"Failed to remove user {id} from group {groupId}" });
        }

        /// <summary>
        /// Bulk add/remove a user's group memberships in one step-up-gated batch. ONE
        /// <see cref="StepUpOps.UpdateUserGroups"/> token authorizes the whole change (adds + removes),
        /// but each group is evaluated independently with the SAME per-group logic as
        /// <see cref="AddUserToGroup"/> / <see cref="RemoveUserFromGroup"/> — tier guard, controlled-user
        /// gate, and the last-controlled-user guard. A privileged add/remove spawns its OWN controlled-user
        /// ceremony, so a batch can start several ceremonies (one per privileged group) while applying
        /// uncontrolled changes directly. Never aborts on one group's failure; returns a per-group summary.
        /// </summary>
        [HttpPost("{id:guid}/groups/bulk")]
        [Authorize(Policy = "CaAdmin")]
        public async Task<IActionResult> BulkUpdateUserGroups(Guid id, [FromBody] BulkUserGroupsRequest request,
            [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();

            // ONE token authorizes the whole add+remove batch.
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UpdateUserGroups, id.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

            var user = await _dbContext.Users.FindAsync(id);
            if (user == null) return NotFound(new { error = "User not found." });

            var isSuper = await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id);
            var results = new List<object>();
            int added = 0, removed = 0, ceremonies = 0, skipped = 0;

            // ── adds ──
            foreach (var groupId in (request.AddGroupIds ?? new List<Guid>()).Distinct())
            {
                if (await AuthorizeUserGroupChangeAsync(groupId, id) != null) { results.Add(new { groupId, action = "add", status = "denied" }); skipped++; continue; }
                var grp = await _dbContext.CaGroups.FindAsync(groupId);
                if (grp == null) { results.Add(new { groupId, action = "add", status = "not_found" }); skipped++; continue; }

                var tier = _controlledUserSvc.ClassifyGroup(grp);
                if (tier != null && !isSuper)
                {
                    var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                        new ModularCA.Shared.Models.ControlledUserChangeParameters
                        {
                            ChangeType = "AddGroupMember", TargetUserId = id, TargetUsername = user.Username,
                            GroupId = groupId, CertificateAuthorityId = grp.CertificateAuthorityId,
                        },
                        tier.Value, _currentUser.User!.Id, _currentUser.User!.Username ?? string.Empty);
                    results.Add(new { groupId, action = "add", status = "ceremony", ceremonyId }); ceremonies++; continue;
                }

                if (await _userService.AddUserToGroup(id, groupId, _currentUser.User?.Id))
                {
                    await _audit.LogAsync(AuditActionType.GroupMemberAdded, _currentUser.User?.Id, _currentUser.User?.Username,
                        "User", id.ToString(), new { GroupId = groupId, Bulk = true }, HttpContext.Connection.RemoteIpAddress?.ToString());
                    results.Add(new { groupId, action = "add", status = "added" }); added++;
                }
                else { results.Add(new { groupId, action = "add", status = "failed" }); skipped++; }
            }

            // ── removes ──
            foreach (var groupId in (request.RemoveGroupIds ?? new List<Guid>()).Distinct())
            {
                if (await AuthorizeUserGroupChangeAsync(groupId, id) != null) { results.Add(new { groupId, action = "remove", status = "denied" }); skipped++; continue; }
                var grp = await _dbContext.CaGroups.FindAsync(groupId);
                if (grp == null) { results.Add(new { groupId, action = "remove", status = "not_found" }); skipped++; continue; }

                var tier = _controlledUserSvc.ClassifyGroup(grp);
                if (tier != null && !isSuper)
                {
                    if (await _controlledUserSvc.CountDominatingControlledUsersAsync(tier.Value, id) == 0)
                    { results.Add(new { groupId, action = "remove", status = "last_user" }); skipped++; continue; }

                    var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                        new ModularCA.Shared.Models.ControlledUserChangeParameters
                        {
                            ChangeType = "RemoveGroupMember", TargetUserId = id, GroupId = groupId, CertificateAuthorityId = grp.CertificateAuthorityId,
                        },
                        tier.Value, _currentUser.User!.Id, _currentUser.User!.Username ?? string.Empty);
                    results.Add(new { groupId, action = "remove", status = "ceremony", ceremonyId }); ceremonies++; continue;
                }

                if (await _userService.RemoveUserFromGroup(id, groupId))
                {
                    await _audit.LogAsync(AuditActionType.GroupMemberRemoved, _currentUser.User?.Id, _currentUser.User?.Username,
                        "User", id.ToString(), new { GroupId = groupId, Bulk = true }, HttpContext.Connection.RemoteIpAddress?.ToString());
                    results.Add(new { groupId, action = "remove", status = "removed" }); removed++;
                }
                else { results.Add(new { groupId, action = "remove", status = "failed" }); skipped++; }
            }

            if (added > 0 || removed > 0)
                await TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, id);

            return Ok(new { added, removed, ceremonies, skipped, results });
        }

    }
}
