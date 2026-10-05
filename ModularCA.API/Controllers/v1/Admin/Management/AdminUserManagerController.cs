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
        IControlledUserCeremonyService controlledUserSvc,
        ICaGroupAuthorizationService groupAuth) : ControllerBase
    {
        private readonly ModularCADbContext _dbContext = dbContext;
        private readonly IUserManagementService _userService = userService;
        private readonly IControlledUserCeremonyService _controlledUserSvc = controlledUserSvc;
        private readonly ICaGroupAuthorizationService _groupAuth = groupAuth;
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
            // Scoped to the caller's spaces. The policy is CaAuditor with no CA in the route, which
            // the handler satisfies for a GET when the capability is held on ANY CA; and the service
            // has no space predicate. A single-CA auditor in one space could list every account
            // in every space, with group memberships (system groups included) and password expiry
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
        /// Restricts a user list to accounts that share a space with the caller, and each account's
        /// group memberships to the groups inside the caller's fence. A caller whose cert.view
        /// fence is instance-wide sees everyone.
        /// </summary>
        /// <remarks>
        /// Users carry no space of their own; their spaces come from their group memberships and
        /// from space- or CA-scoped grants and roles on the user (owner decision Q2). An account is
        /// visible when one of those lies inside the caller's <see cref="SpaceFence"/> (an
        /// instance group, an instance CA or a global grant needs instance scope). An account with
        /// none is visible only to an instance-wide caller.
        /// </remarks>
        private async Task<List<UserEntityDto>> ScopeToCallerAsync(List<UserEntityDto> users)
        {
            var fence = SpaceFence.From(HttpContext, Capabilities.CertView);
            if (fence.InstanceWide)
                return users;
            if (fence.IsEmpty)
                return [];

            var visibleGroupIds = await _dbContext.CaGroups
                .AsNoTracking()
                .Where(fence.Predicate<ModularCA.Shared.Entities.CaGroupEntity>(g => g.SpaceId))
                .Select(g => g.Id)
                .ToHashSetAsync();

            var userIds = users.Select(u => u.Id).ToList();
            var grantScopes = await _dbContext.UserCapabilityGrants.AsNoTracking()
                .Where(g => userIds.Contains(g.UserId))
                .Select(g => new { g.UserId, g.SpaceId, g.CertificateAuthorityId })
                .ToListAsync();
            var roleScopes = await _dbContext.RoleAssignments.AsNoTracking()
                .Where(r => r.UserId != null && r.GroupId == null && userIds.Contains(r.UserId!.Value))
                .Select(r => new { UserId = r.UserId!.Value, r.SpaceId, r.CertificateAuthorityId })
                .ToListAsync();
            var scopes = grantScopes.Select(g => (g.UserId, g.SpaceId, g.CertificateAuthorityId))
                .Concat(roleScopes.Select(r => (r.UserId, r.SpaceId, r.CertificateAuthorityId)))
                .ToList();
            var caIds = scopes.Where(s => s.CertificateAuthorityId != null).Select(s => s.CertificateAuthorityId!.Value).Distinct().ToList();
            var caSpaces = await _dbContext.CertificateAuthorities.AsNoTracking()
                .Where(ca => caIds.Contains(ca.Id))
                .ToDictionaryAsync(ca => ca.Id, ca => ca.SpaceId);
            var grantVisible = scopes
                .Where(s => s.CertificateAuthorityId is Guid caId
                    ? caSpaces.TryGetValue(caId, out var caSpace) && fence.Allows(caSpace)
                    : fence.Allows(s.SpaceId))
                .Select(s => s.UserId)
                .ToHashSet();

            var visible = new List<UserEntityDto>();
            foreach (var u in users)
            {
                var groups = u.Groups?.Where(g => visibleGroupIds.Contains(g.GroupId)).ToList() ?? [];
                if (groups.Count == 0 && !grantVisible.Contains(u.Id))
                    continue;
                u.Groups = groups;
                visible.Add(u);
            }
            return visible;
        }

        /// <summary>
        /// Single-user form of <see cref="ScopeToCallerAsync(List{UserEntityDto})"/>. An account
        /// outside the caller's scope comes back as null, which the endpoints report as not found
        /// rather than forbidden, so a lookup by username or email cannot confirm that an account
        /// exists in another space.
        /// </summary>
        private async Task<UserEntityDto?> ScopeToCallerAsync(UserEntityDto? user)
        {
            if (user == null)
                return null;
            var visible = await ScopeToCallerAsync(new List<UserEntityDto> { user });
            return visible.Count == 1 ? user : null;
        }

        /// <summary>
        /// Creates a new user account. Requires ca.manage on some CA and step-up MFA verification via X-MFA-Token header.
        /// Each requested group needs the right on that group's own scope
        /// (<see cref="AuthorizeGroupAssignmentAsync"/>, 403 otherwise), and a group that confers a
        /// controlled tier is refused (403) unless the caller is system-super. No groups requested means no groups.
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
            var callerIsSuper = await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id);
            foreach (var groupId in request.GroupIds ?? new List<Guid>())
            {
                if (await AuthorizeGroupAssignmentAsync(groupId) is { } denied)
                    return denied;

                // A controlled membership needs a ceremony, which has no path for an account that
                // does not exist yet; otherwise the creator would choose the password of a new admin.
                var group = await _dbContext.CaGroups.FindAsync(groupId);
                if (!callerIsSuper && group != null && await _controlledUserSvc.ClassifyGroupAsync(group) != null)
                    return StatusCode(403, new
                    {
                        error = $"Group '{group.DisplayName ?? group.Name}' confers a privileged tier. Create the user without it, "
                                + "then add the membership, which goes through a controlled-user ceremony."
                    });
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
        /// Only identity fields whose value differs from the account's are applied. Changing one
        /// (username, email, enabled, locked, password expiry, forced change) on another account
        /// needs a caller who dominates every tier it holds (403 otherwise); when that account holds
        /// a controlled tier and the caller is not system-super, the whole update opens a
        /// controlled-user ceremony instead (202 with the ceremony id). Disabling or locking the
        /// last other active dominator of the account's scope is refused (400), as deletion is.
        /// A password is never set here (400): use reset-password. An empty or whitespace username
        /// or email is refused (400). Unlocking also clears a temporary lockout and the failed-login
        /// count. An identity-altering change to another account with a pending promotion is
        /// refused (409) unless the caller is system-super.
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
            if ((request.Username != null && string.IsNullOrWhiteSpace(request.Username))
                || (request.Email != null && string.IsNullOrWhiteSpace(request.Email)))
                return BadRequest(new { error = "Username and email cannot be empty. Omit a field to leave it unchanged." });
            var updateValidation = await _updateValidator.ValidateAsync(request);
            if (!updateValidation.IsValid)
                return BadRequest(new { error = string.Join("; ", updateValidation.Errors.Select(e => e.ErrorMessage)) });
            if (request.Password != null)
                return BadRequest(new { error = "A password cannot be set here. Use reset-password." });

            if (_currentUser.User?.Id == id && request.IsActive == false)
                return BadRequest(new { error = "You cannot deactivate your own account" });

            var target = await _dbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
            if (target == null)
                return NotFound(new { message = $"User with ID {id} not found" });
            var change = new ModularCA.Shared.Models.ControlledIdentityChange
            {
                Username = request.Username != null && request.Username != target.Username ? request.Username : null,
                Email = request.Email != null && request.Email != target.Email ? request.Email : null,
                IsActive = request.IsActive != null && request.IsActive != target.IsActive ? request.IsActive : null,
                IsLocked = request.IsLocked != null
                           && (request.IsLocked != target.IsLocked || (request.IsLocked == false && target.LockoutEndUtc > DateTime.UtcNow))
                    ? request.IsLocked : null,
                PasswordNeverExpires = request.PasswordNeverExpires != null && request.PasswordNeverExpires != target.PasswordNeverExpires ? request.PasswordNeverExpires : null,
                PasswordChangeOnNextLogon = request.PasswordChangeOnNextLogon != null && request.PasswordChangeOnNextLogon != target.PasswordChangeOnNextLogon ? request.PasswordChangeOnNextLogon : null,
            };
            var altersIdentity = change.Username != null || change.Email != null || change.IsActive != null || change.IsLocked != null
                || change.PasswordNeverExpires != null || change.PasswordChangeOnNextLogon != null;
            change.FirstName = request.FirstName;
            change.LastName = request.LastName;
            change.DisplayName = request.DisplayName;

            if (altersIdentity)
            {
                if (await AuthorizeAccountAdministrationAsync(id) is { } denied)
                    return denied;
                if (change.RemovesAccess
                    && await _controlledUserSvc.GetDeletionTierAsync(id) is { } tier
                    && await _controlledUserSvc.CountDominatingControlledUsersAsync(tier, id, actorUserId: _currentUser.User!.Id) == 0)
                    return BadRequest(new { error = "Refusing to disable or lock the last controlled user of this scope." });
                if (await OpenAccountCeremonyAsync(id, target.Username,
                        new ModularCA.Shared.Models.ControlledUserChangeParameters { ChangeType = "UpdateIdentity", Identity = change },
                        "Changing this controlled user's account") is { } accepted)
                    return accepted;
                if (await RefuseWhilePromotionPendingAsync(id) is { } pending)
                    return pending;
            }

            var effective = new UpdateUserRequest
            {
                Username = change.Username, Email = change.Email, FirstName = change.FirstName, LastName = change.LastName,
                DisplayName = change.DisplayName, IsActive = change.IsActive, IsLocked = change.IsLocked,
                PasswordNeverExpires = change.PasswordNeverExpires, PasswordChangeOnNextLogon = change.PasswordChangeOnNextLogon,
            };
            if (!(await _userService.UpdateUser(id, effective)))
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
        /// Deleting a controlled user is refused for every caller when no one other than the caller would
        /// still dominate its tier; otherwise non-super opens a ceremony.
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
            if (delTier != null
                && await _controlledUserSvc.CountDominatingControlledUsersAsync(delTier.Value, id, actorUserId: _currentUser.User!.Id) == 0)
                return BadRequest(new { error = "Refusing to delete the last controlled user of this scope." });
            if (delTier != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User!.Id))
            {
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
        /// Refused (403) when the target holds a controlled tier the caller does not dominate. When it
        /// holds any controlled tier and the caller is not system-super, opens a controlled-user
        /// ceremony instead (202 with the ceremony id, no password); the temporary password is then
        /// generated at execute and returned only to whoever executes it. Refused (409) for another
        /// account with a pending promotion unless the caller is system-super.
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

            var targetUsername = await _dbContext.Users.AsNoTracking().Where(u => u.Id == id).Select(u => u.Username).FirstOrDefaultAsync();
            if (targetUsername == null)
                return NotFound(new { message = $"User with ID {id} not found" });
            if (await AuthorizeAccountAdministrationAsync(id) is { } denied)
                return denied;
            if (await OpenAccountCeremonyAsync(id, targetUsername,
                    new ModularCA.Shared.Models.ControlledUserChangeParameters { ChangeType = "ResetPassword" },
                    "Resetting this controlled user's password") is { } accepted)
                return accepted;
            if (await RefuseWhilePromotionPendingAsync(id) is { } pending)
                return pending;

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
        /// via X-MFA-Token header. Requires SystemOperator authorization policy. Refused (403) when
        /// the target holds a controlled tier the caller does not dominate. When it holds any
        /// controlled tier and the caller is not system-super, opens a controlled-user ceremony
        /// instead (202 with the ceremony id). Refused (409) for another account with a pending
        /// promotion unless the caller is system-super. A reset ends the account's sessions.
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

            var targetUsername = await _dbContext.Users.AsNoTracking().Where(u => u.Id == id).Select(u => u.Username).FirstOrDefaultAsync();
            if (targetUsername == null)
                return NotFound(new { message = $"User with ID {id} not found" });

            if (await AuthorizeAccountAdministrationAsync(id) is { } denied)
                return denied;
            if (await OpenAccountCeremonyAsync(id, targetUsername,
                    new ModularCA.Shared.Models.ControlledUserChangeParameters { ChangeType = "ResetMfa" },
                    "Resetting this controlled user's MFA") is { } accepted)
                return accepted;
            if (await RefuseWhilePromotionPendingAsync(id) is { } pending)
                return pending;

            if (await _userService.ResetUserMfa(id) is not { } removed)
                return NotFound(new { message = $"User with ID {id} not found" });
            await TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, id);

            await _audit.LogAsync(AuditActionType.UserUpdated, _currentUser.User.Id, _currentUser.User.Username,
                "User", id.ToString(),
                new { Action = "MfaReset", removed.TotpSecretsRemoved, removed.WebAuthnCredentialsRemoved },
                HttpContext.Connection.RemoteIpAddress?.ToString());

            _ = _alertService.RaiseAlertAsync("UserMfaReset", AlertSeverity.Critical, $"MFA reset for user {id} by {_currentUser.User?.Username}", new { TargetUserId = id, removed.TotpSecretsRemoved, removed.WebAuthnCredentialsRemoved });
            return Ok(new
            {
                message = $"MFA reset for user {id}",
                totpSecretsRemoved = removed.TotpSecretsRemoved,
                webAuthnCredentialsRemoved = removed.WebAuthnCredentialsRemoved
            });
        }

        /// <summary>
        /// Tier gate for identity-altering administration of another account (password reset,
        /// MFA reset, activation/lock/username/email changes). Self-targeting is left to the
        /// endpoint's existing rules. Returns a 403 when the target holds a controlled tier the
        /// caller does not dominate, or is system-super and the caller is not. Passing it does not
        /// mean the change applies directly; see <see cref="OpenAccountCeremonyAsync"/>.
        /// </summary>
        private async Task<IActionResult?> AuthorizeAccountAdministrationAsync(Guid targetUserId)
        {
            if (_currentUser.User == null) return Unauthorized();
            if (targetUserId == _currentUser.User.Id) return null;
            if (await _controlledUserSvc.CanAdministerAccountAsync(_currentUser.User.Id, targetUserId))
                return null;
            return StatusCode(403, new
            {
                error = "This account holds a privileged tier you do not dominate. Only a system-super, "
                        + "or an administrator whose tier dominates every tier the account holds, can request a change to its credentials or account state."
            });
        }

        /// <summary>
        /// Opens a controlled-user ceremony for an identity-altering change to another account and
        /// returns 202 with its id, when the caller is not system-super and the account holds a
        /// controlled tier: a peer could otherwise take over an approver and satisfy a quorum alone.
        /// The ceremony is minted at the covering tier of the account's holdings; 403 when the caller
        /// does not dominate it. Null when the change applies directly: the caller's own account, a
        /// system-super caller, or an account holding no controlled tier. Call it after
        /// <see cref="AuthorizeAccountAdministrationAsync"/>.
        /// </summary>
        private async Task<IActionResult?> OpenAccountCeremonyAsync(Guid targetUserId, string? targetUsername,
            ModularCA.Shared.Models.ControlledUserChangeParameters parameters, string what)
        {
            var actor = _currentUser.User!;
            if (targetUserId == actor.Id) return null;
            var tier = await _controlledUserSvc.GetDeletionTierAsync(targetUserId);
            if (tier == null || await _controlledUserSvc.IsSuperAsync(actor.Id)) return null;
            if (!await _controlledUserSvc.CanInitiateAsync(actor.Id, tier.Value))
                return StatusCode(403, new { error = "You cannot change the account of a user above your own tier." });

            parameters.TargetUserId = targetUserId;
            parameters.TargetUsername = targetUsername;
            var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(parameters, tier.Value, actor.Id, actor.Username ?? string.Empty);
            return Accepted(new
            {
                ceremonyId,
                requiresCeremony = true,
                message = what + " requires a controlled-user ceremony. "
                          + "Approve via /api/v1/admin/ceremonies/" + ceremonyId + "/approve."
            });
        }

        /// <summary>
        /// 409 when a promotion of <paramref name="targetUserId"/> is pending or approved and the caller
        /// is neither that user nor system-super: resetting the credentials of an account about to
        /// become an approver would let the caller sign in as it once the promotion executes. Null
        /// otherwise.
        /// </summary>
        private async Task<IActionResult?> RefuseWhilePromotionPendingAsync(Guid targetUserId)
        {
            var actor = _currentUser.User!;
            if (targetUserId == actor.Id || await _controlledUserSvc.IsSuperAsync(actor.Id)) return null;
            if (!await _controlledUserSvc.HasOpenPromotionAsync(targetUserId)) return null;
            return Conflict(new
            {
                error = "A promotion of this user is pending. Their password, MFA and account cannot be changed until it is "
                        + "executed or rejected, or a system-super makes the change."
            });
        }

        /// <summary>
        /// Authorization for membership writes: self-assignment is always refused (it would let a
        /// user grant themselves into a higher tier), then <see cref="AuthorizeGroupAssignmentAsync"/>
        /// requires the right on the target group's own scope.
        /// </summary>
        private async Task<IActionResult?> AuthorizeUserGroupChangeAsync(Guid groupId, Guid targetUserId)
        {
            if (_currentUser.User == null) return Unauthorized();
            if (targetUserId == _currentUser.User.Id)
                return BadRequest(new { error = "You cannot modify your own group membership. Ask a system-super admin to do it." });

            return await AuthorizeGroupAssignmentAsync(groupId);
        }

        /// <summary>
        /// The scope check itself, without the self-modification guard, which is meaningless when
        /// the target user does not exist yet; account creation runs it for every requested group.
        /// The caller needs the right on the target group's own scope, read badge-aware from every
        /// grant source (<see cref="GroupAssignmentAccess"/>): system-super for a system group,
        /// <c>group.manage</c> on a CA group's CA or across a space-wide group's space, and a system
        /// administrator for any other instance group. 404 for a missing group, 403 otherwise.
        /// <para>
        /// Membership of an unrelated group never counts. Before this, any system group (a system
        /// auditor's included) read as system admin, so an auditor who operated one CA could create
        /// an account with a password of their choosing in another space's groups, then sign in as it.
        /// </para>
        /// </summary>
        private async Task<IActionResult?> AuthorizeGroupAssignmentAsync(Guid groupId)
        {
            if (_currentUser.User == null) return Unauthorized();

            var group = await _dbContext.CaGroups.FindAsync(groupId);
            if (group == null) return NotFound(new { error = "Group not found" });

            var refusal = await GroupAssignmentAccess.RefusalAsync(_groupAuth, _controlledUserSvc, _currentUser.User.Id, group);
            return refusal == null ? null : StatusCode(403, new { error = refusal });
        }

        /// <summary>
        /// Adds a user to a CA group by group ID. Requires CaAdmin policy and step-up MFA verification.
        /// A controlled membership added by a non-super opens a ceremony (202); 409 when the caller
        /// reset the user's password or MFA in the last 30 days.
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
            var addTier = addGroup != null ? await _controlledUserSvc.ClassifyGroupAsync(addGroup) : null;
            if (addTier != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User!.Id))
            {
                var targetUsername = (await _dbContext.Users.FindAsync(id))?.Username;
                Guid ceremonyId;
                try
                {
                    ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                        new ModularCA.Shared.Models.ControlledUserChangeParameters
                        {
                            ChangeType = "AddGroupMember",
                            TargetUserId = id,
                            TargetUsername = targetUsername,
                            GroupId = groupId,
                            CertificateAuthorityId = addGroup!.CertificateAuthorityId,
                        },
                        addTier.Value, _currentUser.User!.Id, _currentUser.User!.Username ?? string.Empty);
                }
                catch (ControlledUserInitiationRefusedException ex)
                {
                    return Conflict(new { error = ex.Message });
                }
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
            var remTier = remGroup != null ? await _controlledUserSvc.ClassifyGroupAsync(remGroup) : null;
            if (remTier != null
                && await _controlledUserSvc.CountDominatingControlledUsersAsync(remTier.Value, id, actorUserId: _currentUser.User!.Id) == 0)
                return BadRequest(new { error = "Refusing to remove the last controlled user of this scope." });
            if (remTier != null && !await _controlledUserSvc.IsSuperAsync(_currentUser.User!.Id))
            {
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
        /// uncontrolled changes directly. Never aborts on one group's failure; returns a per-group summary,
        /// where a change the caller may not open, or whose ceremony nobody else could approve, is
        /// <c>refused</c>.
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

                var tier = await _controlledUserSvc.ClassifyGroupAsync(grp);
                if (tier != null && !isSuper)
                {
                    try
                    {
                        var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                            new ModularCA.Shared.Models.ControlledUserChangeParameters
                            {
                                ChangeType = "AddGroupMember", TargetUserId = id, TargetUsername = user.Username,
                                GroupId = groupId, CertificateAuthorityId = grp.CertificateAuthorityId,
                            },
                            tier.Value, _currentUser.User!.Id, _currentUser.User!.Username ?? string.Empty);
                        results.Add(new { groupId, action = "add", status = "ceremony", ceremonyId }); ceremonies++;
                    }
                    catch (ControlledUserInitiationRefusedException ex)
                    {
                        results.Add(new { groupId, action = "add", status = "refused", error = ex.Message }); skipped++;
                    }
                    catch (ModularCA.Shared.Errors.CeremonyQuorumUnreachableException ex)
                    {
                        results.Add(new { groupId, action = "add", status = "refused", error = ex.Message }); skipped++;
                    }
                    continue;
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

                var tier = await _controlledUserSvc.ClassifyGroupAsync(grp);
                if (tier != null && await _controlledUserSvc.CountDominatingControlledUsersAsync(tier.Value, id, actorUserId: _currentUser.User!.Id) == 0)
                { results.Add(new { groupId, action = "remove", status = "last_user" }); skipped++; continue; }
                if (tier != null && !isSuper)
                {
                    try
                    {
                        var ceremonyId = await _controlledUserSvc.InitiateChangeAsync(
                            new ModularCA.Shared.Models.ControlledUserChangeParameters
                            {
                                ChangeType = "RemoveGroupMember", TargetUserId = id, GroupId = groupId, CertificateAuthorityId = grp.CertificateAuthorityId,
                            },
                            tier.Value, _currentUser.User!.Id, _currentUser.User!.Username ?? string.Empty);
                        results.Add(new { groupId, action = "remove", status = "ceremony", ceremonyId }); ceremonies++;
                    }
                    catch (ModularCA.Shared.Errors.CeremonyQuorumUnreachableException ex)
                    {
                        results.Add(new { groupId, action = "remove", status = "refused", error = ex.Message }); skipped++;
                    }
                    continue;
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
