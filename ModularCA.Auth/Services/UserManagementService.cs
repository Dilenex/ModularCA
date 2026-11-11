using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Utils;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;

namespace ModularCA.Auth.Services
{
    /// <summary>
    /// Manages user accounts and CA group memberships using the group-role authorization model.
    /// </summary>
    public class UserManagementService : IUserManagementService
    {
        private readonly ModularCADbContext _dbContext;
        private readonly ILogger<UserManagementService> _logger;
        private readonly SystemConfig _config;
        private readonly ISecurityPolicyService _securityPolicy;
        private readonly IPasswordPolicyService _passwordPolicy;
        private readonly ISshLoginNameService? _sshLoginNames;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserManagementService"/> class.
        /// <paramref name="sshLoginNames"/> revokes SSH certificates when a user is disabled,
        /// renamed, deleted or leaves a group; without it nothing is revoked.
        /// </summary>
        public UserManagementService(
            ModularCADbContext dbContext,
            ILogger<UserManagementService> logger,
            SystemConfig config,
            ISecurityPolicyService securityPolicy,
            IPasswordPolicyService passwordPolicy,
            ISshLoginNameService? sshLoginNames = null)
        {
            _dbContext = dbContext;
            _logger = logger;
            _config = config;
            _securityPolicy = securityPolicy;
            _passwordPolicy = passwordPolicy;
            _sshLoginNames = sshLoginNames;
        }

        /// <summary>
        /// Creates a new user and assigns them to the groups specified in <paramref name="request"/>.GroupIds.
        /// If no groups are specified, the user is created with no group memberships.
        /// </summary>
        public async Task<(bool Success, string? Error)> CreateUser(CreateUserRequest request)
        {
            // A deleted account that was retained for its history keeps its username for good.
            if (await _dbContext.Users.IgnoreQueryFilters().Where(u => u.Username == request.Username)
                    .Select(u => (bool?)u.IsDeleted).FirstOrDefaultAsync() is { } taken)
            {
                _logger.LogWarning("Attempted to create user with existing username {Username}", request.Username);
                return (false, taken
                    ? $"Username '{request.Username}' belonged to a deleted account whose history is kept, and cannot be used again"
                    : $"Username '{request.Username}' already exists");
            }
            if (await _dbContext.Users.AnyAsync(u => u.Email == request.Email))
            {
                _logger.LogWarning("Attempted to create user with existing email {Email}", request.Email);
                return (false, $"Email '{request.Email}' already exists");
            }

            // Every other path that sets a password runs it through the policy: setup, the
            // bootstrap seeder, self-service change, the forced change at login, and
            // UpdateUserPassword below. This one hashed whatever it was given, so an
            // administrator, or a script holding an admin token, could create an operator
            // with the password "a" and no forced rotation.
            var (passwordOk, passwordErrors) = await _passwordPolicy.ValidateAsync(request.Password);
            if (!passwordOk)
            {
                _logger.LogWarning("User creation for {Username} rejected by password policy: {Errors}",
                    request.Username, string.Join("; ", passwordErrors));
                return (false, "Password does not meet policy requirements: " + string.Join("; ", passwordErrors));
            }

            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                var newUser = new UserEntity
                {
                    Username = request.Username,
                    PasswordHash = PasswordUtil.HashPassword(request.Password),
                    Email = request.Email,
                    CreatedAt = DateTime.UtcNow,
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    DisplayName = string.IsNullOrWhiteSpace(request.DisplayName)
                        ? $"{request.FirstName} {request.LastName}".Trim()
                        : request.DisplayName,
                    IsActive = request.IsActive ?? true,
                    IsLocked = request.IsLocked ?? false,
                    PasswordNeverExpires = request.PasswordNeverExpires ?? false,
                };
                _dbContext.Users.Add(newUser);

                // Only the requested groups; an account created without groups has none.
                var groupIds = request.GroupIds;
                if (groupIds != null)
                {
                    foreach (var groupId in groupIds)
                    {
                        var groupExists = await _dbContext.CaGroups.AnyAsync(g => g.Id == groupId);
                        if (!groupExists)
                        {
                            _logger.LogWarning("Group {GroupId} not found when creating user {Username}", groupId, request.Username);
                            continue;
                        }

                        _dbContext.CaGroupMembers.Add(new CaGroupMemberEntity
                        {
                            GroupId = groupId,
                            UserId = newUser.Id,
                            AddedAt = DateTime.UtcNow,
                        });
                    }
                }

                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }

            return (true, null);
        }

        /// <summary>
        /// Updates an existing user's profile fields (username, email, name, active/locked status,
        /// password-expiry exemption, forced change at next logon, password source). <see cref="UpdateUserRequest.Password"/>
        /// is never applied; passwords change only through reset or the user's own change. An empty
        /// or whitespace username or email is left unchanged. A username or email change, enabling,
        /// disabling, locking or unlocking rotates the security stamp, and enabling, disabling,
        /// locking, unlocking or a password source change also revokes every refresh token; an unlock (IsLocked false)
        /// also clears the failed-login count and any temporary lockout. Disabling revokes every
        /// live SSH certificate issued for the user, and so does a username change, since their
        /// key id is the old username.
        /// </summary>
        /// <remarks>
        /// The uniqueness checks exclude the user being updated. Without that exclusion a PUT
        /// carrying the account's own current username or email matched the account itself and
        /// returned false, which the controller reports as 404 "user not found" — so disabling a
        /// compromised account failed unless the admin also changed both the username and the
        /// email in the same request. This method holds the only assignment of
        /// <see cref="UserEntity.IsActive"/> from a request in the solution, so that failure left
        /// the account enabled and skipped the stamp rotation and audit record below.
        ///
        /// A null field means "leave unchanged", so it is not a value to check for collisions.
        /// </remarks>
        public async Task<bool> UpdateUser(Guid userId, UpdateUserRequest request)
        {
            if (!string.IsNullOrEmpty(request.Username)
                && await _dbContext.Users.IgnoreQueryFilters().AnyAsync(u => u.Id != userId && u.Username == request.Username))
            {
                _logger.LogWarning("Attempted to update user {UserId} with existing username {Username}", userId, request.Username);
                return false;
            }
            if (!string.IsNullOrEmpty(request.Email)
                && await _dbContext.Users.AnyAsync(u => u.Id != userId && u.Email == request.Email))
            {
                _logger.LogWarning("Attempted to update user {UserId} with existing email {Email}", userId, request.Email);
                return false;
            }
            var user = await _dbContext.Users.FindAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found for update", userId);
                return false;
            }
            var wasActive = user.IsActive;
            var wasLocked = user.IsLocked;
            var previousSource = user.PasswordSource;
            var previousUsername = user.Username;
            var identityChanged = (!string.IsNullOrWhiteSpace(request.Username) && request.Username != user.Username)
                                  || (!string.IsNullOrWhiteSpace(request.Email) && request.Email != user.Email);
            if (!string.IsNullOrWhiteSpace(request.Username)) user.Username = request.Username;
            if (!string.IsNullOrWhiteSpace(request.Email)) user.Email = request.Email;
            user.FirstName = request.FirstName ?? user.FirstName;
            user.LastName = request.LastName ?? user.LastName;
            // String concatenation never yields null, so `(request.FirstName + " " + request.LastName)`
            // evaluates to the single space " " when both are omitted — which made the
            // `?? user.DisplayName` fallback unreachable and blanked the display name on EVERY
            // partial update. Toggling a user's active state from the admin UI (which PUTs only
            // {"isActive": false}) wiped their name. Only derive a name when a name part was
            // actually supplied.
            user.DisplayName = request.DisplayName
                ?? (request.FirstName != null || request.LastName != null
                        ? $"{request.FirstName ?? user.FirstName} {request.LastName ?? user.LastName}".Trim()
                        : null)
                ?? user.DisplayName;
            user.IsActive = request.IsActive ?? user.IsActive;
            user.IsLocked = request.IsLocked ?? user.IsLocked;
            user.PasswordNeverExpires = request.PasswordNeverExpires ?? user.PasswordNeverExpires;
            user.PasswordChangeOnNextLogon = request.PasswordChangeOnNextLogon ?? user.PasswordChangeOnNextLogon;
            user.PasswordSource = request.PasswordSource ?? user.PasswordSource;
            // An unlock starts the failure count afresh; otherwise one wrong password re-locks.
            if (request.IsLocked == false)
            {
                user.FailedLoginAttempts = 0;
                user.LockoutEndUtc = null;
            }

            // A new username or email only makes access tokens stale: the stamp rotates so the
            // client refreshes and picks up the new claims, and its sessions carry on.
            if (identityChanged)
                user.SecurityStamp = Guid.NewGuid().ToString();

            // End the account's sessions whenever an admin toggles
            // IsActive or IsLocked so outstanding JWTs invalidate on the next request
            // rather than waiting out their TTL. A password source change switches which password
            // signs the account in, a credential change like a reset, so it ends sessions too.
            if (wasActive != user.IsActive || wasLocked != user.IsLocked || previousSource != user.PasswordSource)
            {
                // The stamp rotates and every refresh token is revoked, so the next /auth/refresh
                // attempt can't re-mint a valid JWT. Saved below with the change itself.
                await UserSessionTermination.EndAllSessionsAsync(_dbContext, user, DateTime.UtcNow);
            }

            var renamed = !string.Equals(previousUsername, user.Username, StringComparison.Ordinal);
            _dbContext.Users.Update(user);
            var saved = await _dbContext.SaveChangesAsync() > 0;
            if (saved && _sshLoginNames != null)
            {
                if (wasActive && !user.IsActive)
                    await _sshLoginNames.RevokeAllOfUserAsync(userId, "the user was disabled");
                else if (renamed)
                    await _sshLoginNames.RevokeAllOfUserAsync(userId, "the user was renamed");
            }
            return saved;
        }

        /// <inheritdoc />
        /// <remarks>
        /// A realm's foreign key to its enrolment account neither cascades nor clears, and the
        /// realm cannot enrol without the account, so the realm is moved to another account first.
        /// </remarks>
        public async Task<string?> DeletionBlockerAsync(Guid userId)
        {
            var realms = await _dbContext.KerberosRealms.CountAsync(k => k.EnrollmentUserId == userId);
            return realms == 0
                ? null
                : $"This account cannot be deleted: {realms} Kerberos realm(s) enrol through it. "
                  + "Give each realm another enrolment account first.";
        }

        /// <inheritdoc />
        public async Task<string?> RetainedHistoryAsync(Guid userId)
        {
            var requests = await _dbContext.CertificateRequests.CountAsync(r => r.RequestorUserId == userId);
            var approvals = await _dbContext.CsrApprovals.CountAsync(a => a.ApproverId == userId);
            var held = new List<string>();
            if (requests > 0) held.Add($"{requests} certificate request(s) it made");
            if (approvals > 0) held.Add($"{approvals} approval(s) it gave");
            return held.Count == 0 ? null : string.Join(" and ", held);
        }

        /// <inheritdoc />
        public async Task<List<RetainedAccountDto>> GetRetainedAccounts()
        {
            var accounts = await _dbContext.Users.IgnoreQueryFilters().AsNoTracking()
                .Where(u => u.IsDeleted)
                .OrderByDescending(u => u.DeletedAt)
                .Select(u => new RetainedAccountDto { Id = u.Id, Username = u.Username, DisplayName = u.DisplayName, DeletedAt = u.DeletedAt })
                .ToListAsync();
            if (accounts.Count == 0)
                return accounts;
            var ids = accounts.Select(a => a.Id).ToList();
            var requests = await _dbContext.CertificateRequests.AsNoTracking()
                .Where(r => r.RequestorUserId != null && ids.Contains(r.RequestorUserId.Value))
                .GroupBy(r => r.RequestorUserId!.Value)
                .Select(g => new { g.Key, Count = g.Count() })
                .ToDictionaryAsync(g => g.Key, g => g.Count);
            var approvals = await _dbContext.CsrApprovals.AsNoTracking()
                .Where(a => ids.Contains(a.ApproverId))
                .GroupBy(a => a.ApproverId)
                .Select(g => new { g.Key, Count = g.Count() })
                .ToDictionaryAsync(g => g.Key, g => g.Count);
            foreach (var account in accounts)
            {
                account.Requests = requests.GetValueOrDefault(account.Id);
                account.Approvals = approvals.GetValueOrDefault(account.Id);
            }
            return accounts;
        }

        /// <summary>The address a retained account's row carries once its own is given up.</summary>
        internal static string TombstoneEmail(Guid userId) => $"deleted-{userId:N}@deleted.invalid";

        /// <inheritdoc />
        /// <remarks>
        /// Every live SSH certificate issued for the user is revoked first and the SSH login names
        /// granted to the user are removed. Access to single certificates goes in both cases: that
        /// foreign key restricts, and access is not history.
        /// <para>
        /// A retained account keeps its id and username, so requests and approvals stay attributed
        /// and the name cannot be taken by someone else. It loses its group memberships, roles,
        /// direct grants, badges, sessions, MFA credentials, mTLS credentials, password, password
        /// history, claim tokens, the enrolment tokens it created and its email address, which is
        /// replaced so the address can be used again. The security stamp changes so access tokens
        /// already issued stop working. Nothing restores a retained account.
        /// </para>
        /// </remarks>
        public async Task<bool> DeleteUser(Guid userId)
        {
            var user = await _dbContext.Users.FindAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found for deletion", userId);
                return false;
            }
            if (await DeletionBlockerAsync(userId) is { } blocker)
                throw new InvalidOperationException(blocker);
            var history = await RetainedHistoryAsync(userId);
            if (_sshLoginNames != null)
                await _sshLoginNames.UserDeletingAsync(userId);
            _dbContext.CertificateAccessLists.RemoveRange(await _dbContext.CertificateAccessLists.Where(a => a.UserId == userId).ToListAsync());
            if (history == null)
            {
                _dbContext.Users.Remove(user);
                return await _dbContext.SaveChangesAsync() > 0;
            }

            // Access tokens already issued stop working; the sessions' rows then go with the rest.
            await UserSessionTermination.EndAllSessionsAsync(_dbContext, user, DateTime.UtcNow);
            _dbContext.CaGroupMembers.RemoveRange(await _dbContext.CaGroupMembers.Where(m => m.UserId == userId).ToListAsync());
            _dbContext.RoleAssignments.RemoveRange(await _dbContext.RoleAssignments.Where(a => a.UserId == userId).ToListAsync());
            _dbContext.UserCapabilityGrants.RemoveRange(await _dbContext.UserCapabilityGrants.Where(g => g.UserId == userId).ToListAsync());
            _dbContext.AccessBadges.RemoveRange(await _dbContext.AccessBadges.Where(b => b.UserId == userId).ToListAsync());
            _dbContext.RefreshTokens.RemoveRange(await _dbContext.RefreshTokens.Where(r => r.UserId == userId).ToListAsync());
            _dbContext.Fido2Credentials.RemoveRange(await _dbContext.Fido2Credentials.Where(c => c.UserId == userId).ToListAsync());
            _dbContext.TotpSecrets.RemoveRange(await _dbContext.TotpSecrets.Where(s => s.UserId == userId).ToListAsync());
            _dbContext.TotpRecoveryCodes.RemoveRange(await _dbContext.TotpRecoveryCodes.Where(c => c.UserId == userId).ToListAsync());
            _dbContext.MtlsCredentials.RemoveRange(await _dbContext.MtlsCredentials.Where(c => c.UserId == userId).ToListAsync());
            _dbContext.PasswordHistory.RemoveRange(await _dbContext.PasswordHistory.Where(p => p.UserId == userId).ToListAsync());
            _dbContext.UserClaimTokens.RemoveRange(await _dbContext.UserClaimTokens.Where(c => c.UserId == userId).ToListAsync());
            _dbContext.EnrollmentTokens.RemoveRange(await _dbContext.EnrollmentTokens.Where(e => e.CreatedByUserId == userId).ToListAsync());

            user.IsDeleted = true;
            user.DeletedAt = DateTime.UtcNow;
            user.IsActive = false;
            user.PasswordHash = string.Empty;
            user.Email = TombstoneEmail(userId);
            _logger.LogInformation("User {UserId} retained as a deleted account: the record keeps {History}", userId, history);
            return await _dbContext.SaveChangesAsync() > 0;
        }

        /// <summary>
        /// Returns all users with their CA group memberships mapped to DTOs.
        /// </summary>
        public async Task<List<UserEntityDto>> GetAllUsers()
        {
            // People only. Service identities are listed and managed through their own endpoint.
            var users = await _dbContext.Users
                .Where(u => !u.IsServiceIdentity)
                .Include(u => u.GroupMemberships)
                    .ThenInclude(gm => gm.Group)
                .ToListAsync();

            var result = new List<UserEntityDto>();
            foreach (var user in users)
            {
                var userEntry = MapToDto(user);
                if (user.PasswordExpirationDate != null)
                    userEntry.PasswordExpiration = user.PasswordExpirationDate;
                result.Add(userEntry);
            }
            return result;
        }

        /// <summary>
        /// Returns a single user by ID with group memberships, or null when there is none.
        /// </summary>
        public async Task<UserEntityDto?> GetUserById(Guid userId)
        {
            var user = await _dbContext.Users
                .Include(u => u.GroupMemberships)
                    .ThenInclude(gm => gm.Group)
                .FirstOrDefaultAsync(u => u.Id == userId);
            return user == null ? null : MapToDto(user);
        }

        /// <summary>
        /// Returns a single user by username with group memberships, or null when there is none.
        /// </summary>
        public async Task<UserEntityDto?> GetUserByUsername(string username)
        {
            var user = await _dbContext.Users
                .Include(u => u.GroupMemberships)
                    .ThenInclude(gm => gm.Group)
                .FirstOrDefaultAsync(u => u.Username == username);
            return user == null ? null : MapToDto(user);
        }

        /// <summary>
        /// Returns a single user by email with group memberships, or null when there is none.
        /// </summary>
        public async Task<UserEntityDto?> GetUserByEmail(string email)
        {
            var user = await _dbContext.Users
                .Include(u => u.GroupMemberships)
                    .ThenInclude(gm => gm.Group)
                .FirstOrDefaultAsync(u => u.Email == email);
            return user == null ? null : MapToDto(user);
        }

        /// <summary>
        /// Adds a user to a CA group. Returns false if the membership already exists
        /// or if the user or group cannot be found.
        /// </summary>
        public async Task<bool> AddUserToGroup(Guid userId, Guid groupId, Guid? addedByUserId = null)
        {
            var userExists = await _dbContext.Users.AnyAsync(u => u.Id == userId);
            if (!userExists)
            {
                _logger.LogWarning("User {UserId} not found for group addition", userId);
                return false;
            }
            // A service identity never holds system-tier rights, whichever endpoint adds it.
            if (await _dbContext.Users.AnyAsync(u => u.Id == userId && u.IsServiceIdentity)
                && await _dbContext.CaGroups.AnyAsync(g => g.Id == groupId && g.IsSystemGroup))
            {
                _logger.LogWarning("Refused to add service identity {UserId} to system group {GroupId}", userId, groupId);
                return false;
            }

            var groupExists = await _dbContext.CaGroups.AnyAsync(g => g.Id == groupId);
            if (!groupExists)
            {
                _logger.LogWarning("Group {GroupId} not found for user {UserId}", groupId, userId);
                return false;
            }

            var alreadyMember = await _dbContext.CaGroupMembers
                .AnyAsync(gm => gm.UserId == userId && gm.GroupId == groupId);
            if (alreadyMember)
            {
                _logger.LogWarning("User {UserId} is already a member of group {GroupId}", userId, groupId);
                return false;
            }

            _dbContext.CaGroupMembers.Add(new CaGroupMemberEntity
            {
                GroupId = groupId,
                UserId = userId,
                AddedAt = DateTime.UtcNow,
                AddedByUserId = addedByUserId,
            });
            // Rotate the stamp on group change so the next request
            // fails the ghash claim check and the user must refresh their JWT.
            var addUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (addUser != null)
            {
                addUser.SecurityStamp = Guid.NewGuid().ToString();
                _dbContext.Users.Update(addUser);
            }
            return await _dbContext.SaveChangesAsync() > 0;
        }

        /// <summary>
        /// Removes a user from a CA group. Returns false if the membership does not exist. SSH
        /// certificates that carried a login name the user held through the group are revoked.
        /// </summary>
        public async Task<bool> RemoveUserFromGroup(Guid userId, Guid groupId)
        {
            var membership = await _dbContext.CaGroupMembers
                .FirstOrDefaultAsync(gm => gm.UserId == userId && gm.GroupId == groupId);
            if (membership == null)
            {
                _logger.LogWarning("Membership not found for user {UserId} in group {GroupId}", userId, groupId);
                return false;
            }

            _dbContext.CaGroupMembers.Remove(membership);
            // Rotate stamp so outstanding JWTs get invalidated.
            var removeUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (removeUser != null)
            {
                removeUser.SecurityStamp = Guid.NewGuid().ToString();
                _dbContext.Users.Update(removeUser);
            }
            var removed = await _dbContext.SaveChangesAsync() > 0;
            if (removed && _sshLoginNames != null)
                await _sshLoginNames.ReconcileUsersAsync([userId], "the user left a group");
            return removed;
        }

        /// <summary>
        /// Returns all group memberships for a given user as DTOs.
        /// </summary>
        public async Task<List<GroupMembershipDto>> GetUserGroups(Guid userId)
        {
            var memberships = await _dbContext.CaGroupMembers
                .Include(gm => gm.Group)
                .Where(gm => gm.UserId == userId)
                .ToListAsync();

            return memberships.Select(gm => new GroupMembershipDto
            {
                GroupId = gm.Group.Id,
                GroupName = gm.Group.Name,
                DisplayName = gm.Group.DisplayName,
                TemplateName = gm.Group.TemplateName ?? "Custom",
                CertificateAuthorityId = gm.Group.CertificateAuthorityId,
                IsSystemGroup = gm.Group.IsSystemGroup,
            }).ToList();
        }

        /// <summary>
        /// Updates a user's password after verifying the current password matches. Refused (false,
        /// no failed attempt counted) for a service identity and for a Directory account, whose
        /// password lives in the directory and which would never use a local one. A change ends
        /// the account's sessions (<see cref="UserSessionTermination"/>) in the save that writes
        /// the new password.
        /// </summary>
        public async Task<bool> UpdateUserPassword(Guid userId, UpdatePasswordRequest request)
        {
            if (await _dbContext.Users.AnyAsync(u => u.Id == userId && u.IsServiceIdentity))
            {
                _logger.LogWarning("Password change refused for service identity {UserId}", userId);
                return false;
            }
            if (await _dbContext.Users.AnyAsync(u => u.Id == userId && u.PasswordSource == Shared.Enums.PasswordSource.Directory))
            {
                _logger.LogWarning("Password change refused for directory account {UserId}: its password lives in the directory", userId);
                return false;
            }
            if (request.OldPassword == null || request.NewPassword == null || request.ConfirmNewPassword == null)
            {
                _logger.LogWarning("Incomplete password update request for user {UserId}", userId);
                return false;
            }
            if (request.NewPassword != request.ConfirmNewPassword)
            {
                _logger.LogWarning("Password confirmation mismatch for user {UserId}", userId);
                return false;
            }
            var user = await _dbContext.Users
                .FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found for password update", userId);
                return false;
            }
            if (!(PasswordUtil.VerifyPassword(request.OldPassword, user.PasswordHash)))
            {
                // Atomic increment via provider-agnostic ExecuteUpdateAsync.
                // Previously used raw SQL with unquoted identifiers which only worked by accident.
                await _dbContext.Users
                    .Where(u => u.Id == user.Id)
                    .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
                await _dbContext.Entry(user).ReloadAsync();

                var secPolicy = await _securityPolicy.GetAsync();
                var maxAttempts = secPolicy.MaxFailedLoginAttempts;
                var lockoutMinutes = secPolicy.LockoutMinutes;
                if (maxAttempts > 0 && user.FailedLoginAttempts >= maxAttempts)
                {
                    if (lockoutMinutes > 0)
                    {
                        user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                        _logger.LogWarning(
                            "User {UserId} temporarily locked for {LockoutMinutes} minutes after {Attempts} failed password change attempts",
                            userId, lockoutMinutes, user.FailedLoginAttempts);
                    }
                    else
                    {
                        user.IsLocked = true;
                        _logger.LogWarning(
                            "User {UserId} permanently locked after {Attempts} failed password change attempts",
                            userId, user.FailedLoginAttempts);
                    }
                }
                await _dbContext.SaveChangesAsync();
                _logger.LogWarning("Failed password change attempt for user {UserId}", userId);
                return false;
            }
            // Reject reuse of the prior N passwords.
            // Runs only when HistoryCount > 0; otherwise ValidateAsync short-circuits and
            // the historic behavior is preserved. The complexity rules also run here, so
            // a caller that reaches UpdateUserPassword without a prior validation still
            // gets the full check (defense in depth).
            var (newPwdValid, newPwdErrors) = await _passwordPolicy.ValidateAsync(userId, request.NewPassword);
            if (!newPwdValid)
            {
                _logger.LogWarning(
                    "Password change for user {UserId} rejected by policy: {Errors}",
                    userId, string.Join("; ", newPwdErrors));
                return false;
            }

            // On successful password verification, reset failed attempt counter.
            // NeedsRehash always returns true for legacy hashes, but
            // here we are unconditionally replacing the hash anyway — the new hash
            // automatically uses the current-generation algorithm/iteration count.
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            var newHash = PasswordUtil.HashPassword(request.NewPassword);
            user.PasswordHash = newHash;
            // Append to rotating history + prune.
            // No-op when HistoryCount <= 0.
            await _passwordPolicy.RecordPasswordHistoryAsync(userId, newHash);
            if (!user.PasswordNeverExpires)
                user.PasswordExpirationDate = DateTime.UtcNow.AddDays(90);
            _dbContext.Users.Update(user);
            // The stamp rotates and every refresh token is revoked in the save that writes the new
            // password, so a compromised session cannot persist after the change.
            await UserSessionTermination.EndAllSessionsAsync(_dbContext, user, DateTime.UtcNow);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Password changed and all sessions invalidated for user {UserId}", userId);
            return true;
        }

        /// <summary>
        /// Resets a user's password to a randomly generated value and returns it.
        /// The user will be forced to change password on next logon, and the account's sessions
        /// end (<see cref="UserSessionTermination"/>) in the save that writes the password. Throws
        /// <see cref="InvalidOperationException"/> for a service identity, which has no password,
        /// and for a Directory account, which would never use a local one.
        /// </summary>
        public async Task<string> ResetUserPassword(Guid userId)
        {
            var user = await _dbContext.Users.Where(u => u.Id == userId)
                .FirstOrDefaultAsync();
            if (user == null)
                throw new Exception("User not found");
            if (user.IsServiceIdentity)
                throw new InvalidOperationException("A service identity has no password.");
            if (user.PasswordSource == Shared.Enums.PasswordSource.Directory)
                throw new InvalidOperationException(
                    "This account's password is checked by the directory only, so a local password would never be used. "
                    + "Set its password source to Local first if it needs one.");
            var newPassword = PasswordUtil.Generate();
            var newHash = PasswordUtil.HashPassword(newPassword);
            user.PasswordHash = newHash;
            // Admin-initiated resets also go into
            // the user's rotating history so the next user-driven change can't
            // bounce back to the admin-generated temporary password.
            await _passwordPolicy.RecordPasswordHistoryAsync(userId, newHash);
            user.PasswordChangeOnNextLogon = true;
            user.PasswordExpirationDate = DateTime.UtcNow.AddDays(90);
            _dbContext.Users.Update(user);
            // The stamp rotates and every refresh token is revoked in the save that writes the
            // temporary password.
            await UserSessionTermination.EndAllSessionsAsync(_dbContext, user, DateTime.UtcNow);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Password reset and all sessions invalidated for user {UserId}", userId);
            return newPassword;
        }

        /// <summary>
        /// Removes every MFA method of a user (TOTP secrets and WebAuthn credentials) and clears
        /// <see cref="UserEntity.MfaEnrolledAt"/>, so they must enrol again at next login. Ends the
        /// account's sessions (<see cref="UserSessionTermination"/>), so none outlives the reset. Returns
        /// the counts removed, or null when the user does not exist.
        /// </summary>
        public async Task<(int TotpSecretsRemoved, int WebAuthnCredentialsRemoved)?> ResetUserMfa(Guid userId)
        {
            var user = await _dbContext.Users.FindAsync(userId);
            if (user == null)
                return null;

            var totpSecrets = await _dbContext.TotpSecrets.Where(t => t.UserId == userId).ToListAsync();
            _dbContext.TotpSecrets.RemoveRange(totpSecrets);
            var webAuthnCreds = await _dbContext.Fido2Credentials.Where(c => c.UserId == userId).ToListAsync();
            _dbContext.Fido2Credentials.RemoveRange(webAuthnCreds);
            user.MfaEnrolledAt = null;
            await UserSessionTermination.EndAllSessionsAsync(_dbContext, user, DateTime.UtcNow);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("MFA reset for user {UserId}", userId);
            return (totpSecrets.Count, webAuthnCreds.Count);
        }

        /// <summary>
        /// Maps a <see cref="UserEntity"/> with loaded GroupMemberships to a <see cref="UserEntityDto"/>.
        /// </summary>
        private static UserEntityDto MapToDto(UserEntity user)
        {
            var dto = new UserEntityDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                DisplayName = user.DisplayName,
                IsActive = user.IsActive,
                IsServiceIdentity = user.IsServiceIdentity,
                ServiceScopeSpaceId = user.ServiceScopeSpaceId,
                ServiceScopeCaId = user.ServiceScopeCaId,
                Description = user.Description,
                IsLocked = user.IsLocked,
                PasswordNeverExpires = user.PasswordNeverExpires,
                PasswordSource = user.PasswordSource,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt,
                Groups = user.GroupMemberships?.Select(gm => new GroupMembershipDto
                {
                    GroupId = gm.Group.Id,
                    GroupName = gm.Group.Name,
                    DisplayName = gm.Group.DisplayName,
                    TemplateName = gm.Group.TemplateName ?? "Custom",
                    CertificateAuthorityId = gm.Group.CertificateAuthorityId,
                    IsSystemGroup = gm.Group.IsSystemGroup,
                }).ToList()
            };

            if (user.PasswordExpirationDate != null)
                dto.PasswordExpiration = user.PasswordExpirationDate;

            return dto;
        }
    }
}
