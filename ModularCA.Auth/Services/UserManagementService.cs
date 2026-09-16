using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Utils;
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

        /// <summary>
        /// Initializes a new instance of the <see cref="UserManagementService"/> class.
        /// </summary>
        public UserManagementService(
            ModularCADbContext dbContext,
            ILogger<UserManagementService> logger,
            SystemConfig config,
            ISecurityPolicyService securityPolicy,
            IPasswordPolicyService passwordPolicy)
        {
            _dbContext = dbContext;
            _logger = logger;
            _config = config;
            _securityPolicy = securityPolicy;
            _passwordPolicy = passwordPolicy;
        }

        /// <summary>
        /// Creates a new user and assigns them to the groups specified in <paramref name="request"/>.GroupIds.
        /// If no groups are specified, the user is added to the "system-auditor" group by default.
        /// </summary>
        public async Task<(bool Success, string? Error)> CreateUser(CreateUserRequest request)
        {
            if (await _dbContext.Users.AnyAsync(u => u.Username == request.Username))
            {
                _logger.LogWarning("Attempted to create user with existing username {Username}", request.Username);
                return (false, $"Username '{request.Username}' already exists");
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

                // Assign to specified groups, or fall back to system-auditor
                var groupIds = request.GroupIds;
                if (groupIds == null || groupIds.Count == 0)
                {
                    var defaultGroup = await _dbContext.CaGroups
                        .FirstOrDefaultAsync(g => g.Name == "system-auditor");
                    if (defaultGroup != null)
                        groupIds = new List<Guid> { defaultGroup.Id };
                }

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
        /// Updates an existing user's profile fields (username, email, name, active/locked status).
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
                && await _dbContext.Users.AnyAsync(u => u.Id != userId && u.Username == request.Username))
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
            user.Username = request.Username ?? user.Username;
            user.Email = request.Email ?? user.Email;
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

            // Rotate the security stamp whenever an admin toggles
            // IsActive or IsLocked so outstanding JWTs invalidate on the next request
            // rather than waiting out their TTL.
            if (wasActive != user.IsActive || wasLocked != user.IsLocked)
            {
                user.SecurityStamp = Guid.NewGuid().ToString();

                // Also revoke all outstanding refresh tokens so the next /auth/refresh
                // attempt can't re-mint a valid JWT.
                var refreshTokens = await _dbContext.Set<RefreshTokenEntity>()
                    .Where(t => t.UserId == userId && !t.IsRevoked)
                    .ToListAsync();
                foreach (var t in refreshTokens)
                {
                    t.IsRevoked = true;
                    t.RevokedAt = DateTime.UtcNow;
                }
            }

            _dbContext.Users.Update(user);
            return await _dbContext.SaveChangesAsync() > 0;
        }

        /// <summary>
        /// Deletes a user by ID and all associated group memberships (via cascade).
        /// </summary>
        public async Task<bool> DeleteUser(Guid userId)
        {
            var user = await _dbContext.Users.FindAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found for deletion", userId);
                return false;
            }
            _dbContext.Users.Remove(user);
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
        /// Returns a single user by ID with group memberships, or throws if not found.
        /// </summary>
        public async Task<UserEntityDto> GetUserById(Guid userId)
        {
            var user = await _dbContext.Users
                .Include(u => u.GroupMemberships)
                    .ThenInclude(gm => gm.Group)
                .FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null)
                throw new Exception("User not found");
            return MapToDto(user);
        }

        /// <summary>
        /// Returns a single user by username with group memberships, or throws if not found.
        /// </summary>
        public async Task<UserEntityDto> GetUserByUsername(string username)
        {
            var user = await _dbContext.Users
                .Include(u => u.GroupMemberships)
                    .ThenInclude(gm => gm.Group)
                .FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
                throw new Exception("User not found");
            return MapToDto(user);
        }

        /// <summary>
        /// Returns a single user by email with group memberships, or throws if not found.
        /// </summary>
        public async Task<UserEntityDto> GetUserByEmail(string email)
        {
            var user = await _dbContext.Users
                .Include(u => u.GroupMemberships)
                    .ThenInclude(gm => gm.Group)
                .FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                throw new Exception("User not found");
            return MapToDto(user);
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
        /// Removes a user from a CA group. Returns false if the membership does not exist.
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
            return await _dbContext.SaveChangesAsync() > 0;
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
        /// Updates a user's password after verifying the current password matches.
        /// </summary>
        public async Task<bool> UpdateUserPassword(Guid userId, UpdatePasswordRequest request)
        {
            if (await _dbContext.Users.AnyAsync(u => u.Id == userId && u.IsServiceIdentity))
            {
                _logger.LogWarning("Password change refused for service identity {UserId}", userId);
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
            // Rotate security stamp so outstanding JWTs get invalidated.
            user.SecurityStamp = Guid.NewGuid().ToString();
            if (!user.PasswordNeverExpires)
                user.PasswordExpirationDate = DateTime.UtcNow.AddDays(90);
            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();

            // Revoke all refresh tokens for this user to invalidate existing sessions
            // This ensures compromised sessions don't persist after password change
            var refreshTokens = await _dbContext.Set<RefreshTokenEntity>()
                .Where(t => t.UserId == userId && !t.IsRevoked)
                .ToListAsync();
            foreach (var token in refreshTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Password changed and all sessions invalidated for user {UserId}", userId);
            return true;
        }

        /// <summary>
        /// Resets a user's password to a randomly generated value and returns it.
        /// The user will be forced to change password on next logon.
        /// </summary>
        public async Task<string> ResetUserPassword(Guid userId)
        {
            var user = await _dbContext.Users.Where(u => u.Id == userId)
                .FirstOrDefaultAsync();
            if (user == null)
                throw new Exception("User not found");
            if (user.IsServiceIdentity)
                throw new InvalidOperationException("A service identity has no password.");
            var newPassword = PasswordUtil.Generate();
            var newHash = PasswordUtil.HashPassword(newPassword);
            user.PasswordHash = newHash;
            // Admin-initiated resets also go into
            // the user's rotating history so the next user-driven change can't
            // bounce back to the admin-generated temporary password.
            await _passwordPolicy.RecordPasswordHistoryAsync(userId, newHash);
            user.SecurityStamp = Guid.NewGuid().ToString();
            user.PasswordChangeOnNextLogon = true;
            user.PasswordExpirationDate = DateTime.UtcNow.AddDays(90);
            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();

            // Revoke all refresh tokens for this user to invalidate existing sessions
            var refreshTokens = await _dbContext.Set<RefreshTokenEntity>()
                .Where(t => t.UserId == userId && !t.IsRevoked)
                .ToListAsync();
            foreach (var token in refreshTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Password reset and all sessions invalidated for user {UserId}", userId);
            return newPassword;
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
                ServiceScopeTenantId = user.ServiceScopeTenantId,
                ServiceScopeCaId = user.ServiceScopeCaId,
                Description = user.Description,
                IsLocked = user.IsLocked,
                PasswordNeverExpires = user.PasswordNeverExpires,
                CreatedAt = user.CreatedAt,
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
