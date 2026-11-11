using ModularCA.Shared.Models.Management;

namespace ModularCA.Auth.Interfaces
{
    /// <summary>
    /// Manages user accounts and their CA group memberships.
    /// </summary>
    public interface IUserManagementService
    {
        /// <summary>
        /// Creates a new user and assigns them to the specified groups (none when no groups are given).
        /// </summary>
        Task<(bool Success, string? Error)> CreateUser(CreateUserRequest request);

        /// <summary>
        /// Updates an existing user's profile fields.
        /// </summary>
        Task<bool> UpdateUser(Guid userId, UpdateUserRequest request);

        /// <summary>
        /// Deletes a user by ID. An account with no history is removed outright. An account the
        /// record must keep naming (see <see cref="RetainedHistoryAsync"/>) is retained instead:
        /// the row stays, hidden from every ordinary query, and everything it could sign in with
        /// or reach is removed. False when the id names no account.
        /// </summary>
        /// <exception cref="InvalidOperationException">The account cannot be deleted at all; the
        /// message is the one <see cref="DeletionBlockerAsync"/> returns.</exception>
        Task<bool> DeleteUser(Guid userId);

        /// <summary>
        /// Why the account cannot be deleted, or null when it can: it is the enrolment account of
        /// a Kerberos realm, which would stop enrolling without it. Null also for an id that names
        /// no account.
        /// </summary>
        Task<string?> DeletionBlockerAsync(Guid userId);

        /// <summary>
        /// The history that makes deleting this account retain its row, or null when the account
        /// has none and is removed outright: the certificate requests it made and the approvals it
        /// gave, with their counts. Null also for an id that names no account.
        /// </summary>
        Task<string?> RetainedHistoryAsync(Guid userId);

        /// <summary>
        /// The deleted accounts whose rows were retained, newest deletion first, each with the
        /// number of requests and approvals that still name it. Ordinary queries never return
        /// these accounts.
        /// </summary>
        Task<List<RetainedAccountDto>> GetRetainedAccounts();

        /// <summary>
        /// Returns all users with their group memberships.
        /// </summary>
        Task<List<UserEntityDto>> GetAllUsers();

        /// <summary>
        /// Returns a single user by ID with group memberships, or null when there is none.
        /// </summary>
        Task<UserEntityDto?> GetUserById(Guid userId);

        /// <summary>
        /// Returns a single user by username with group memberships, or null when there is none.
        /// </summary>
        Task<UserEntityDto?> GetUserByUsername(string username);

        /// <summary>
        /// Returns a single user by email with group memberships, or null when there is none.
        /// </summary>
        Task<UserEntityDto?> GetUserByEmail(string email);

        /// <summary>
        /// Adds a user to a CA group. Returns false if the user is already a member or either entity is missing.
        /// </summary>
        Task<bool> AddUserToGroup(Guid userId, Guid groupId, Guid? addedByUserId = null);

        /// <summary>
        /// Removes a user from a CA group. Returns false if the membership does not exist.
        /// </summary>
        Task<bool> RemoveUserFromGroup(Guid userId, Guid groupId);

        /// <summary>
        /// Returns all group memberships for a user as DTOs.
        /// </summary>
        Task<List<GroupMembershipDto>> GetUserGroups(Guid userId);

        /// <summary>
        /// Updates a user's password after verifying the old password.
        /// </summary>
        Task<bool> UpdateUserPassword(Guid userId, UpdatePasswordRequest request);

        /// <summary>
        /// Resets a user's password to a random value and returns the new password.
        /// </summary>
        Task<string> ResetUserPassword(Guid userId);

        /// <summary>
        /// Removes every TOTP secret and WebAuthn credential of a user and clears their MFA
        /// enrollment, forcing re-enrollment. Returns the counts removed, or null when the user does not exist.
        /// </summary>
        Task<(int TotpSecretsRemoved, int WebAuthnCredentialsRemoved)?> ResetUserMfa(Guid userId);
    }
}
