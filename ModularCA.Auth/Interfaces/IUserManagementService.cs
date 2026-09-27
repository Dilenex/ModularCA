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
        /// Deletes a user by ID.
        /// </summary>
        Task<bool> DeleteUser(Guid userId);

        /// <summary>
        /// Returns all users with their group memberships.
        /// </summary>
        Task<List<UserEntityDto>> GetAllUsers();

        /// <summary>
        /// Returns a single user by ID with group memberships.
        /// </summary>
        Task<UserEntityDto> GetUserById(Guid userId);

        /// <summary>
        /// Returns a single user by username with group memberships.
        /// </summary>
        Task<UserEntityDto> GetUserByUsername(string username);

        /// <summary>
        /// Returns a single user by email with group memberships.
        /// </summary>
        Task<UserEntityDto> GetUserByEmail(string email);

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
    }
}
