using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Models.Management
{
    /// <summary>
    /// Request body for updating an existing user account's profile fields.
    /// Nullable fields are treated as "no change" when omitted from the request.
    /// </summary>
    public class UpdateUserRequest
    {
        [MaxLength(255)]
        public string? Username { get; set; }

        [MaxLength(255)]
        public string? Email { get; set; }

        [MaxLength(256)]
        public string? Password { get; set; }

        [MaxLength(255)]
        public string? FirstName { get; set; }

        /// <summary>
        /// When true, exempts the account from password-age expiration policy. Null means
        /// leave the current value unchanged. Aligned with <c>CreateUserRequest.PasswordNeverExpires</c>
        /// so System.Text.Json deserializes the UI's <c>true</c>/<c>false</c> literal directly.
        /// </summary>
        public bool? PasswordNeverExpires { get; set; }
        public bool? PasswordChangeOnNextLogon { get; set; }

        /// <summary>
        /// Where the account's sign-in password is checked: <c>Inherit</c> (the instance LDAP
        /// setting), <c>Local</c> (the local hash only) or <c>Directory</c> (LDAP only). Null means
        /// leave it unchanged. A credential field: it takes the same step-up, tier gate and
        /// controlled-user ceremony as the other account fields, and an account cannot change its own.
        /// </summary>
        public Enums.PasswordSource? PasswordSource { get; set; }

        [MaxLength(255)]
        public string? LastName { get; set; }

        [MaxLength(255)]
        public string? DisplayName { get; set; }

        /// <summary>
        /// Null means "leave unchanged", matching every other nullable field on this DTO.
        /// <para>
        /// These two carried property initializers (<c>= true</c> and <c>= false</c>) while
        /// PasswordNeverExpires and PasswordChangeOnNextLogon above — same type, same contract —
        /// did not. System.Text.Json constructs the object, running the initializers, and then
        /// assigns only the properties present in the payload, so an omitted field arrived
        /// non-null and <c>request.IsLocked ?? user.IsLocked</c> in UserManagementService could
        /// never take its fallback. A PUT of <c>{"email":"x@y.com"}</c> therefore silently
        /// UNLOCKED a locked-out account and reactivated a disabled one, and the controller's
        /// self-deactivation guard (<c>request.IsActive == false</c>) was unreachable for an
        /// omitted field. Of every property on this DTO, only the two security-relevant booleans
        /// had initializers.
        /// </para>
        /// </summary>
        public bool? IsActive { get; set; }
        public bool? IsLocked { get; set; }
    }
}
