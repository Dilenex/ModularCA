using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Entities
{
    public class UserEntity
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(255)]
        public string Username { get; set; } = string.Empty;

        [MaxLength(255)]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        public bool PasswordNeverExpires { get; set; } = false;
        public DateTime? PasswordExpirationDate { get; set; } = DateTime.UtcNow.AddDays(90);
        public bool PasswordChangeOnNextLogon { get; set; } = false;

        [MaxLength(255)]
        public string? DisplayName { get; set; }

        public string FirstName { get; set; } = string.Empty;

        public string LastName { get; set; } = string.Empty;

        public bool IsActive { get; set; } = true;

        /// <summary>
        /// A service identity holds group memberships and grants for a non-person caller (a
        /// Kerberos realm binding, for instance) and can never sign in: no password, no second
        /// factor, no token by any path. Every authorization check treats it as a user.
        /// </summary>
        public bool IsServiceIdentity { get; set; } = false;

        /// <summary>Service identities only: the tenant the identity is confined to. Null with a null CA means system scope.</summary>
        public Guid? ServiceScopeTenantId { get; set; }

        /// <summary>Service identities only: the CA the identity is confined to, when narrower than a tenant.</summary>
        public Guid? ServiceScopeCaId { get; set; }

        /// <summary>Free-text purpose, shown in the console. Service identities mostly.</summary>
        [MaxLength(500)]
        public string? Description { get; set; }
        public bool IsLocked { get; set; } = false;
        public int FailedLoginAttempts { get; set; } = 0;
        public DateTime? LockoutEndUtc { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? LastLoginAt { get; set; }

        /// <summary>
        /// Random value that changes whenever security-sensitive fields (password, MFA) are updated.
        /// Used to invalidate existing tokens after credential changes.
        /// </summary>
        public string SecurityStamp { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Timestamp when the user first enrolled an MFA method (TOTP or WebAuthn).
        /// Null means MFA has never been configured — the user will be forced to set it up.
        /// </summary>
        public DateTime? MfaEnrolledAt { get; set; }

        // === Relationships ===

        /// <summary>CA group memberships determining the user's permissions across CAs.</summary>
        public virtual ICollection<CaGroupMemberEntity> GroupMemberships { get; set; } = new List<CaGroupMemberEntity>();

        public virtual ICollection<CertificateAccessListEntity> CertificateAccess { get; set; } = new List<CertificateAccessListEntity>();

        public virtual ICollection<CertificateAccessListEntity> GrantedAccess { get; set; } = new List<CertificateAccessListEntity>();

        /// <summary>Direct capability grants on this user (no group/role required).</summary>
        public virtual ICollection<UserCapabilityGrantEntity> UserGrants { get; set; } = new List<UserCapabilityGrantEntity>();

        /// <summary>Roles assigned directly to this user.</summary>
        public virtual ICollection<RoleAssignmentEntity> RoleAssignments { get; set; } = new List<RoleAssignmentEntity>();

        /// <summary>Optimistic concurrency token (MySQL TIMESTAMP(6)).</summary>
        [Timestamp]
        public byte[]? RowVersion { get; set; }

        /// <summary>
        /// Soft-delete flag. When true, the user is hidden by
        /// the global query filter; existing tokens still invalidate via the security
        /// stamp but the row survives for audit trail continuity.
        /// </summary>
        public bool IsDeleted { get; set; } = false;

        /// <summary>Timestamp when <see cref="IsDeleted"/> was flipped to true.</summary>
        public DateTime? DeletedAt { get; set; }
    }
}
