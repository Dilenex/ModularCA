namespace ModularCA.Shared.Models.Management
{
    /// <summary>
    /// Data transfer object for user information in API responses.
    /// </summary>
    public class UserEntityDto
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? DisplayName { get; set; }
        public bool IsActive { get; set; } = true;
        /// <summary>True for a permission-only account that can never sign in.</summary>
        public bool IsServiceIdentity { get; set; }
        public Guid? ServiceScopeTenantId { get; set; }
        public Guid? ServiceScopeCaId { get; set; }
        public string? Description { get; set; }
        public bool IsLocked { get; set; } = false;
        public bool PasswordNeverExpires { get; set; }
        public bool PasswordChangeOnNextLogon { get; set; }

        public DateTime? PasswordExpiration { get; set; }

        public DateTime CreatedAt { get; set; }

        /// <summary>CA group memberships for this user.</summary>
        public List<GroupMembershipDto>? Groups { get; set; }
    }

    /// <summary>Represents a user's membership in a CA group for API responses.</summary>
    public class GroupMembershipDto
    {
        /// <summary>The unique identifier of the group.</summary>
        public Guid GroupId { get; set; }
        /// <summary>The backend name of the group (lowercase dashed).</summary>
        public string GroupName { get; set; } = string.Empty;
        /// <summary>Human-friendly display name of the group.</summary>
        public string DisplayName { get; set; } = string.Empty;
        /// <summary>The capability template this group was created from (e.g. "Administrator", "Operator", "Auditor", "Requester", or "Custom").</summary>
        public string TemplateName { get; set; } = string.Empty;
        /// <summary>The CA this group is scoped to, if any.</summary>
        public Guid? CertificateAuthorityId { get; set; }
        /// <summary>Whether this is a system-wide group.</summary>
        public bool IsSystemGroup { get; set; }
    }
}