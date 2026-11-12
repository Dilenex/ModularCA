namespace ModularCA.Shared.Models.Management
{
    /// <summary>
    /// A deleted account whose row was retained because certificate requests or approvals still
    /// name it. It holds nothing and cannot sign in; only its id, its username and this history
    /// remain.
    /// </summary>
    public class RetainedAccountDto
    {
        /// <summary>The account's id, which its requests and approvals keep referring to.</summary>
        public Guid Id { get; set; }

        /// <summary>The username, which stays reserved and cannot be given to another account.</summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>The display name the account had, if any.</summary>
        public string? DisplayName { get; set; }

        /// <summary>When the account was deleted.</summary>
        public DateTime? DeletedAt { get; set; }

        /// <summary>How many certificate requests the account made.</summary>
        public int Requests { get; set; }

        /// <summary>How many approvals the account gave.</summary>
        public int Approvals { get; set; }
    }
}
