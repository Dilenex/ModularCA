using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities
{
    /// <summary>
    /// Persisted refresh-token row. The <see cref="Token"/> column
    /// now stores the SHA-256 hash of the opaque token, not the plaintext — a DB read
    /// compromise cannot be replayed. The plaintext is returned to the client once at
    /// issuance via the non-persisted <see cref="PlaintextTokenForClient"/> shim.
    /// <see cref="FamilyCreatedAt"/> tracks the original family
    /// issuance time for the absolute session-lifetime cap.
    /// </summary>
    public class RefreshTokenEntity
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        public Guid UserId { get; set; }

        [ForeignKey("UserId")]
        public UserEntity? User { get; set; }

        /// <summary>
        /// SHA-256 hex of the plaintext refresh token. Lookups must
        /// hash the incoming plaintext before comparing. Keeps the column ASCII-only
        /// so the 512 HasMaxLength limit stays comfortable.
        /// </summary>
        [Required]
        public required string Token { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime ExpiresAt { get; set; }

        public bool IsRevoked { get; set; } = false;

        public string? CreatedByIp { get; set; }

        public DateTime? RevokedAt { get; set; }

        public string? ReplacedByToken { get; set; }

        /// <summary>
        /// Groups tokens into a rotation family so that reuse of a revoked token
        /// triggers revocation of the entire chain (stolen-token detection).
        /// Assigned on first login; copied forward on each refresh rotation.
        /// </summary>
        public Guid? FamilyId { get; set; }

        /// <summary>
        /// The original family issuance timestamp. Copied forward
        /// on rotation so <see cref="Shared.Models.Config.SecurityConfig.MaxSessionLifetimeDays"/>
        /// can be enforced regardless of how many times the token has rotated.
        /// </summary>
        public DateTime? FamilyCreatedAt { get; set; }

        /// <summary>
        /// SHA-256 hash of the User-Agent header at token creation time, used for session fingerprinting.
        /// </summary>
        public string? UserAgentHash { get; set; }

        /// <summary>
        /// JWK SHA-256 thumbprint (RFC 7638, base64url) of the client's non-extractable WebCrypto
        /// public key, binding this refresh token to proof-of-possession (DPoP-style). When set, the
        /// <c>/auth/refresh</c> endpoint requires a valid DPoP proof signed by the matching private
        /// key — so a stolen refresh token is useless without the key that can't be exfiltrated.
        /// Null for sessions created before PoP enrollment (soft rollout) or by non-PoP clients.
        /// </summary>
        public string? CnfJkt { get; set; }

        /// <summary>
        /// Last time this session was active (token refresh or API call).
        /// </summary>
        public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// The access badge this session wears, carried across refreshes so a rotated access
        /// token keeps the badge. Null when badgeless. Cleared when the badge is deleted.
        /// </summary>
        public Guid? AccessBadgeId { get; set; }

        /// <summary>
        /// Transient plaintext handed back to the client on issuance.
        /// Never persisted. Only set by <c>JwtTokenService.GenerateRefreshToken</c> and
        /// read once by the controller before it writes the LoginResponse.
        /// </summary>
        [NotMapped]
        public string? PlaintextTokenForClient { get; set; }
    }

}
