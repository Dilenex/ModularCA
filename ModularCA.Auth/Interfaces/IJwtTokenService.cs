using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Interfaces
{
    public interface IJwtTokenService
    {
        /// <summary>
        /// Generates a signed JWT for the given user and their group memberships.
        /// When <paramref name="mfaSetupRequired"/> is true, the token includes an
        /// <c>mfa_setup_required</c> claim that restricts access to admin endpoints.
        /// Group names are embedded as <c>groups</c> claims. The token never outlives
        /// <paramref name="notAfter"/>, the horizon of the session it belongs to, when one is given.
        /// </summary>
        (string Token, DateTime ExpiresAt) GenerateToken(UserEntity user, List<CaGroupEntity> groups, string? sourceIp = null, bool mfaSetupRequired = false, AccessBadgeClaim? badge = null, DateTime? notAfter = null);

        /// <summary>
        /// Creates a cryptographically random refresh token for the specified user.
        /// Optionally stores a User-Agent hash for session fingerprint binding. The token expires
        /// after the refresh-token lifetime or when the session reaches
        /// <paramref name="maxSessionLifetimeHours"/> (0 = no maximum) counted from
        /// <paramref name="sessionStartedAt"/> (now, for a new sign-in), whichever comes first.
        /// </summary>
        RefreshTokenEntity GenerateRefreshToken(Guid userId, string? ip, int maxSessionLifetimeHours, string? userAgentHash = null, string? cnfJkt = null, DateTime? sessionStartedAt = null);
    }
}
