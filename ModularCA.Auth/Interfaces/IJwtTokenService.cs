using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Interfaces
{
    public interface IJwtTokenService
    {
        /// <summary>
        /// Generates a signed JWT for the given user and their group memberships.
        /// When <paramref name="mfaSetupRequired"/> is true, the token includes an
        /// <c>mfa_setup_required</c> claim that restricts access to admin endpoints.
        /// Group names are embedded as <c>groups</c> claims.
        /// </summary>
        (string Token, DateTime ExpiresAt) GenerateToken(UserEntity user, List<CaGroupEntity> groups, string? sourceIp = null, bool mfaSetupRequired = false, AccessBadgeClaim? badge = null);

        /// <summary>
        /// Creates a cryptographically random refresh token for the specified user.
        /// Optionally stores a User-Agent hash for session fingerprint binding.
        /// </summary>
        RefreshTokenEntity GenerateRefreshToken(Guid userId, string? ip, string? userAgentHash = null, string? cnfJkt = null);
    }
}
