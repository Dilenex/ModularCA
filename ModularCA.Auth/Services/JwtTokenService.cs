using Microsoft.IdentityModel.Tokens;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Auth.Services
{
    /// <summary>
    /// JWT issuance, refresh-token generation, and refresh-token hashing helpers.
    /// <para>
    /// Emits <c>stamp</c> (<see cref="UserEntity.SecurityStamp"/>)
    /// and <c>ghash</c> (SHA-256 of sorted group GUIDs) claims that are validated by
    /// <c>TokenRevocationMiddleware</c> on every request. Rotating the stamp invalidates
    /// outstanding JWTs immediately (disable / lock / password reset / group change).
    /// </para>
    /// <para>
    /// <see cref="GenerateRefreshToken"/> now returns the plaintext
    /// to the caller but stores the SHA-256 hash in the DB row. Lookups on
    /// <c>/auth/refresh</c> must hash the incoming token with <see cref="HashRefreshToken"/>.
    /// </para>
    /// </summary>
    public class JwtTokenService : IJwtTokenService
    {
        private readonly SystemConfig _config;

        public JwtTokenService(SystemConfig config)
        {
            _config = config;
        }

        /// <summary>
        /// Generates a signed JWT for the given user and their group memberships.
        /// When <paramref name="mfaSetupRequired"/> is true, an <c>mfa_setup_required</c> claim
        /// is embedded so the MFA enrollment middleware can restrict access until setup is complete.
        /// Group names are embedded as <c>groups</c> claims.
        /// </summary>
        public (string Token, DateTime ExpiresAt) GenerateToken(UserEntity user, List<CaGroupEntity> groups, string? sourceIp = null, bool mfaSetupRequired = false, AccessBadgeClaim? badge = null)
        {
            var handler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config.JWT.Secret);
            var expires = DateTime.UtcNow.AddMinutes(_config.JWT.ExpirationMinutes);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("username", user.Username),
                // Bind the token to the user's current security stamp.
                // Any admin-initiated disable/lock/password-reset rotates the stamp and
                // the per-request middleware short-circuits on mismatch.
                new Claim("stamp", user.SecurityStamp ?? string.Empty),
                // Group-membership digest for outstanding-token
                // invalidation on group changes. The middleware recomputes this from the
                // DB when it has to pay the cache-miss cost.
                new Claim("ghash", ComputeGroupHash(groups))
            };

            foreach (var group in groups)
            {
                claims.Add(new Claim("groups", group.Name));
            }

            // Consolidated JWT-to-IP binding.
            var bindMode = _config.Security.BindJwtToIp;
            if (bindMode != JwtIpBindingMode.Off && !string.IsNullOrWhiteSpace(sourceIp))
            {
                claims.Add(new Claim("ip", sourceIp!));
                claims.Add(new Claim("ipm", ((int)bindMode).ToString()));
            }

            // MFA enrollment: flag the token so the middleware blocks admin access
            if (mfaSetupRequired)
            {
                claims.Add(new Claim("mfa_setup_required", "true"));
            }

            // The worn access badge. The authorization resolver keeps only the grant sources
            // the badge names while this token is presented; the name is for audit rows.
            if (badge != null)
            {
                claims.Add(new Claim(Authorization.AccessBadgeContext.BadgeClaim, badge.Id.ToString()));
                claims.Add(new Claim(Authorization.AccessBadgeContext.BadgeNameClaim, badge.Name));
            }

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expires,
                Issuer = _config.JWT.Issuer,
                Audience = _config.JWT.Audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256)
            };

            var token = handler.CreateToken(descriptor);
            return (handler.WriteToken(token), expires);
        }

        /// <summary>
        /// Computes the SHA-256 hex of the user's sorted group IDs. Used as the
        /// <c>ghash</c> JWT claim so group membership changes invalidate outstanding tokens.
        /// </summary>
        public static string ComputeGroupHash(IEnumerable<CaGroupEntity> groups)
        {
            if (groups == null) return string.Empty;
            var ids = groups.Where(g => g != null).Select(g => g.Id.ToString("N")).OrderBy(s => s, StringComparer.Ordinal);
            var joined = string.Join(",", ids);
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(joined)));
        }

        /// <summary>
        /// SHA-256 hex of a refresh token. Used as the stored form
        /// in the RefreshTokens table so a DB read compromise does not yield usable
        /// session tokens. Callers pass plaintext; lookups hash-then-compare.
        /// </summary>
        public static string HashRefreshToken(string plaintextToken)
        {
            if (plaintextToken == null) return string.Empty;
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(plaintextToken)));
        }

        /// <summary>
        /// Creates a cryptographically random refresh token for the specified user.
        /// The plaintext is returned to the caller (via the hidden
        /// <see cref="RefreshTokenEntity.PlaintextTokenForClient"/> property) while the
        /// <see cref="RefreshTokenEntity.Token"/> field stores the SHA-256 hash.
        /// </summary>
        public RefreshTokenEntity GenerateRefreshToken(Guid userId, string? ip, string? userAgentHash = null, string? cnfJkt = null)
        {
            var plaintext = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var entity = new RefreshTokenEntity
            {
                UserId = userId,
                Token = HashRefreshToken(plaintext), // DB stores hash
                CreatedByIp = ip,
                UserAgentHash = userAgentHash,
                CnfJkt = cnfJkt, // DPoP proof-of-possession binding (null = unbound / legacy)
                FamilyId = Guid.NewGuid(),
                FamilyCreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(_config.Tokens.RefreshTokenDays)
            };
            // Stash plaintext on a non-persisted property so the controller can return it.
            entity.PlaintextTokenForClient = plaintext;
            return entity;
        }
    }
}
