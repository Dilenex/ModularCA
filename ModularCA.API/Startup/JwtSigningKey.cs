using System.Text;
using Microsoft.IdentityModel.Tokens;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Startup;

/// <summary>
/// The key access tokens are checked against: <c>JWT.Secret</c> as the running configuration
/// holds it when a token is checked, the same value <c>JwtTokenService</c> signs with. It is
/// read at each check rather than fixed at start so that a node that started before its signer
/// answered, and runs on a temporary secret meanwhile, moves to the stored secret as soon as
/// <see cref="ModularCA.API.Services.SignerSecretsRetryService"/> reads it: sessions signed with
/// the temporary one then end, and a refresh gets a token under the stored one. Nothing else
/// changes the secret while a process runs; a rotation is stored for the next start and leaves
/// the running configuration alone.
/// </summary>
/// <param name="config">The running configuration.</param>
public sealed class JwtSigningKey(SystemConfig config)
{
    /// <summary>
    /// The shortest secret a key is made from: 32 bytes, the HMAC-SHA256 block the tokens are
    /// signed with. Every secret the product makes is longer; this is a floor, not a setting.
    /// </summary>
    internal const int MinimumSecretBytes = 32;

    private volatile Held? _held;

    /// <summary>The secret a key was made from, and the key.</summary>
    private sealed record Held(string Secret, SymmetricSecurityKey Key);

    /// <summary>
    /// The key for the secret in force now, or null when there is no usable secret (missing, or
    /// shorter than <see cref="MinimumSecretBytes"/>). Made once per secret: the same key object is
    /// returned for as long as the secret is the same string.
    /// </summary>
    public SecurityKey? Current()
    {
        var secret = config.JWT.Secret;
        if (string.IsNullOrEmpty(secret) || Encoding.UTF8.GetByteCount(secret) < MinimumSecretBytes)
            return null;
        var held = _held;
        if (held != null && ReferenceEquals(held.Secret, secret))
            return held.Key;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        _held = new Held(secret, key);
        return key;
    }

    /// <summary>
    /// The keys a token may be checked against, for <see cref="TokenValidationParameters.IssuerSigningKeyResolver"/>:
    /// the current key, or none at all, so that with no usable secret every token is refused
    /// rather than checked against a key made from an empty or short value.
    /// </summary>
    public IEnumerable<SecurityKey> Keys()
        => Current() is { } key ? [key] : [];
}
