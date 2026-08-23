using System.Security.Cryptography;

namespace ModularCA.Keystore.Utils;

/// <summary>
/// Cryptographic utility methods for keystore salt generation.
/// </summary>
/// <remarks>
/// A <c>HashPass</c> helper used to live here — <c>Base64(SHA256(passphrase))</c>, unsalted and
/// single-round. Its only caller stored the result in <c>Keystores.PassHash</c>, which nothing
/// ever read. Removed along with the column rather than left available: a one-line function that
/// looks like password hashing is an invitation to use it as password hashing. Passwords go
/// through <c>ModularCA.Auth.Utils.PasswordUtil.HashPassword</c>, which is salted and iterated.
/// </remarks>
public static class CryptoUtils
{
    /// <summary>
    /// Generates a cryptographically random salt of the specified length.
    /// </summary>
    public static byte[] GenerateSalt(int length = 16)
    {
        var salt = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }
}
