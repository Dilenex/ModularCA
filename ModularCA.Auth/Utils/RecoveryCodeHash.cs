using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Auth.Utils;

/// <summary>
/// Hashes TOTP recovery codes for storage in <c>TotpRecoveryCodeEntity.CodeHash</c> (64 characters).
/// <para>
/// Current form: <c>pbkdf2:</c> followed by the hex of 28 bytes of PBKDF2-HMAC-SHA256 at
/// <see cref="Iterations"/> rounds, salted per user (the salt is derived from the user id), so equal
/// codes of two users hash differently and a stolen table costs a full PBKDF2 run per guess per user.
/// One hash is computed per attempt and matched by equality, so a sign-in costs one derivation however
/// many codes the user holds.
/// </para>
/// <para>
/// Legacy form: bare uppercase hex of unsalted SHA-256, written before 0.4.3. Rows in that form keep
/// verifying (<see cref="Candidates"/> yields both), so existing codes stay usable without a migration;
/// each is consumed on use and the next enrolment writes the current form.
/// </para>
/// </summary>
public static class RecoveryCodeHash
{
    /// <summary>PBKDF2-HMAC-SHA256 rounds. A code carries 50 random bits, so this is ample.</summary>
    public const int Iterations = 100_000;

    /// <summary>The prefix that marks the current form.</summary>
    public const string Prefix = "pbkdf2:";

    private const int HashBytes = 28;

    /// <summary>The stored hash of <paramref name="code"/> for <paramref name="userId"/> in the current form.</summary>
    public static string Compute(Guid userId, string code)
    {
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(Normalize(code)), Salt(userId), Iterations, HashAlgorithmName.SHA256, HashBytes);
        return Prefix + Convert.ToHexString(hash);
    }

    /// <summary>The unsalted SHA-256 form written before 0.4.3, recognised only so older rows still verify.</summary>
    public static string ComputeLegacy(string code)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(code))));

    /// <summary>The stored values that <paramref name="code"/> matches: the current form, then the legacy form.</summary>
    public static (string Current, string Legacy) Candidates(Guid userId, string code)
        => (Compute(userId, code), ComputeLegacy(code));

    /// <summary>Removes dashes and uppercases, so case and grouping typed from paper do not matter.</summary>
    private static string Normalize(string code)
        => code.Replace("-", string.Empty, StringComparison.Ordinal).Trim().ToUpperInvariant();

    private static byte[] Salt(Guid userId)
        => SHA256.HashData(Encoding.UTF8.GetBytes("ModularCA TOTP recovery code:" + userId.ToString("N")));
}
