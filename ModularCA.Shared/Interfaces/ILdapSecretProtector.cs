namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Encrypts and decrypts the LDAP publisher bind password held in
/// <c>LdapConfigurations.Password</c>.
/// </summary>
/// <remarks>
/// <para>
/// That column stored the password as plaintext. The API surface around it was careful — reads
/// return <c>"***"</c>, the audit payload omits it, and an update that echoes the mask back is
/// treated as "unchanged" — so the value was well protected everywhere except the one place it
/// actually lived. Anyone with read access to the database had the credential, and an LDAP
/// publisher bind account is not a low-value one: publishing into a directory's PKI containers
/// needs write access high enough that the account is worth stealing on its own.
/// </para>
/// <para>
/// The implementation lives in the API layer because it is built on ASP.NET Core Data Protection,
/// the same keyring that already protects TOTP secrets — so it inherits the existing key
/// management, the Redis or <c>dp-keys</c> persistence choice, and the ACL hardening applied at
/// startup, rather than introducing a second secret-at-rest scheme to operate.
/// </para>
/// <para><b>Losing the keyring loses these passwords.</b> That is the same bargain already made
/// for TOTP secrets. Decryption failure is surfaced as an error rather than swallowed, so the
/// operator sees "re-enter the bind password" instead of a directory bind failing for no visible
/// reason.</para>
/// </remarks>
public interface ILdapSecretProtector
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> for storage. An empty or whitespace input is
    /// returned unchanged — an unset password stays unset rather than becoming ciphertext that
    /// decrypts to nothing.
    /// </summary>
    string Protect(string? plaintext);

    /// <summary>
    /// Recovers the bind password from its stored form. A value written before this protection
    /// existed is stored in the clear and is returned as-is, so upgrading does not break running
    /// publishers; <see cref="LdapSecretProtection.IsProtected"/> tells the two apart, and callers
    /// use it to re-write such rows in protected form.
    /// </summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The value is tagged as protected but cannot be decrypted — typically a lost or replaced
    /// Data Protection keyring. Failing here is deliberate: binding with an unusable password
    /// would present a garbage credential to the directory and could count against an account
    /// lockout policy.
    /// </exception>
    string Unprotect(string? stored);
}

/// <summary>
/// The on-disk format shared by every reader and writer of a protected LDAP secret.
/// </summary>
public static class LdapSecretProtection
{
    /// <summary>
    /// Marks a value as ciphertext. Data Protection payloads are base64url, which never contains
    /// a colon, so the tag cannot collide with one — and a plaintext password that happens to
    /// begin with these characters is not a false positive either, because it would have to be
    /// exactly this prefix followed by a decryptable payload.
    /// </summary>
    public const string Tag = "dp1:";

    /// <summary>Whether a stored value carries the protection tag.</summary>
    public static bool IsProtected(string? stored) =>
        stored != null && stored.StartsWith(Tag, StringComparison.Ordinal);

    /// <summary>
    /// Whether a stored value is a non-empty password still held in the clear, and so should be
    /// re-written in protected form when a caller is in a position to do so.
    /// </summary>
    public static bool NeedsUpgrade(string? stored) =>
        !string.IsNullOrWhiteSpace(stored) && !IsProtected(stored);
}
