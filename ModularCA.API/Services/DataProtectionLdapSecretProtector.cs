using Microsoft.AspNetCore.DataProtection;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Services;

/// <summary>
/// <see cref="ILdapSecretProtector"/> backed by ASP.NET Core Data Protection — the same keyring
/// that protects TOTP secrets, configured once in <c>StartModularCA</c> and persisted to Redis
/// when available or to the ACL-tightened <c>dp-keys</c> directory otherwise.
/// </summary>
/// <remarks>
/// The purpose string isolates this from the <c>TotpSecret</c> protector: a payload produced for
/// one cannot be decrypted by the other, so a value moved between the two columns fails to
/// decrypt instead of silently round-tripping.
/// </remarks>
public sealed class DataProtectionLdapSecretProtector : ILdapSecretProtector
{
    private readonly IDataProtector _protector;

    /// <summary>
    /// Creates the protector for LDAP publisher bind passwords.
    /// </summary>
    /// <param name="provider">The application's Data Protection provider.</param>
    public DataProtectionLdapSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("LdapPublisherPassword");
    }

    /// <inheritdoc />
    public string Protect(string? plaintext)
    {
        if (string.IsNullOrWhiteSpace(plaintext))
            return string.Empty;

        // Already protected — re-protecting would nest one payload inside another and the value
        // would need two passes to read back. Callers that re-save an unchanged row hit this.
        if (LdapSecretProtection.IsProtected(plaintext))
            return plaintext;

        return LdapSecretProtection.Tag + _protector.Protect(plaintext);
    }

    /// <inheritdoc />
    public string Unprotect(string? stored)
    {
        if (string.IsNullOrWhiteSpace(stored))
            return string.Empty;

        // Written before this protection existed. Returned as-is so an upgrade does not break
        // publishers that are working; the caller re-writes the row in protected form.
        if (!LdapSecretProtection.IsProtected(stored))
            return stored;

        return _protector.Unprotect(stored[LdapSecretProtection.Tag.Length..]);
    }
}
