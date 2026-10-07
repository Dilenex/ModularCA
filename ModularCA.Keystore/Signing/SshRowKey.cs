using ModularCA.Ssh;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// Reads the public key an <c>SshCaKeys</c> row carries, which is an authorized_keys line. This
/// is the one place the signer parses it, so load, commit, import and use all compare a key to
/// its row the same way: by the OpenSSH wire-format blob, never by the text.
/// </summary>
internal static class SshRowKey
{
    /// <summary>The row's public key, or null when the text is not one supported OpenSSH public key.</summary>
    public static SshPublicKey? Parse(string? authorizedKey)
    {
        if (string.IsNullOrWhiteSpace(authorizedKey))
            return null;
        try
        {
            return SshPublicKey.ParseAuthorizedKey(authorizedKey);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
