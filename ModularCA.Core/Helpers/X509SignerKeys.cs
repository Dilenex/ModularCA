using ModularCA.Shared.Signing;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Finds the key of an X.509 certificate among the keys the signer lists. The list also carries
/// SSH CA keys, each under its <c>SshCaKeys</c> row id, and an id alone does not say which kind
/// of row it names. Every caller that asks "does the signer hold the key of this certificate"
/// asks here, so an SSH CA key is never taken for the key of a certificate.
/// </summary>
public static class X509SignerKeys
{
    /// <summary>
    /// Whether <paramref name="key"/> can be the key of an X.509 certificate: it is not of kind
    /// <see cref="KeyKind.SshCa"/> and its reference does not name <see cref="KeyRef.SshKeystore"/>.
    /// </summary>
    public static bool IsX509(KeyInfo key)
        => key.Kind != KeyKind.SshCa
           && !string.Equals(key.Key.Keystore, KeyRef.SshKeystore, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The listed key of certificate <paramref name="certificateId"/>, or null when the signer
    /// lists none. SSH CA keys are passed over, whatever id they are listed under.
    /// </summary>
    public static KeyInfo? Find(IEnumerable<KeyInfo> keys, Guid certificateId)
        => keys.FirstOrDefault(k => IsX509(k) && k.Key.CertificateId == certificateId);

    /// <summary>Whether <paramref name="keys"/> lists the key of certificate <paramref name="certificateId"/>; see <see cref="Find"/>.</summary>
    public static bool Holds(IEnumerable<KeyInfo> keys, Guid certificateId) => Find(keys, certificateId) != null;
}
