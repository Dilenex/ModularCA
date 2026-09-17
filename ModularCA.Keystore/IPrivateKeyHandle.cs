namespace ModularCA.Keystore;

/// <summary>
/// A private key the signer holds, software or PKCS#11, behind an operation interface so the
/// signer never needs the raw key for a signature. This type lives in the keystore project and
/// nowhere else: nothing outside the signer holds a handle, and the architecture test in the
/// test suite fails the build of any Core, API, Auth or Bootstrap type that references one.
/// </summary>
public interface IPrivateKeyHandle
{
    /// <summary>Whether the key can be exported as PKCS#8 DER; false for a token-held key.</summary>
    bool CanExport { get; }

    /// <summary>The key as PKCS#8 DER, for a software key that allows it; null or an exception otherwise.</summary>
    byte[]? ExportPrivateKeyDer();

    /// <summary>Signs <paramref name="data"/> with the named algorithm and returns the raw signature.</summary>
    byte[] Sign(byte[] data, string algorithm);
}
