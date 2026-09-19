using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Utils;

namespace ModularCA.Signer.Identity;

/// <summary>
/// Reads and writes the PKCS#12 files the signer channel's identities live in. A file is
/// written owner-only through <see cref="FileSecurityUtil"/>, as every other secret file
/// under <c>config/</c> is; it is read with a persisted key so the platform TLS stack can use
/// it, which an ephemeral key cannot be on Windows.
/// </summary>
public static class Pkcs12Files
{
    /// <summary>
    /// Writes <paramref name="certificate"/> with its private key, followed by
    /// <paramref name="chain"/>, to <paramref name="path"/> under <paramref name="password"/>,
    /// and tightens the file to its owner. An existing file is replaced.
    /// </summary>
    public static void Write(string path, X509Certificate2 certificate, IEnumerable<X509Certificate2>? chain, string password)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(certificate);
        var collection = new X509Certificate2Collection { certificate };
        // Chain entries go in public-only: the issuer's key is never copied into a leaf's file,
        // and a persisted issuer key may not be exportable anyway.
        foreach (var c in chain ?? Array.Empty<X509Certificate2>())
            collection.Add(X509CertificateLoader.LoadCertificate(c.RawData));
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        File.WriteAllBytes(path, collection.Export(X509ContentType.Pkcs12, password ?? string.Empty)!);
        FileSecurityUtil.SetOwnerOnly(path);
    }

    /// <summary>
    /// Loads the certificate with the private key from <paramref name="path"/>. Throws
    /// <see cref="FileNotFoundException"/> when the file is missing, so the caller can say
    /// which configured path it is.
    /// </summary>
    public static X509Certificate2 Load(string path, string password)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!File.Exists(path))
            throw new FileNotFoundException($"The PKCS#12 file '{path}' does not exist.", path);
        return X509CertificateLoader.LoadPkcs12FromFile(path, password ?? string.Empty, X509KeyStorageFlags.DefaultKeySet);
    }

    /// <summary>
    /// Loads a certificate with its private key from PKCS#12 bytes, as <see cref="Load(string, string)"/>
    /// does from a file. With <paramref name="exportable"/> the key can be written out again,
    /// which a freshly generated identity needs and a loaded one does not.
    /// </summary>
    public static X509Certificate2 Load(byte[] pkcs12, string password, bool exportable = false)
    {
        ArgumentNullException.ThrowIfNull(pkcs12);
        var flags = X509KeyStorageFlags.DefaultKeySet | (exportable ? X509KeyStorageFlags.Exportable : X509KeyStorageFlags.DefaultKeySet);
        return X509CertificateLoader.LoadPkcs12(pkcs12, password ?? string.Empty, flags);
    }
}
