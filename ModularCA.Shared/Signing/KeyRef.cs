namespace ModularCA.Shared.Signing;

/// <summary>
/// A reference to a stored private key: the id of the certificate the key belongs to, and the
/// name of the keystore that holds it. This is how the keystore already addresses its entries,
/// and it is the only thing a caller of <see cref="ISigningService"/> ever holds; the key itself
/// stays with the signer.
/// </summary>
/// <param name="CertificateId">
/// The <c>Certificates</c> row id of the certificate whose key this is. An SSH CA key has no
/// certificate: for a key in <see cref="SshKeystore"/> this is its <c>SshCaKeys</c> row id.
/// </param>
/// <param name="Keystore">The keystore file name holding the entry, <see cref="DefaultKeystore"/> unless a key lives elsewhere.</param>
public sealed record KeyRef(Guid CertificateId, string Keystore = KeyRef.DefaultKeystore)
{
    /// <summary>The keystore every CA and infrastructure private key is written to today.</summary>
    public const string DefaultKeystore = "ca-certs.keystore";

    /// <summary>The keystore the trusted CA certificates are written to, beside <see cref="DefaultKeystore"/>.</summary>
    public const string TrustKeystore = "ca-trust.keystore";

    /// <summary>
    /// The keystore SSH CA keys live in (<c>ssh-keystore.md</c>). The file is what makes a key an
    /// SSH key: the signer serves a key under this name only when it loaded, committed or
    /// imported it into this file, and a reference naming this keystore reaches no other key. A
    /// raw signature with a key in it is refused for every purpose. The file exists only once
    /// an SSH key has been committed or imported.
    /// </summary>
    public const string SshKeystore = "ssh-ca.keystore";

    /// <summary>The keystore files a backup carries, in the order a backup writes them.</summary>
    public static readonly IReadOnlyList<string> BackupKeystores = new[] { DefaultKeystore, TrustKeystore };

    /// <summary>
    /// A reference to a whole keystore file rather than one key in it: <see cref="CertificateId"/>
    /// is empty. This is what a backup exports and a restore imports, through the
    /// <see cref="ExportWrap.KeystoreFile"/> wrap and the <see cref="KeyMaterial.KeystoreFile"/> format.
    /// </summary>
    public static KeyRef ForKeystore(string keystore) => new(Guid.Empty, keystore);

    /// <summary>Whether this reference names a whole keystore file rather than a key.</summary>
    public bool IsKeystoreFile => CertificateId == Guid.Empty;

    /// <summary>Renders the reference as <c>keystore:certificate-id</c> for logs and audit rows.</summary>
    public override string ToString() => $"{Keystore}:{CertificateId}";
}
