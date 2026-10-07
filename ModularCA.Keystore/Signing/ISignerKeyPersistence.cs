namespace ModularCA.Keystore.Signing;

/// <summary>
/// Where the signer writes a key it has committed: the private key and the certificate it now
/// belongs to, as a pair, since the keystore pairs keys with certificates by public key when it
/// loads. An SSH CA key has no certificate and is written alone, to a keystore of its own. The
/// file-backed implementation appends to the keystore files through the existing append path;
/// a test implementation keeps what it is given in memory.
/// </summary>
/// <remarks>
/// The persistence is also the only thing that reads or replaces a keystore file whole, which
/// is what a backup and a restore do through the signer: a backup takes the files as they are
/// kept, encrypted under the keystore passphrases and signed by the pinned signer, and a
/// restore puts such files back after their signatures verify against the pin.
/// </remarks>
public interface ISignerKeyPersistence
{
    /// <summary>
    /// Persists <paramref name="privateKeyPkcs8Der"/> and <paramref name="certificateDer"/>
    /// durably. The private key is written first and the certificate second, so a failure
    /// between the two leaves a key that pairs with nothing and is never loaded.
    /// </summary>
    void Append(byte[] privateKeyPkcs8Der, byte[] certificateDer);

    /// <summary>
    /// Persists an SSH CA key durably in <c>ssh-ca.keystore</c> and nowhere else: the key has no
    /// certificate, and nothing is written to the trust keystore. The first key creates the
    /// keystore; an install that never commits or imports an SSH key never has one.
    /// </summary>
    void AppendSshKey(byte[] privateKeyPkcs8Der);

    /// <summary>
    /// The names of the keystore files the persistence holds, for a backup to walk.
    /// </summary>
    IReadOnlyList<string> ListKeystoreFiles();

    /// <summary>
    /// Reads the keystore file <paramref name="name"/> byte for byte as it is kept. Throws
    /// <see cref="FileNotFoundException"/> when there is no such file.
    /// </summary>
    byte[] ReadKeystoreFile(string name);

    /// <summary>
    /// Verifies <paramref name="bytes"/> as a keystore file signed by the pinned signer for
    /// <paramref name="name"/> and, only then, makes it the file in place, keeping the previous
    /// file beside it so the operator can go back. Throws
    /// <see cref="System.Security.SecurityException"/>, <see cref="System.Security.Cryptography.CryptographicException"/>
    /// or <see cref="InvalidDataException"/> when the bytes do not verify, in which case nothing
    /// in place has changed.
    /// </summary>
    void ImportKeystoreFile(string name, byte[] bytes);
}
