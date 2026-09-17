namespace ModularCA.Shared.Signing;

/// <summary>
/// What kind of key a stored private key is, decided from what the database already records
/// about the certificate it belongs to. The signer's policy is a table over this and
/// <see cref="SigningPurpose"/>.
/// </summary>
public enum KeyKind
{
    /// <summary>Nothing in the database says what this key is for. It signs nothing.</summary>
    Unknown,

    /// <summary>The key of a certificate authority: a <c>CertificateAuthorities</c> row names its certificate.</summary>
    Ca,

    /// <summary>The key of a CA's delegated OCSP responder certificate.</summary>
    OcspResponder,

    /// <summary>The key of a CA's timestamp authority certificate.</summary>
    Tsa,

    /// <summary>The key of a CA's CMP protection certificate.</summary>
    CmpSigner,

    /// <summary>The key of an end-entity certificate: held only so it can be exported to its holder.</summary>
    EndEntity,
}

/// <summary>
/// What a caller asks the signer to generate: the algorithm and size or curve, and an optional
/// label for backends that name their objects, such as PKCS#11 tokens.
/// </summary>
/// <param name="Algorithm">The key algorithm: <c>RSA</c>, <c>ECDSA</c>, <c>Ed25519</c>, <c>ML-DSA</c> and so on.</param>
/// <param name="SizeOrCurve">The RSA modulus size or the named curve, as the key policy already spells them.</param>
/// <param name="Label">A label for the key object on a backend that has one, or null.</param>
public sealed record KeySpec(string Algorithm, string SizeOrCurve, string? Label = null);

/// <summary>
/// A key the signer just generated: the reference the caller keeps, and the DER-encoded
/// SubjectPublicKeyInfo it needs to build a certificate or request around.
/// </summary>
/// <param name="Key">The reference to the new key.</param>
/// <param name="PublicKeyDer">The public half, DER-encoded SubjectPublicKeyInfo.</param>
public sealed record GeneratedKey(KeyRef Key, byte[] PublicKeyDer);

/// <summary>
/// Key material offered to the signer for import, wrapped so that it never crosses the contract
/// in the clear once the signer is remote.
/// </summary>
/// <param name="Wrapped">The wrapped key bytes. The signer zeroes them once it has parsed them.</param>
/// <param name="Format">The wrapping format, for the signer to recognise how to unwrap: <see cref="Pkcs8"/> for one key, <see cref="KeystoreFile"/> for a whole keystore file.</param>
/// <param name="CertificateId">The certificate the key belongs to; its row must exist and carry the key's public half. Empty for a keystore file.</param>
/// <param name="Keystore">The keystore the material belongs to; the file name for <see cref="KeystoreFile"/>.</param>
public sealed record KeyMaterial(byte[] Wrapped, string Format, Guid CertificateId, string Keystore = KeyRef.DefaultKeystore)
{
    /// <summary>DER-encoded PKCS#8 PrivateKeyInfo, in the clear; the in-process wrapping.</summary>
    public const string Pkcs8 = "pkcs8";

    /// <summary>
    /// A whole keystore file as the signer's persistence keeps it: encrypted under the keystore
    /// passphrases and signed by the pinned signer, so it is already wrapped. This is what a
    /// restore offers under a <see cref="SigningPurpose.Restore"/> or <see cref="SigningPurpose.Bootstrap"/>
    /// context; the signer verifies the signature against the pin before the file replaces the
    /// one in place.
    /// </summary>
    public const string KeystoreFile = "keystore-file";
}

/// <summary>
/// How an exported key is to be wrapped: PKCS#12 under a password the caller chose, which is
/// how a stored end-entity key is handed to its holder; or, for a backup, the keystore file as
/// it is kept, which is already wrapped under the keystore passphrases.
/// </summary>
/// <param name="Format">The wrapping format, <see cref="Pkcs12"/> for a key, <see cref="KeystoreFile"/> for a whole keystore.</param>
/// <param name="Password">The password the wrapping is placed under; ignored for <see cref="KeystoreFile"/>, whose wrap is the keystore's own.</param>
/// <param name="Chain">
/// Certificates to place beside the key's own in the PKCS#12, DER-encoded, issuer first: the
/// chain the holder needs to present the certificate. Null or empty for the certificate alone.
/// </param>
public sealed record ExportWrap(string Format, string Password, IReadOnlyList<byte[]>? Chain = null)
{
    /// <summary>PKCS#12 under a caller-supplied password.</summary>
    public const string Pkcs12 = "pkcs12";

    /// <summary>
    /// The keystore file the reference names, byte for byte as the signer's persistence keeps
    /// it: encrypted under the keystore passphrases and signed by the pinned signer. Allowed
    /// under <see cref="SigningPurpose.Backup"/> only, and the one export a locked signer
    /// performs, since it hands out no usable key.
    /// </summary>
    public const string KeystoreFile = "keystore-file";

    /// <summary>A backup wrap for a whole keystore file.</summary>
    public static ExportWrap ForKeystoreFile() => new(KeystoreFile, string.Empty);
}

/// <summary>
/// One key the signer holds, as <see cref="ISigningService.ListKeysAsync"/> reports it: the
/// reference, its public half, what kind of key it is and where it lives.
/// </summary>
/// <param name="Key">The reference callers use to sign with it.</param>
/// <param name="PublicKeyDer">The public half, DER-encoded SubjectPublicKeyInfo.</param>
/// <param name="Kind">What the database says the key is for.</param>
/// <param name="CaId">The <c>CertificateAuthorities</c> row that owns the key, when one does.</param>
/// <param name="TenantId">The tenant the owning CA belongs to, when one does.</param>
/// <param name="Backend">Where the key lives: <see cref="SignerHealth.SoftwareBackend"/> or <see cref="SignerHealth.Pkcs11Backend"/>.</param>
public sealed record KeyInfo(KeyRef Key, byte[] PublicKeyDer, KeyKind Kind, Guid? CaId, Guid? TenantId, string Backend);
