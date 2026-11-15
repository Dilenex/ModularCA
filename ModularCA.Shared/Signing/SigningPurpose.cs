namespace ModularCA.Shared.Signing;

/// <summary>
/// What a caller is asking the signer to do with a key. The signer's policy is keyed on this
/// together with the kind of key: a CA key signs certificates, CRLs and protocol responses for
/// its own CA; a delegated OCSP responder key signs OCSP responses only; the TSA key signs
/// timestamp tokens only. Ceremony, Backup, Export, Bootstrap, Restore and SshKeyMigration name
/// the contexts under which key generation, import and export are permitted rather than a
/// signature operation. A signing purpose also fixes the structure that is signed: the signer
/// parses the bytes and refuses any that are not it (see <see cref="ISigningService.SignAsync"/>).
/// </summary>
public enum SigningPurpose
{
    /// <summary>Sign an X.509 certificate.</summary>
    Certificate,

    /// <summary>Sign a certificate revocation list, full or delta.</summary>
    Crl,

    /// <summary>Sign an OCSP response.</summary>
    Ocsp,

    /// <summary>Sign or decrypt a SCEP envelope.</summary>
    Scep,

    /// <summary>Sign a CMP response.</summary>
    Cmp,

    /// <summary>Sign a timestamp token.</summary>
    Tsa,

    /// <summary>A key ceremony: generation, import or cross-certification under quorum.</summary>
    Ceremony,

    /// <summary>A backup export of the keystore.</summary>
    Backup,

    /// <summary>Export of an end-entity key to its holder.</summary>
    Export,

    /// <summary>Initial bootstrap of the node, before any ceremony exists. It moves whole keystore files only and manages no individual key.</summary>
    Bootstrap,

    /// <summary>Restore of a backup: keystore files imported through the signer as the archive carries them.</summary>
    Restore,

    /// <summary>
    /// A delegated key of an existing CA: its OCSP responder, timestamp or CMP signer. Generated
    /// and committed without a ceremony, held to the CA and space named, and never committed to
    /// a CA certificate; reissuing a responder is an operator's action, not a ceremony.
    /// </summary>
    Infrastructure,

    /// <summary>
    /// The settings store keeping or reading a secret setting. It wraps and unwraps
    /// <see cref="SecretKind.SettingSecret"/> and nothing else, and signs nothing.
    /// </summary>
    Configuration,

    /// <summary>
    /// Sign an SSH certificate, which the signer builds from its fields
    /// (<see cref="ISigningService.SignSshCertificateAsync"/>, <c>ssh-keystore.md</c>). The
    /// purpose permits that call and nothing else: no raw signature, no decryption, no key
    /// management, no export and no secret wrap.
    /// </summary>
    SshCertificate,

    /// <summary>
    /// The one-time move of an SSH CA key from a file on the node into the signer. It permits
    /// <see cref="ISigningService.ImportKeyAsync"/> of a PKCS#8 key into
    /// <see cref="KeyRef.SshKeystore"/> for an <c>SshCaKeys</c> row whose storage is
    /// <c>LegacyFile</c> and whose public key is the key's, and nothing else. It needs no ceremony.
    /// </summary>
    SshKeyMigration,

    /// <summary>
    /// Recording a fact the node asserts in the signer's journal (<c>RecordFact</c>): a
    /// revocation, a released hold, a spent token, a restore, a changed incarnation, something
    /// disabled. It permits that call and nothing else, and no key is used under it.
    /// </summary>
    JournalFact,

    /// <summary>
    /// Sign a new certificate for an existing CA over the key it already has
    /// (<c>docs/architecture/ca-certificate-renewal.md</c>): a root's key signs its own new
    /// certificate, a parent's key signs its child's. It permits that signature and nothing else.
    /// The signer finds the CA being renewed from the subject key, which must be the key of that
    /// CA's current certificate and a key it holds, and signs only a certificate that repeats the
    /// current one in everything but its serial, its validity and, for an intermediate, where its
    /// issuer is found (authority key identifier, CRL distribution points, authority information
    /// access). The context names the CA whose key signs; a ceremony it names must be an approved
    /// <c>RenewCaCertificate</c> ceremony for the CA being renewed, and one is required where the
    /// CA's scope requires a key ceremony.
    /// </summary>
    CaCertificateRenewal,
}
