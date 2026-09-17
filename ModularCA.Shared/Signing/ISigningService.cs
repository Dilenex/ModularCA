namespace ModularCA.Shared.Signing;

/// <summary>
/// The only door to a stored private key. Callers hold a <see cref="KeyRef"/>, never a key, and
/// every operation carries a <see cref="SigningContext"/> the signer judges and audits. In
/// process today, behind a mutually authenticated channel tomorrow, with the same contract.
/// </summary>
/// <remarks>
/// The policy the signer applies, keyed on the kind of key and the purpose:
/// <list type="bullet">
/// <item>a CA key signs certificates, CRLs, OCSP, SCEP and CMP responses for its own CA only;</item>
/// <item>a delegated OCSP responder key signs OCSP responses for its own CA only;</item>
/// <item>the TSA key signs timestamp tokens for its own CA only;</item>
/// <item>a CMP protection key signs CMP responses for its own CA only;</item>
/// <item>export is allowed only for end-entity keys and only to a caller holding the export right;</item>
/// <item>generation, import, commit and retire are allowed only under a ceremony or bootstrap context;</item>
/// <item>a generated key not yet committed signs only under the context that generated it.</item>
/// </list>
/// Anything else is refused with a <see cref="SigningRefusedException"/>, and every decision,
/// allowed or refused, is written to the signer's own audit before the call returns.
/// </remarks>
public interface ISigningService
{
    /// <summary>
    /// Signs <paramref name="data"/> with the key of <paramref name="key"/> using
    /// <paramref name="algorithm"/>, and returns the raw signature bytes as the algorithm
    /// defines them (PKCS#1 v1.5 for RSA, DER-encoded r/s for ECDSA).
    /// </summary>
    /// <exception cref="SigningRefusedException">The key is unknown, or policy refuses the purpose or CA.</exception>
    Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a CMS envelope addressed to the key. SCEP is the only protocol that needs this:
    /// its clients encrypt the request to the CA (RA) certificate.
    /// </summary>
    /// <exception cref="SigningRefusedException">The key is unknown, or policy refuses the purpose or CA.</exception>
    Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a new key inside the signer and returns its reference and public half. Allowed
    /// only under a <see cref="SigningPurpose.Ceremony"/> or <see cref="SigningPurpose.Bootstrap"/> context.
    /// The key has no certificate yet: it is held pending, signs only under the context that
    /// generated it, and is written nowhere until <see cref="CommitKeyAsync"/> binds it to the
    /// certificate row that carries its public key. <see cref="RetireKeyAsync"/> discards it.
    /// </summary>
    /// <exception cref="SigningRefusedException">The context is not a ceremony or bootstrap.</exception>
    Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Imports wrapped key material for a certificate row that already exists: a migration from
    /// an older keystore or an HSM import. The pair is persisted at once. Allowed only under a
    /// ceremony or bootstrap context. Material in the <see cref="KeyMaterial.KeystoreFile"/>
    /// format is a whole keystore file from a backup: it is verified against the pinned signer
    /// and replaces the file in place, under a <see cref="SigningPurpose.Restore"/> or
    /// <see cref="SigningPurpose.Bootstrap"/> context, locked or not, since restoring the
    /// keystore is how a signer comes to hold keys at all.
    /// </summary>
    /// <exception cref="SigningRefusedException">The context is not one the format allows, the format is not accepted, the certificate does not carry the key's public half, or a keystore file does not verify.</exception>
    Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Commits a key from <see cref="GenerateKeyAsync"/> to the certificate it now belongs to:
    /// the signer checks that certificate row <paramref name="certificateId"/> carries the key's
    /// public half, persists the pair durably, and from then on serves the key under the policy
    /// for its kind, addressed by <c>new KeyRef(certificateId)</c>. The generated reference is
    /// spent. Allowed only under a ceremony or bootstrap context.
    /// </summary>
    /// <exception cref="SigningRefusedException">The context is not a ceremony or bootstrap, no generated key awaits under <paramref name="key"/>, or the certificate is missing or is not the key's.</exception>
    Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exports a key wrapped as <paramref name="wrap"/> says. Allowed for an end-entity key under
    /// an <see cref="SigningPurpose.Export"/> context, and for every stored key under a
    /// <see cref="SigningPurpose.Backup"/> context; the context must name its caller, and a
    /// PKCS#11 key never leaves its token. A certificate the signer holds no key for is refused
    /// as <see cref="SigningRefusalReason.UnknownKey"/>: since re-download ended, a key the CA
    /// generates is delivered once, with the request that carries it, and is not kept. A
    /// reference to a whole keystore (<see cref="KeyRef.ForKeystore"/>) with the
    /// <see cref="ExportWrap.KeystoreFile"/> wrap returns the file as the signer keeps it,
    /// under Backup only, locked or not.
    /// </summary>
    /// <exception cref="SigningRefusedException">The key is unknown, or policy refuses the export.</exception>
    Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the keys the signer holds, with their public halves and what kind of key each is.
    /// A context naming a CA lists that CA's keys only.
    /// </summary>
    Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retires a key: it is no longer available to sign with. For a generated key that was not
    /// committed this discards it, which is the undo of a ceremony that failed after generating
    /// it. Allowed only under a ceremony or bootstrap context.
    /// </summary>
    /// <exception cref="SigningRefusedException">The key is unknown, the context is not a ceremony or bootstrap, or the key is committed and cannot be retired.</exception>
    Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reports whether the signer is unlocked, how many keys it holds and which backend holds them.
    /// </summary>
    Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default);
}
