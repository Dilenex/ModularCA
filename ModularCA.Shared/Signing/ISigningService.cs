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
/// <item>generation, commit and retire are allowed only under a ceremony or infrastructure context, import only under a ceremony;</item>
/// <item>a generated key not yet committed signs only under the context that generated it;</item>
/// <item>
/// what is signed is typed: <see cref="SignAsync"/> parses the bytes as the one structure the
/// key and purpose sign and refuses anything else (see <see cref="SignAsync"/>), so a purpose
/// label constrains what a key signs, not only which key signs;
/// </item>
/// <item>
/// an SSH CA key, which is every key in <see cref="KeyRef.SshKeystore"/> and no other, signs
/// nothing through <see cref="SignAsync"/> for any purpose, decrypts nothing, and is never
/// exported as PKCS#12; while it is generated and not yet committed it signs nothing at all;
/// </item>
/// <item>
/// an SSH CA key is generated, committed and retired only under a ceremony context that states
/// the instance as its scope, never under an infrastructure context; it is committed only to
/// an enabled <c>SshCaKeys</c> row that carries its public key, of the enabled SSH CA the
/// context names;
/// </item>
/// <item>
/// a named ceremony licenses only its own kind of key: <c>CreateRootCA</c> and
/// <c>CreateIntermediateCA</c> an X.509 CA key, <c>CreateSshCa</c> an SSH CA key;
/// </item>
/// <item>
/// <see cref="SigningPurpose.SshKeyMigration"/> imports a PKCS#8 key into
/// <see cref="KeyRef.SshKeystore"/> for an <c>SshCaKeys</c> row whose storage is
/// <c>LegacyFile</c> and which carries the key's public key, without a ceremony, and permits
/// nothing else;
/// </item>
/// <item>
/// <see cref="SigningPurpose.SshCertificate"/> permits <see cref="SignSshCertificateAsync"/> and
/// nothing else, and that call is permitted under no other purpose. An SSH CA key signs an
/// SSH certificate the signer builds from the request's fields, and only that: for the SSH CA
/// the context names at instance scope, while its <c>SshCaKeys</c> row still carries its public
/// key, has storage <c>Signer</c> and is enabled, and its CA is an enabled, undeleted SSH CA
/// of the instance; of a type the row permits (<c>IsUserCa</c>, <c>IsHostCa</c>); valid for no
/// longer than the row's <c>MaxValidityHours</c>, from a start close to the signer's own
/// clock; with at least one principal, a non-zero serial, only the known critical options and
/// extensions (none on a host certificate), and a subject key that is Ed25519, ECDSA P-256,
/// P-384 or P-521, or RSA of at least 2048 bits, and is not the CA's own key. The nonce, the
/// signature key and the signature algorithm are the signer's, and the certificate is
/// returned only once its signature verifies under the CA public key;
/// </item>
/// <item>
/// secrets are wrapped and unwrapped under the purposes listed for their
/// <see cref="SecretKind"/>: <see cref="SigningPurpose.Cmp"/> both wraps and unwraps a CMP
/// shared secret, <see cref="SigningPurpose.Certificate"/> wraps a held private key and
/// <see cref="SigningPurpose.Export"/> unwraps one, and nothing else wraps or unwraps anything.
/// </item>
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
    /// <remarks>
    /// <para>
    /// The signer parses <paramref name="data"/> before it signs. It must be exactly one DER
    /// object of the structure the key and purpose sign, and that structure must name
    /// <paramref name="algorithm"/> where it names one:
    /// </para>
    /// <list type="bullet">
    /// <item><see cref="SigningPurpose.Certificate"/>, CA key: a v3 TBSCertificate whose issuer is the CA's subject;</item>
    /// <item><see cref="SigningPurpose.Crl"/>, CA key: a TBSCertList whose issuer is the CA's subject;</item>
    /// <item><see cref="SigningPurpose.Ocsp"/>, CA or responder key: a ResponseData whose responder id is the signing key's certificate;</item>
    /// <item><see cref="SigningPurpose.Scep"/>, CA key: CMS signed attributes with content type id-data and a SCEP messageType;</item>
    /// <item><see cref="SigningPurpose.Cmp"/>, CA or CMP signer key: a CMP ProtectedPart;</item>
    /// <item><see cref="SigningPurpose.Tsa"/>, TSA key: CMS signed attributes with content type id-ct-TSTInfo;</item>
    /// <item>
    /// a generated key not yet committed, under its ceremony or infrastructure context: a
    /// PKCS#10 CertificationRequestInfo for its own key; a key generated for a new CA also its
    /// own self-signed CA certificate, and once certified as a CA the non-CA certificates of the
    /// delegated keys generated under the same ceremony.
    /// </item>
    /// </list>
    /// <para>
    /// A certificate asserts keyCertSign, cRLSign, a path length or name constraints only with
    /// <c>cA=TRUE</c>. A <c>cA=TRUE</c> certificate is signed only for a key the signer itself
    /// generated under a ceremony context for a new CA, still holds uncommitted and has not yet
    /// certified as a CA, and within the signing CA's path length. An OCSP-signing certificate
    /// is signed only for a delegated key the signer generated for the signing CA and still
    /// holds uncommitted. Neither is signed for a key from outside the signer, whatever ceremony
    /// the context names: cross-certification and external responders wait for approvals the
    /// signer can verify. Refusals carry <see cref="SigningRefusalReason.UntypedData"/>,
    /// <see cref="SigningRefusalReason.AlgorithmMismatch"/>, <see cref="SigningRefusalReason.IssuerMismatch"/>,
    /// <see cref="SigningRefusalReason.EvidenceRequired"/> or
    /// <see cref="SigningRefusalReason.PurposeNotPermitted"/>, and are audited like any other.
    /// </para>
    /// </remarks>
    /// <exception cref="SigningRefusedException">The key is unknown, policy refuses the purpose or CA, or the data is not what the purpose signs.</exception>
    Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Builds an OpenSSH certificate from <paramref name="request"/>, signs it with the SSH CA
    /// key the request names and returns the whole certificate blob; the caller renders
    /// <c>type base64 comment</c> from it. This is the only way an SSH CA key signs anything: the
    /// signer never takes bytes to sign with one, so what it signs is always a certificate it
    /// built and checked itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The context must have purpose <see cref="SigningPurpose.SshCertificate"/>, name the SSH CA
    /// the key belongs to and state the instance as its scope. The key must be bound to its
    /// <c>SshCaKeys</c> row in <see cref="KeyRef.SshKeystore"/>, and the row is read on every
    /// call: it must still carry the key's public key, have storage <c>Signer</c> and be
    /// enabled, and its CA must be an enabled, undeleted SSH CA with no space. The row's
    /// <c>IsUserCa</c>, <c>IsHostCa</c> and <c>MaxValidityHours</c> bound the certificate, and
    /// the remaining rules (principals, serial, options, subject key, the start of validity
    /// against the signer's clock) are the signer's own. A key held on a PKCS#11 token is
    /// refused as <see cref="SigningRefusalReason.OperationUnsupported"/> until SSH keys on
    /// tokens are built.
    /// </para>
    /// <para>
    /// The signer makes the nonce, writes the CA public key as the signature key and chooses the
    /// signature algorithm from that key (RSA signs <c>rsa-sha2-512</c>); the request has no
    /// field for any of them. The certificate is returned only once its signature verifies
    /// under the CA public key. Fields that are malformed or break a rule are refused as
    /// <see cref="SigningRefusalReason.UntypedData"/>, and a signature that does not verify as
    /// <see cref="SigningRefusalReason.IntegrityFailure"/>. Every call, allowed or refused, is
    /// audited with the certificate's type, serial, key id, validity and the number of its
    /// principals, never their names, and an issued certificate with its SHA-256.
    /// </para>
    /// </remarks>
    /// <param name="request">The SSH CA key and the certificate's fields.</param>
    /// <param name="context">Who is asking: purpose <see cref="SigningPurpose.SshCertificate"/>, the SSH CA, instance scope.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The certificate blob, as OpenSSH encodes it.</returns>
    /// <exception cref="SigningRefusedException">The key is unknown or not usable, policy refuses the context, the fields break a rule, or the signer in use predates this call.</exception>
    Task<byte[]> SignSshCertificateAsync(SshCertificateRequest request, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a CMS envelope addressed to the key. SCEP is the only protocol that needs this:
    /// its clients encrypt the request to the CA (RA) certificate. An SSH CA key decrypts nothing.
    /// </summary>
    /// <exception cref="SigningRefusedException">The key is unknown, or policy refuses the purpose or CA.</exception>
    Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a new key inside the signer and returns its reference and public half. Allowed
    /// only under a <see cref="SigningPurpose.Ceremony"/> or <see cref="SigningPurpose.Infrastructure"/> context.
    /// The key has no certificate yet: it is held pending, signs only under the context that
    /// generated it, and is written nowhere until <see cref="CommitKeyAsync"/> binds it to the
    /// certificate row that carries its public key. <see cref="RetireKeyAsync"/> discards it.
    /// With <see cref="KeySpec.SshUsage"/> the key is an SSH CA key: Ed25519, ECDSA P-256, P-384
    /// or P-521, or RSA of at least 2048 bits, generated under a ceremony context at instance
    /// scope only, returned under a reference in <see cref="KeyRef.SshKeystore"/>, and signing
    /// nothing until it is committed to its <c>SshCaKeys</c> row.
    /// </summary>
    /// <exception cref="SigningRefusedException">The context is not a ceremony or infrastructure context, its scope's ceremony policy refuses it, or the spec names a usage or, for an SSH CA key, an algorithm the signer does not generate.</exception>
    Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Imports wrapped key material for a certificate row that already exists: a migration from
    /// an older keystore or an HSM import. The pair is persisted at once. Allowed only under a
    /// ceremony context held to the scope of the CA that owns the certificate. Material in the <see cref="KeyMaterial.KeystoreFile"/>
    /// format is a whole keystore file from a backup: it is verified against the pinned signer
    /// and replaces the file in place, under a <see cref="SigningPurpose.Restore"/> or
    /// <see cref="SigningPurpose.Bootstrap"/> context, locked or not, since restoring the
    /// keystore is how a signer comes to hold keys at all. PKCS#8 material offered to
    /// <see cref="KeyRef.SshKeystore"/> is an SSH CA key moving off the node: it is imported
    /// only under <see cref="SigningPurpose.SshKeyMigration"/>, for the <c>SshCaKeys</c> row
    /// <see cref="KeyMaterial.CertificateId"/> names, which must have storage <c>LegacyFile</c>
    /// and carry the key's public key, of the SSH CA the context names at instance scope. That
    /// import can be repeated: offering the key the signer already holds for the row succeeds
    /// and writes nothing, and offering another key for a row it holds a key for is refused.
    /// A whole <see cref="KeyRef.SshKeystore"/> file is restored only into a database that has
    /// its <c>Keystores</c> row, which carries the pin it is verified against. Material in the
    /// <see cref="KeyMaterial.KeystoreFileAbsent"/> format carries no bytes and says that the
    /// state a restore brings has no SSH keystore: under <see cref="SigningPurpose.Restore"/>,
    /// and only while the database has no <c>Keystores</c> row for it, a file the signer still
    /// keeps under that name is moved aside so that it cannot keep the signer locked.
    /// </summary>
    /// <exception cref="SigningRefusedException">The context is not one the format or the keystore allows, the format is not accepted, the certificate or SSH CA key row does not carry the key's public half, a keystore file does not verify, or a keystore declared absent has its row or is not the SSH keystore.</exception>
    Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Commits a key from <see cref="GenerateKeyAsync"/> to the certificate it now belongs to:
    /// the signer checks that certificate row <paramref name="certificateId"/> carries the key's
    /// public half, persists the pair durably, and from then on serves the key under the policy
    /// for its kind, addressed by <c>new KeyRef(certificateId)</c>. The generated reference is
    /// spent. Allowed only under a ceremony or infrastructure context; a key generated for a CA
    /// binds only to a certificate of that CA, and an infrastructure key only to a delegated
    /// signer certificate of the CA the context names. An SSH CA key, whose reference is in
    /// <see cref="KeyRef.SshKeystore"/>, has no certificate: <paramref name="certificateId"/> is
    /// then its <c>SshCaKeys</c> row id, the row must carry the key's public key, be enabled and
    /// have storage <c>Signer</c>, and its CA must be the enabled SSH CA the context names at
    /// instance scope. The key is written to the SSH keystore, which the first such commit
    /// creates, and is addressed from then on by <c>new KeyRef(certificateId, KeyRef.SshKeystore)</c>.
    /// A key generated for X.509 is never committed to an SSH CA key row, nor an SSH CA key to
    /// a certificate.
    /// </summary>
    /// <exception cref="SigningRefusedException">The context is not a ceremony or infrastructure context, no generated key awaits under <paramref name="key"/>, the certificate or SSH CA key row is missing or is not the key's, or it belongs to another CA or scope.</exception>
    Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exports a key wrapped as <paramref name="wrap"/> says. A single key leaves as PKCS#12 only
    /// when it is an end-entity key and the context is <see cref="SigningPurpose.Export"/>; a CA,
    /// responder, TSA, CMP, SSH CA or system key never leaves as PKCS#12, and a PKCS#12 request under
    /// <see cref="SigningPurpose.Backup"/> is refused as
    /// <see cref="SigningRefusalReason.PurposeNotPermitted"/>. The context must name its caller,
    /// and a PKCS#11 key never leaves its token. A certificate the signer holds no key for is refused
    /// as <see cref="SigningRefusalReason.UnknownKey"/>: since re-download ended, a key the CA
    /// generates is delivered once, with the request that carries it, and is not kept. A
    /// reference to a whole keystore (<see cref="KeyRef.ForKeystore"/>) with the
    /// <see cref="ExportWrap.KeystoreFile"/> wrap returns the file as the signer keeps it,
    /// under Backup only, locked or not.
    /// </summary>
    /// <exception cref="SigningRefusedException">The key is unknown, or policy refuses the export.</exception>
    Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Wraps a secret the node has to keep but cannot hold in the clear, so that the key which
    /// protects it lives in the keystore rather than on the node. This is not
    /// <see cref="ExportKeyAsync"/>: nothing here is a key the signer holds, and the caller names
    /// no key at all. It names what the secret <b>is</b>, with <paramref name="kind"/>, and the
    /// signer decides which key wraps for it and whether this context may ask.
    /// </summary>
    /// <param name="kind">What kind of secret this is; the policy is keyed on it and the purpose.</param>
    /// <param name="secret">The bytes to protect. The signer does not interpret them.</param>
    /// <param name="context">Who is asking and what for.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// An opaque blob, laid out as <see cref="WrappedSecretEnvelope"/> describes: it names its
    /// own kind and the key that wrapped it, so the key can be rotated and an old blob still
    /// unwraps under the key it names.
    /// </returns>
    /// <exception cref="SigningRefusedException">The purpose may not wrap this kind, the signer is locked, or the wrapping key cannot be derived.</exception>
    Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recovers a secret <see cref="WrapSecretAsync"/> wrapped. The blob says which kind of
    /// secret it holds and which key wrapped it; the caller says nothing about either, so a
    /// caller permitted to unwrap one kind cannot unwrap another by asking differently.
    /// </summary>
    /// <param name="wrapped">The blob as <see cref="WrapSecretAsync"/> returned it.</param>
    /// <param name="context">Who is asking and what for.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <exception cref="SigningRefusedException">
    /// The blob is not a well-formed envelope, the purpose may not unwrap its kind, the signer
    /// holds no key with the id the blob names, the signer is locked, or the blob does not
    /// authenticate under the key it names.
    /// </exception>
    Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// <see cref="WrapSecretAsync"/> for a secret that is kept in a named place:
    /// <paramref name="binding"/> names it, and the blob unwraps only for a caller that names the
    /// same place. A blob copied to another row of the same kind is therefore useless there.
    /// </summary>
    /// <param name="kind">What kind of secret this is; the policy is keyed on it and the purpose.</param>
    /// <param name="binding">Where the blob will be kept, for example <c>setting:JWT_Secret</c>.</param>
    /// <param name="secret">The bytes to protect. The signer does not interpret them.</param>
    /// <param name="context">Who is asking and what for.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A version 2 <see cref="WrappedSecretEnvelope"/>, which carries the binding.</returns>
    /// <exception cref="SigningRefusedException">As <see cref="WrapSecretAsync"/>, or the binding is empty or too long.</exception>
    Task<byte[]> WrapBoundSecretAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recovers a secret <see cref="WrapBoundSecretAsync"/> wrapped, for the place
    /// <paramref name="binding"/> names. The kind and the wrapping key come out of the blob as in
    /// <see cref="UnwrapSecretAsync"/>; the binding comes from the caller and has to be the one
    /// the blob was wrapped under.
    /// </summary>
    /// <param name="wrapped">The blob as <see cref="WrapBoundSecretAsync"/> returned it.</param>
    /// <param name="binding">Where the caller read the blob from.</param>
    /// <param name="context">Who is asking and what for.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <exception cref="SigningRefusedException">
    /// As <see cref="UnwrapSecretAsync"/>, or the blob carries no binding, or it was wrapped for
    /// another place.
    /// </exception>
    Task<byte[]> UnwrapBoundSecretAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the keys the signer holds, with their public halves and what kind of key each is.
    /// A context naming a CA lists that CA's keys only. An SSH CA key is listed with kind
    /// <see cref="KeyKind.SshCa"/> under its <c>SshCaKeys</c> row id in
    /// <see cref="KeyRef.SshKeystore"/>, as long as that row still carries its public key.
    /// </summary>
    Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retires a key: it is no longer available to sign with. For a generated key that was not
    /// committed this discards it, which is the undo of a ceremony that failed after generating
    /// it. Allowed only under a ceremony or infrastructure context, and for a generated SSH CA
    /// key only under a ceremony context at instance scope.
    /// </summary>
    /// <exception cref="SigningRefusedException">The key is unknown, the context is not a ceremony or infrastructure context, or the key is committed and cannot be retired.</exception>
    Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reports whether the signer is unlocked, how many keys it holds and which backend holds them.
    /// </summary>
    Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default);
}
