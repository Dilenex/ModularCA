using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Keystore.Hsm;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The signer, in process: <see cref="ISigningService"/> over the keys the node decrypted from
/// its keystore at startup and the PKCS#11 keys it opened, held by <see cref="ISignerKeyRegistry"/>.
/// This is the implementation that runs behind the signer role once it is a separate process;
/// the node then talks to it through the same contract.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="KeyRef"/> names a certificate. The service classifies the key from what the
/// database already records about that certificate: a <c>CertificateAuthorities</c> row naming
/// it as the CA certificate makes it a CA key; naming it as the CA's OCSP responder, TSA or CMP
/// protection certificate makes it that kind of infrastructure key; a <c>Certificates</c> row
/// with no owning CA makes it an end-entity key; no row at all makes it unknown. The owning CA's
/// id and space come from the same row, and that is what the context is held to.
/// </para>
/// <para>
/// A key the signer generates or imports has no certificate yet. It is held pending, in the
/// signer's memory only, under a reference the signer mints, and signs only under the ceremony
/// or infrastructure context it was created in: that is how a new CA self-signs, signs its CSR, and
/// signs its infrastructure certificates before any row names it. <see cref="CommitKeyAsync"/>
/// binds the pending key to the certificate row that now carries its public key, persists the
/// pair through <see cref="ISignerKeyPersistence"/> and registers the identity; from then on the
/// key serves the policy for its kind. <see cref="RetireKeyAsync"/> discards a pending key. A
/// failure anywhere between generation and commit therefore leaves nothing on disk and nothing
/// that signs outside the ceremony that made it.
/// </para>
/// <para>
/// A signature is typed. Once the key and context pass the policy, <see cref="JudgeData"/>
/// parses the bytes as the one structure that key signs for that purpose
/// (<see cref="SignedDataTypes"/>) and refuses anything else, so a purpose label constrains what
/// is signed. A certificate asserting <c>cA=TRUE</c> is signed only for a pending key this
/// signer generated under a ceremony context for a new CA, and one carrying the OCSP-signing
/// EKU only for a pending delegated key it generated for the signing CA: a key from outside the
/// signer becomes neither, whatever the context claims.
/// </para>
/// <para>
/// The policy, keyed on kind and purpose, is in <see cref="JudgeSign"/>, <see cref="JudgeDecrypt"/>,
/// <see cref="JudgePending"/>, <see cref="JudgeKeyManagement"/> and <see cref="JudgeExport"/>. Every decision is written to the <see cref="ISignerAuditSink"/>
/// before the call returns. Classification is cached for a short while per certificate so a
/// signature costs one audit insert and nothing else once the key is known; a certificate never
/// changes kind, and the cache bounds how long a re-pointed responder certificate is still
/// believed to be one.
/// </para>
/// </remarks>
public sealed class InProcessSigningService : ISigningService
{
    private static readonly TimeSpan ClassificationTtl = TimeSpan.FromSeconds(60);

    private readonly ISignerKeyRegistry _keystore;
    private readonly IServiceScopeFactory _scopes;
    private readonly ISignerAuditSink _audit;
    private readonly ISignerKeyPersistence _persistence;
    private readonly ILogger<InProcessSigningService> _logger;
    private readonly IKeyWrappingPassphraseProvider? _keyWrapping;
    private readonly bool _unlocked;
    private readonly string _backend;
    private readonly bool _failClosedOnAuditFailure;
    private readonly ConcurrentDictionary<Guid, CachedOwner> _owners = new();
    private readonly ConcurrentDictionary<Guid, PendingKey> _pending = new();

    /// <summary>
    /// Creates the in-process signer.
    /// </summary>
    /// <param name="keystore">The keys the node holds, as loaded at startup and registered since.</param>
    /// <param name="scopes">Opens a database scope of the signer's own for classification and audit, independent of any caller's unit of work.</param>
    /// <param name="audit">Where decisions are recorded.</param>
    /// <param name="persistence">Where a committed key and its certificate are written durably.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="unlocked">Whether the keystore was decrypted; false in setup mode or after a failed load, when nothing can sign.</param>
    /// <param name="backend"><see cref="SignerHealth.Pkcs11Backend"/> when a PKCS#11 session is open, otherwise <see cref="SignerHealth.SoftwareBackend"/>.</param>
    /// <param name="keyWrapping">The passphrase the node derives non-RSA key wraps from, for unwrapping a stored end-entity key; null when only RSA-wrapped keys can be exported.</param>
    /// <param name="failClosedOnAuditFailure">
    /// Whether an audit row that cannot be written refuses the operation as
    /// <see cref="SigningRefusalReason.AuditUnavailable"/> instead of logging and proceeding.
    /// The signer role runs fail-closed: its audit is the only record of what was signed. In
    /// process the node's own audit still sees the operation, and the stage-1 behaviour stays.
    /// </param>
    public InProcessSigningService(
        ISignerKeyRegistry keystore,
        IServiceScopeFactory scopes,
        ISignerAuditSink audit,
        ISignerKeyPersistence persistence,
        ILogger<InProcessSigningService> logger,
        bool unlocked = true,
        string backend = SignerHealth.SoftwareBackend,
        IKeyWrappingPassphraseProvider? keyWrapping = null,
        bool failClosedOnAuditFailure = false)
    {
        _keystore = keystore ?? throw new ArgumentNullException(nameof(keystore));
        _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _persistence = persistence ?? throw new ArgumentNullException(nameof(persistence));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _unlocked = unlocked;
        _backend = backend;
        _keyWrapping = keyWrapping;
        _failClosedOnAuditFailure = failClosedOnAuditFailure;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The key and the context are judged first (<see cref="JudgeSign"/>, <see cref="JudgePending"/>),
    /// then the bytes: <see cref="JudgeData"/> parses them as the structure the purpose and
    /// the key sign and refuses anything else, so the purpose label constrains what is signed.
    /// A key in <see cref="KeyRef.SshKeystore"/> signs nothing here.
    /// </remarks>
    public async Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(context);

        var dataHash = SHA256.HashData(data);
        Resolution resolved;
        if (string.Equals(key.Keystore, KeyRef.SshKeystore, StringComparison.OrdinalIgnoreCase))
            resolved = new Resolution(null, null, null, new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"The key {key} is an SSH CA key; SSH certificates are built and signed by the signer from their fields, never from bytes offered for a raw signature."));
        else
            resolved = await ResolveAsync(key, context, JudgeSign, JudgePending, cancellationToken);
        var refusal = resolved.Refusal ?? JudgeData(resolved, key, algorithm, data, context);
        if (refusal != null)
        {
            await RecordAsync("Sign", context, key, algorithm, allowed: false, refusal.Message, dataHash, cancellationToken);
            throw refusal;
        }

        var signature = resolved.Handle!.Sign(data, algorithm.Name);
        await RecordAsync("Sign", context, key, algorithm, allowed: true, reason: null, dataHash, cancellationToken);
        return signature;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Only a CA key decrypts, and only under <see cref="SigningPurpose.Scep"/> for its own CA:
    /// SCEP clients encrypt the request to the CA (RA) certificate and nothing else in the node
    /// receives an envelope. The envelope is opened here with the key; a PKCS#11 key cannot
    /// open one and is refused as <see cref="SigningRefusalReason.OperationUnsupported"/>, as
    /// the node reported before the signer existed. The audit row carries the hash of the
    /// enveloped bytes.
    /// </remarks>
    public async Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(enveloped);
        ArgumentNullException.ThrowIfNull(context);

        var dataHash = SHA256.HashData(enveloped);
        var (handle, _, _, refusal) = await ResolveAsync(key, context, JudgeDecrypt, RefusePendingDecrypt, cancellationToken);
        if (refusal == null && handle is not SoftwarePrivateKeyHandle)
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The key {key} is held by a backend that cannot decrypt; SCEP needs a software CA key.");
        if (refusal != null)
        {
            await RecordAsync("Decrypt", context, key, null, allowed: false, refusal.Message, dataHash, cancellationToken);
            throw refusal;
        }

        await RecordAsync("Decrypt", context, key, null, allowed: true, reason: null, dataHash, cancellationToken);
        return OpenEnvelope(((SoftwarePrivateKeyHandle)handle!).PrivateKey, enveloped);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Generates a software key and holds it pending under a reference minted here. Nothing is
    /// written to disk until <see cref="CommitKeyAsync"/>. On-device generation is refused: no
    /// path in the node generates a CA key on a PKCS#11 token today, so a labelled key spec has
    /// nothing to be honoured by. The audit row carries the hash of the public key, which the
    /// commit row repeats, so the two can be paired.
    /// </remarks>
    public async Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(context);

        var refusal = JudgeKeyManagement(context);
        if (refusal == null && spec.Label != null)
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                "The signer generates software keys only; a labelled key would be an on-device (PKCS#11) key, which nothing generates yet.");
        refusal ??= await JudgeCeremonyAsync(context, cancellationToken);
        if (refusal != null)
        {
            await RecordAsync("GenerateKey", context, null, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        AsymmetricCipherKeyPair keyPair;
        try
        {
            keyPair = KeyAlgorithmPolicy.GenerateKeyPair(spec.Algorithm, spec.SizeOrCurve);
        }
        catch (ArgumentException ex)
        {
            var notAllowed = new SigningRefusedException(SigningRefusalReason.OperationUnsupported, ex.Message);
            await RecordAsync("GenerateKey", context, null, null, allowed: false, notAllowed.Message, null, cancellationToken);
            throw notAllowed;
        }

        // Recorded before the key becomes reachable: a signer that fails closed on its audit
        // then holds nothing a caller could name.
        var pending = PendingKey.From(keyPair, context);
        await RecordAsync("GenerateKey", context, pending.Ref, null, allowed: true, reason: null, SHA256.HashData(pending.PublicKeyDer), cancellationToken);
        _pending[pending.Ref.CertificateId] = pending;
        return new GeneratedKey(pending.Ref, pending.PublicKeyDer);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Accepts PKCS#8 DER (<see cref="KeyMaterial.Pkcs8"/>) for a certificate row that already
    /// exists and carries the key's public half, which is what a restore or a migration has. The
    /// import is held to the scope of the CA that owns that certificate: a context stating another
    /// scope is <see cref="SigningRefusalReason.TenantMismatch"/>, and that scope's ceremony policy
    /// applies. The pair is persisted and registered at once, so the key serves the policy for its
    /// kind from this call on; the wrapped bytes are zeroed once parsed.
    /// </remarks>
    public async Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(context);

        if (string.Equals(material.Format, KeyMaterial.KeystoreFile, StringComparison.OrdinalIgnoreCase))
            return await ImportKeystoreFileAsync(material, context, cancellationToken);

        var key = new KeyRef(material.CertificateId);
        var refusal = JudgeKeyManagement(context);
        if (refusal == null && context.Purpose == SigningPurpose.Infrastructure)
            refusal = new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted, "Infrastructure keys are generated by the signer, never imported.");
        if (refusal == null && !string.Equals(material.Format, KeyMaterial.Pkcs8, StringComparison.OrdinalIgnoreCase))
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"Key material in format '{material.Format}' cannot be imported; the signer accepts '{KeyMaterial.Pkcs8}'.");
        refusal ??= await JudgeCeremonyAsync(context, cancellationToken, material.CertificateId);

        AsymmetricKeyParameter? privateKey = null;
        if (refusal == null)
        {
            try
            {
                privateKey = PrivateKeyFactory.CreateKey(material.Wrapped);
            }
            catch (Exception ex)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported, $"The key material could not be parsed: {ex.Message}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material.Wrapped);
            }
        }

        X509Certificate? certificate = null;
        if (refusal == null)
        {
            var publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(KeystoreService.GetPublicFromPrivate(privateKey!)).GetDerEncoded();
            (certificate, refusal) = await MatchCertificateAsync(key, material.CertificateId, publicKeyDer, cancellationToken);
            if (refusal == null && _keystore.GetPrivateKeyFor(certificate!) != null)
                refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                    $"The signer already holds a key for {key}; it is not imported twice.");
        }

        if (refusal != null)
        {
            await RecordAsync("ImportKey", context, key, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        var handle = new SoftwarePrivateKeyHandle(privateKey!);
        var publicHash = SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(certificate!.GetPublicKey()).GetDerEncoded());
        await RecordAsync("ImportKey", context, key, null, allowed: true, reason: null, publicHash, cancellationToken);
        Persist(handle, certificate, key);
        return key;
    }

    /// <inheritdoc />
    /// <remarks>
    /// A key generated for a CA is committed only to a certificate that CA owns, and a key
    /// managed under an infrastructure context only to the OCSP responder, TSA or CMP signer
    /// certificate of the CA and scope the context names (<see cref="JudgeCommitOwnerAsync"/>).
    /// </remarks>
    public async Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(context);

        var committed = new KeyRef(certificateId, key.Keystore);
        var refusal = JudgeKeyManagement(context) ?? await JudgeCeremonyAsync(context, cancellationToken, certificateId);
        PendingKey? pending = null;
        if (refusal == null && !_pending.TryGetValue(key.CertificateId, out pending))
            refusal = new SigningRefusedException(SigningRefusalReason.UnknownKey, $"No generated key awaits commit under {key}.");
        if (refusal == null)
            refusal = HoldPendingToContext(pending!, context, key);

        X509Certificate? certificate = null;
        if (refusal == null)
            (certificate, refusal) = await MatchCertificateAsync(committed, certificateId, pending!.PublicKeyDer, cancellationToken);
        // An infrastructure key is a CA's delegated signer. It is never committed to a CA
        // certificate: that would make a key generated without a ceremony into a CA key.
        if (refusal == null && context.Purpose == SigningPurpose.Infrastructure && certificate!.GetBasicConstraints() != -1)
            refusal = new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"Certificate {certificateId} is a CA certificate; a key generated under an infrastructure context cannot become a CA key.");
        if (refusal == null)
            refusal = await JudgeCommitOwnerAsync(pending!, certificateId, context, committed, cancellationToken);

        if (refusal != null)
        {
            await RecordAsync("CommitKey", context, committed, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        await RecordAsync("CommitKey", context, committed, null, allowed: true, reason: null, SHA256.HashData(pending!.PublicKeyDer), cancellationToken);
        Persist(pending.Handle, certificate!, committed);
        _pending.TryRemove(key.CertificateId, out _);
    }

    /// <inheritdoc />
    /// <remarks>
    /// A key leaves as PKCS#12 only under <see cref="SigningPurpose.Export"/>, and only an
    /// end-entity key, to its holder: the key the node wrapped at request time and stored on the
    /// certificate row, before re-download ended, is unwrapped here with the CA key that wrapped
    /// it and re-wrapped as PKCS#12 under the holder's password, beside the chain the caller
    /// supplies. Under <see cref="SigningPurpose.Backup"/> only whole keystore files leave, in
    /// the keystore-file wrap; a PKCS#12 request under Backup is refused whatever the key, so no
    /// CA or infrastructure key is ever re-wrapped under a password the caller chooses. The
    /// context must name its caller, since the export right is a person's, and a PKCS#11 key
    /// never leaves its token. A certificate
    /// with no stored key is refused as <see cref="SigningRefusalReason.UnknownKey"/>, and the
    /// reason says why: since re-download ended, a key the CA generates is delivered once, with
    /// the request that carries it, and is not kept. The audit row carries the hash of the
    /// wrapped bytes that left.
    /// </remarks>
    public async Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(wrap);
        ArgumentNullException.ThrowIfNull(context);

        if (key.IsKeystoreFile || string.Equals(wrap.Format, ExportWrap.KeystoreFile, StringComparison.OrdinalIgnoreCase))
            return await ExportKeystoreFileAsync(key, wrap, context, cancellationToken);

        var refusal = JudgeExportContext(context, wrap);
        CachedOwner? owner = null;
        if (refusal == null)
        {
            owner = await ClassifyAsync(key.CertificateId, cancellationToken);
            if (owner == null)
                refusal = new SigningRefusedException(SigningRefusalReason.UnknownKey, $"No certificate {key} is known to the signer.");
        }
        if (refusal == null)
            refusal = JudgeExport(owner!, context, key);

        AsymmetricKeyParameter? privateKey = null;
        if (refusal == null)
        {
            (privateKey, refusal) = owner!.Kind == KeyKind.EndEntity
                ? await UnwrapStoredEndEntityKeyAsync(owner, key, cancellationToken)
                : HeldSoftwareKey(owner, key);
        }

        if (refusal != null)
        {
            await RecordAsync("ExportKey", context, key, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        var wrapped = WrapAsPkcs12(privateKey!, owner!.Certificate, wrap);
        await RecordAsync("ExportKey", context, key, null, allowed: true, reason: null, SHA256.HashData(wrapped), cancellationToken);
        return wrapped;
    }

    /// <inheritdoc />
    /// <remarks>
    /// A pending key is discarded: it was never written anywhere, so retiring it is the whole
    /// undo of a ceremony that failed after generating it. A committed key cannot be retired in
    /// this stage; revoking its certificate is what takes it out of service.
    /// </remarks>
    public async Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(context);

        var refusal = JudgeKeyManagement(context);
        PendingKey? pending = null;
        if (refusal == null && !_pending.TryGetValue(key.CertificateId, out pending))
        {
            var owner = await ClassifyAsync(key.CertificateId, cancellationToken);
            refusal = owner != null && _keystore.GetPrivateKeyFor(owner.Certificate) != null
                ? new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                    $"The key {key} is committed to its certificate and cannot be retired; revoke the certificate instead.")
                : new SigningRefusedException(SigningRefusalReason.UnknownKey, $"No generated key awaits commit under {key}.");
        }
        if (refusal == null)
            refusal = HoldPendingToContext(pending!, context, key);

        if (refusal != null)
        {
            await RecordAsync("RetireKey", context, key, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        _pending.TryRemove(key.CertificateId, out _);
        await RecordAsync("RetireKey", context, key, null, allowed: true, reason: null, SHA256.HashData(pending!.PublicKeyDer), cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The wrapping key is derived, per blob, from the keystore key this signer designates
    /// (<see cref="ResolveWrappingKey"/>): HKDF-SHA256 over its PKCS#8 encoding with a fresh
    /// salt, and AES-256-GCM under the result with the blob's header as associated data. The
    /// derived key exists only where that private key exists, which is the keystore, which is
    /// behind the signer; a node in remote mode cannot reproduce it. The blob names the key it
    /// was derived from, so the designation can change without re-wrapping anything.
    /// </remarks>
    public async Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(context);

        var refusal = JudgeSecretWrap(context, kind, wrapping: true);
        byte[]? keyId = null;
        byte[]? material = null;
        byte[]? blob = null;
        if (refusal == null)
            (keyId, material, refusal) = ResolveWrappingKey(null);
        if (refusal == null)
        {
            try
            {
                blob = Seal(kind, keyId!, material!, secret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material!);
            }
        }

        if (refusal != null)
        {
            await RecordSecretAsync("WrapSecret", context, kind, keyId, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        await RecordSecretAsync("WrapSecret", context, kind, keyId, allowed: true, reason: null, SHA256.HashData(blob!), cancellationToken);
        return blob!;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Everything the unwrap needs comes out of the blob and nothing out of the caller: the kind
    /// the policy is applied to, and the id of the key to derive from. A caller permitted one
    /// kind therefore cannot reach another by asking differently, and because the kind is in the
    /// associated data, a blob relabelled on its way here does not authenticate at all.
    /// </remarks>
    public async Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrapped);
        ArgumentNullException.ThrowIfNull(context);

        var dataHash = SHA256.HashData(wrapped);
        if (!WrappedSecretEnvelope.TryRead(wrapped, out var header))
        {
            var malformed = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                "The bytes offered are not a wrapped secret this signer recognises.");
            await RecordSecretAsync("UnwrapSecret", context, null, null, allowed: false, malformed.Message, dataHash, cancellationToken);
            throw malformed;
        }

        var refusal = JudgeSecretWrap(context, header.Kind, wrapping: false);
        byte[]? material = null;
        byte[]? secret = null;
        if (refusal == null)
            (_, material, refusal) = ResolveWrappingKey(header.KeyId);
        if (refusal == null)
        {
            try
            {
                secret = Open(header, material!);
            }
            catch (CryptographicException)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.IntegrityFailure,
                    $"The wrapped {header.Kind} does not authenticate under the key {WrappedSecretEnvelope.KeyIdText(header.KeyId)} its header names.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material!);
            }
        }

        if (refusal != null)
        {
            await RecordSecretAsync("UnwrapSecret", context, header.Kind, header.KeyId, allowed: false, refusal.Message, dataHash, cancellationToken);
            throw refusal;
        }

        await RecordSecretAsync("UnwrapSecret", context, header.Kind, header.KeyId, allowed: true, reason: null, dataHash, cancellationToken);
        return secret!;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!_unlocked)
            return Array.Empty<KeyInfo>();

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

        IQueryable<CertificateAuthorityEntity> cas = db.CertificateAuthorities.AsNoTracking();
        if (context.CaId is Guid caId)
            cas = cas.Where(ca => ca.Id == caId);

        var owners = new Dictionary<Guid, KeyOwner>();
        foreach (var ca in await cas.ToListAsync(cancellationToken))
        {
            if (ca.CertificateId is Guid c) owners[c] = new KeyOwner(KeyKind.Ca, ca.Id, ca.SpaceId);
            if (ca.OcspResponderCertificateId is Guid o) owners[o] = new KeyOwner(KeyKind.OcspResponder, ca.Id, ca.SpaceId);
            if (ca.TsaCertificateId is Guid t) owners[t] = new KeyOwner(KeyKind.Tsa, ca.Id, ca.SpaceId);
            if (ca.CmpSigningCertificateId is Guid m) owners[m] = new KeyOwner(KeyKind.CmpSigner, ca.Id, ca.SpaceId);
        }
        if (owners.Count == 0)
            return Array.Empty<KeyInfo>();

        var ids = owners.Keys.ToList();
        var rows = await db.Certificates.AsNoTracking()
            .Where(c => ids.Contains(c.CertificateId))
            .ToListAsync(cancellationToken);

        var keys = new List<KeyInfo>();
        foreach (var row in rows)
        {
            var cert = TryParse(row);
            if (cert == null) continue;
            var handle = _keystore.GetPrivateKeyFor(cert);
            if (handle == null) continue;
            var owner = owners[row.CertificateId];
            keys.Add(new KeyInfo(
                new KeyRef(row.CertificateId),
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(cert.GetPublicKey()).GetDerEncoded(),
                owner.Kind, owner.CaId, owner.SpaceId,
                handle is Pkcs11PrivateKeyHandle ? SignerHealth.Pkcs11Backend : SignerHealth.SoftwareBackend));
        }
        return keys;
    }

    /// <inheritdoc />
    public Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default)
    {
        var count = _unlocked ? _keystore.GetSigners().Count : 0;
        return Task.FromResult(new SignerHealth(_unlocked, count, _backend));
    }

    /// <summary>
    /// Opens a CMS EnvelopedData with the key: every recipient the envelope names is tried,
    /// since the client may address it to more than one certificate, and the first that opens
    /// is the content. Throws <see cref="CmsException"/> when none does.
    /// </summary>
    private static byte[] OpenEnvelope(AsymmetricKeyParameter privateKey, byte[] enveloped)
    {
        var envelopedData = new CmsEnvelopedData(enveloped);
        Exception? last = null;
        foreach (RecipientInformation recipient in envelopedData.GetRecipientInfos().GetRecipients())
        {
            try
            {
                var content = recipient.GetContent(privateKey);
                if (content != null)
                    return content;
            }
            catch (Exception ex)
            {
                last = ex;
            }
        }
        throw new CmsException("No recipient of the envelope could be opened with the key.", last);
    }

    /// <summary>
    /// A resolved key: the handle to use and what the key is, a committed key's classification
    /// or a pending key, or the refusal to record and throw. A refusal carries no handle.
    /// </summary>
    private sealed record Resolution(IPrivateKeyHandle? Handle, CachedOwner? Owner, PendingKey? Pending, SigningRefusedException? Refusal);

    /// <summary>
    /// Resolves the key and judges the context: a pending key with <paramref name="judgePending"/>,
    /// a key the keystore holds with <paramref name="judge"/> over its classification. Returns
    /// the handle to use with the key's classification or pending entry, or the refusal to
    /// record and throw; never both.
    /// </summary>
    private async Task<Resolution> ResolveAsync(
        KeyRef key, SigningContext context,
        Func<CachedOwner, SigningContext, KeyRef, SigningRefusedException?> judge,
        Func<PendingKey, SigningContext, KeyRef, SigningRefusedException?> judgePending,
        CancellationToken cancellationToken)
    {
        if (!_unlocked)
            return new Resolution(null, null, null, new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore."));

        if (_pending.TryGetValue(key.CertificateId, out var pending))
        {
            var pendingRefusal = judgePending(pending, context, key);
            return pendingRefusal != null ? new Resolution(null, null, null, pendingRefusal) : new Resolution(pending.Handle, null, pending, null);
        }

        var owner = await ClassifyAsync(key.CertificateId, cancellationToken);
        if (owner == null)
            return new Resolution(null, null, null, new SigningRefusedException(SigningRefusalReason.UnknownKey, $"No certificate {key} is known to the signer."));

        var handle = _keystore.GetPrivateKeyFor(owner.Certificate);
        if (handle == null)
            return new Resolution(null, null, null, new SigningRefusedException(SigningRefusalReason.UnknownKey, $"The signer holds no private key for {key}."));

        var refusal = judge(owner, context, key);
        return refusal != null ? new Resolution(null, null, null, refusal) : new Resolution(handle, owner, null, null);
    }

    /// <summary>
    /// The signing policy table. A key of a given kind signs for the purposes listed for it, and
    /// only for the CA that owns it; a caller that names a space must name the owning CA's space.
    /// An SSH CA key signs for no purpose. What the bytes may be is judged after this, by
    /// <see cref="JudgeData"/>.
    /// </summary>
    private static SigningRefusedException? JudgeSign(CachedOwner owner, SigningContext context, KeyRef key)
    {
        if (owner.Kind == KeyKind.SshCa)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"The SSH CA key {key} signs no raw bytes, for any purpose; SSH certificates are signed only from their fields.");

        var permitted = owner.Kind switch
        {
            KeyKind.Ca => context.Purpose is SigningPurpose.Certificate or SigningPurpose.Crl or SigningPurpose.Ocsp
                                             or SigningPurpose.Scep or SigningPurpose.Cmp,
            KeyKind.OcspResponder => context.Purpose is SigningPurpose.Ocsp,
            KeyKind.Tsa => context.Purpose is SigningPurpose.Tsa,
            KeyKind.CmpSigner => context.Purpose is SigningPurpose.Cmp,
            _ => false,
        };

        if (owner.Kind == KeyKind.Unknown)
            return new SigningRefusedException(SigningRefusalReason.UnknownKeyKind,
                $"Nothing records what kind of key {key} is; it signs nothing.");
        if (!permitted)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"A {owner.Kind} key does not sign for purpose {context.Purpose}.");
        return HoldToOwner(owner, context, key);
    }

    /// <summary>
    /// The decryption policy: a CA key opens SCEP envelopes for its own CA, and no other key
    /// opens anything for any purpose.
    /// </summary>
    private static SigningRefusedException? JudgeDecrypt(CachedOwner owner, SigningContext context, KeyRef key)
    {
        if (owner.Kind == KeyKind.Unknown)
            return new SigningRefusedException(SigningRefusalReason.UnknownKeyKind,
                $"Nothing records what kind of key {key} is; it decrypts nothing.");
        if (owner.Kind != KeyKind.Ca || context.Purpose != SigningPurpose.Scep)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"A {owner.Kind} key does not decrypt for purpose {context.Purpose}; only a CA key opens SCEP envelopes.");
        return HoldToOwner(owner, context, key);
    }

    /// <summary>
    /// The policy for a key that has no certificate yet: it signs only under the purpose it was
    /// generated under, ceremony or infrastructure, and only for the space and CA (when either was
    /// named) that generated it. It has no kind, so nothing else applies.
    /// </summary>
    private static SigningRefusedException? JudgePending(PendingKey pending, SigningContext context, KeyRef key)
    {
        if (context.Purpose != pending.Purpose)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"The generated key {key} signs only under the {pending.Purpose} context that generated it, not {context.Purpose}.");
        return HoldPendingToContext(pending, context, key);
    }

    /// <summary>A pending key decrypts nothing: no client has its certificate to encrypt to.</summary>
    private static SigningRefusedException? RefusePendingDecrypt(PendingKey pending, SigningContext context, KeyRef key)
        => new(SigningRefusalReason.PurposeNotPermitted, $"The generated key {key} has no certificate yet and decrypts nothing.");

    /// <summary>
    /// Typed signing: the bytes must parse as the one structure this key signs for this purpose.
    /// A CA key signs a v3 TBSCertificate under Certificate (<see cref="JudgeCertificate"/>),
    /// a TBSCertList under Crl, an OCSP ResponseData under Ocsp, SCEP signed attributes under
    /// Scep and a CMP ProtectedPart under Cmp; a responder key signs ResponseData, a TSA key
    /// timestamp-token signed attributes, a CMP signer key a ProtectedPart. A pending key is
    /// judged by <see cref="JudgePendingData"/>. Anything else is refused before the key is used.
    /// </summary>
    private SigningRefusedException? JudgeData(Resolution resolved, KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context)
    {
        if (resolved.Pending is PendingKey pending)
            return JudgePendingData(pending, key, algorithm, data);

        var owner = resolved.Owner!;
        return (owner.Kind, context.Purpose) switch
        {
            (KeyKind.Ca, SigningPurpose.Certificate) => JudgeCertificate(owner, algorithm, data),
            (KeyKind.Ca, SigningPurpose.Crl) => JudgeCrl(owner, algorithm, data),
            (KeyKind.Ca or KeyKind.OcspResponder, SigningPurpose.Ocsp) => JudgeOcspResponse(owner, data),
            (KeyKind.Ca, SigningPurpose.Scep) => SignedDataTypes.SignedAttributes(data, SignedDataTypes.IdData, SignedDataTypes.ScepMessageType) != null
                ? null
                : Untyped(context.Purpose, "the signed attributes of a SCEP pkiMessage: a DER SET carrying content type id-data, a message digest and a SCEP messageType"),
            (KeyKind.Ca or KeyKind.CmpSigner, SigningPurpose.Cmp) => JudgeCmp(algorithm, data),
            (KeyKind.Tsa, SigningPurpose.Tsa) => SignedDataTypes.SignedAttributes(data, SignedDataTypes.IdCtTstInfo, null) != null
                ? null
                : Untyped(context.Purpose, "the signed attributes of a timestamp token: a DER SET carrying content type id-ct-TSTInfo and a message digest"),
            _ => new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted, $"A {owner.Kind} key signs no {context.Purpose} structure."),
        };
    }

    /// <summary>The refusal for bytes that are not the structure <paramref name="purpose"/> signs.</summary>
    private static SigningRefusedException Untyped(SigningPurpose purpose, string expected)
        => new(SigningRefusalReason.UntypedData, $"Under {purpose} the signer signs {expected}; the bytes offered are not that.");

    /// <summary>
    /// What every certificate the signer signs must be, whoever signs it: v3, signed with the
    /// algorithm the request names, and no CA-only extension unless it asserts <c>cA=TRUE</c>
    /// (a path length, keyCertSign or cRLSign, name constraints). A CA certificate carries no
    /// OCSP-signing EKU. Returns the shape for the issuer-specific rules.
    /// </summary>
    private static SigningRefusedException? JudgeCertificateShape(TbsCertificateStructure tbs, SignatureAlgorithm algorithm, out SignedDataTypes.CertificateShape? shape)
    {
        shape = null;
        if (tbs.VersionNumber == null || !tbs.VersionNumber.HasValue(2))
            return new SigningRefusedException(SigningRefusalReason.UntypedData,
                "The signer signs v3 certificates only; some verifiers treat a v1 or v2 certificate as a CA.");
        if (!SignedDataTypes.SameAlgorithm(tbs.Signature, algorithm))
            return new SigningRefusedException(SigningRefusalReason.AlgorithmMismatch,
                $"The certificate names signature algorithm {tbs.Signature?.Algorithm.Id}, not the {algorithm} the request signs with.");
        try
        {
            shape = SignedDataTypes.Shape(tbs);
        }
        catch (Exception)
        {
            return Untyped(SigningPurpose.Certificate, "a TBSCertificate whose basic constraints, key usage and extended key usage parse");
        }
        if (!shape.IsCa && shape.PathLength != null)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                "The certificate carries a path length constraint without cA=TRUE.");
        if (!shape.IsCa && shape.CaKeyUsages)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                "The certificate asserts keyCertSign or cRLSign without cA=TRUE; only a CA certificate signs certificates or CRLs.");
        if (!shape.IsCa && shape.NameConstraints)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                "The certificate carries name constraints without cA=TRUE.");
        if (shape.IsCa && shape.OcspSigning)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                "A CA certificate does not carry the OCSP-signing EKU.");
        return null;
    }

    /// <summary>
    /// A CA key's certificate. The issuer must be the CA's own subject. A <c>cA=TRUE</c>
    /// certificate is held to the CA's path length, and is signed only for a key this signer
    /// generated under a ceremony context for a new CA and holds pending, not yet certified as
    /// a CA (which the signature then records). An OCSP-signing certificate is signed only for a
    /// delegated key this signer generated for this CA and holds pending. Either for any other
    /// key is <see cref="SigningRefusalReason.EvidenceRequired"/>: a ceremony row is not
    /// evidence here, since the node writes it, and evidence the signer can verify for an
    /// outside key (cross-certification, an external responder) arrives with verified
    /// approvals. Every other certificate is a leaf and is signed as before.
    /// </summary>
    private SigningRefusedException? JudgeCertificate(CachedOwner owner, SignatureAlgorithm algorithm, byte[] data)
    {
        var tbs = SignedDataTypes.TbsCertificate(data);
        if (tbs == null)
            return Untyped(SigningPurpose.Certificate, "a DER TBSCertificate");
        var refusal = JudgeCertificateShape(tbs, algorithm, out var shape);
        if (refusal != null)
            return refusal;
        if (!tbs.Issuer.Equivalent(owner.Certificate.SubjectDN, true))
            return new SigningRefusedException(SigningRefusalReason.IssuerMismatch,
                $"The certificate names issuer '{tbs.Issuer}', not '{owner.Certificate.SubjectDN}', the CA whose key would sign it.");

        if (shape!.IsCa)
        {
            var issuerPathLength = owner.Certificate.GetBasicConstraints();
            if (issuerPathLength >= 0 && issuerPathLength != int.MaxValue
                && (issuerPathLength == 0 || shape.PathLength == null || shape.PathLength.IntValue >= issuerPathLength))
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"CA {owner.CaId} has a path length of {issuerPathLength}; a CA certificate it signs must carry a path length below it.");

            var subject = FindPending(shape.SubjectPublicKeyInfo);
            if (subject is not { MayBecomeCa: true })
                return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                    "A cA=TRUE certificate is signed only for a key this signer generated under a ceremony for a new CA and still holds uncommitted; the subject key of this certificate is not one.");
            return subject.TryCertify(tbs.Subject)
                ? null
                : new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                    $"The generated key {subject.Ref} is already certified as a CA; a key is certified as a CA once.");
        }

        if (shape.OcspSigning)
        {
            var subject = FindPending(shape.SubjectPublicKeyInfo);
            if (subject is not { MayBecomeCa: false } || subject.CaId != owner.CaId)
                return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                    $"An OCSP-signing certificate is signed only for a delegated key this signer generated for CA {owner.CaId} and still holds uncommitted; the subject key of this certificate is not one.");
        }
        return null;
    }

    /// <summary>A CA key's CRL: a TBSCertList, signed with the algorithm requested, naming the CA as its issuer.</summary>
    private static SigningRefusedException? JudgeCrl(CachedOwner owner, SignatureAlgorithm algorithm, byte[] data)
    {
        var tbs = SignedDataTypes.TbsCertList(data);
        if (tbs == null)
            return Untyped(SigningPurpose.Crl, "a DER TBSCertList");
        if (!SignedDataTypes.SameAlgorithm(tbs.Signature, algorithm))
            return new SigningRefusedException(SigningRefusalReason.AlgorithmMismatch,
                $"The CRL names signature algorithm {tbs.Signature?.Algorithm.Id}, not the {algorithm} the request signs with.");
        if (!tbs.Issuer.Equivalent(owner.Certificate.SubjectDN, true))
            return new SigningRefusedException(SigningRefusalReason.IssuerMismatch,
                $"The CRL names issuer '{tbs.Issuer}', not '{owner.Certificate.SubjectDN}', the CA whose key would sign it.");
        return null;
    }

    /// <summary>
    /// An OCSP response from a CA key or its delegated responder: a ResponseData whose responder
    /// id is the signing key's own certificate, by name or by key hash.
    /// </summary>
    private static SigningRefusedException? JudgeOcspResponse(CachedOwner owner, byte[] data)
    {
        var response = SignedDataTypes.OcspResponseData(data);
        if (response == null)
            return Untyped(SigningPurpose.Ocsp, "a DER OCSP ResponseData");
        var responder = response.ResponderID;
        bool matches;
        if (responder.Name is X509Name name)
            matches = name.Equivalent(owner.Certificate.SubjectDN, true);
        else
            matches = responder.GetKeyHash() is byte[] hash
                && hash.AsSpan().SequenceEqual(SignedDataTypes.ResponderKeyHash(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(owner.Certificate.GetPublicKey())));
        return matches
            ? null
            : new SigningRefusedException(SigningRefusalReason.IssuerMismatch,
                $"The OCSP response names a responder other than '{owner.Certificate.SubjectDN}', whose key would sign it.");
    }

    /// <summary>A CMP protection signature: a ProtectedPart whose header names the algorithm requested.</summary>
    private static SigningRefusedException? JudgeCmp(SignatureAlgorithm algorithm, byte[] data)
    {
        var part = SignedDataTypes.CmpProtectedPart(data);
        if (part == null)
            return Untyped(SigningPurpose.Cmp, "a DER CMP ProtectedPart (PKIHeader and PKIBody)");
        if (!SignedDataTypes.SameAlgorithm(part.Header.ProtectionAlg, algorithm))
            return new SigningRefusedException(SigningRefusalReason.AlgorithmMismatch,
                $"The CMP header names protection algorithm {part.Header.ProtectionAlg?.Algorithm.Id}, not the {algorithm} the request signs with.");
        return null;
    }

    /// <summary>
    /// What a pending key signs, under the context that generated it. Any pending key signs a
    /// certification request for its own public key. A key that may become a CA also signs its
    /// own self-signed <c>cA=TRUE</c> certificate, once, which records it as certified; once
    /// certified, by itself or a parent, it signs the non-CA certificates of the keys the signer
    /// generated under the same ceremony and scope, with its certified subject as the issuer.
    /// Nothing else.
    /// </summary>
    private SigningRefusedException? JudgePendingData(PendingKey pending, KeyRef key, SignatureAlgorithm algorithm, byte[] data)
    {
        if (SignedDataTypes.CertificationRequestInfo(data) is { } request)
        {
            return SignedDataTypes.Spki(request.SubjectPublicKeyInfo).AsSpan().SequenceEqual(pending.PublicKeyDer)
                ? null
                : new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"The generated key {key} signs a certification request for its own public key only.");
        }

        var tbs = SignedDataTypes.TbsCertificate(data);
        if (tbs == null)
            return Untyped(pending.Purpose, "a certification request for the generated key, or a certificate of the CA it is being created for");
        var refusal = JudgeCertificateShape(tbs, algorithm, out var shape);
        if (refusal != null)
            return refusal;

        if (shape!.SubjectPublicKeyInfo.AsSpan().SequenceEqual(pending.PublicKeyDer))
        {
            if (!pending.MayBecomeCa)
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"The generated key {key} is a delegated key; it does not certify itself.");
            if (!shape.IsCa)
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"The generated key {key} self-signs only its own CA certificate.");
            if (!tbs.Issuer.Equivalent(tbs.Subject, true))
                return new SigningRefusedException(SigningRefusalReason.IssuerMismatch,
                    "A self-signed certificate names its subject as its issuer.");
            return pending.TryCertify(tbs.Subject)
                ? null
                : new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                    $"The generated key {key} is already certified as a CA; a key is certified as a CA once.");
        }

        if (!pending.MayBecomeCa || pending.CertifiedSubject is not X509Name certified)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"The generated key {key} signs another key's certificate only once it is itself certified as a CA.");
        if (!tbs.Issuer.Equivalent(certified, true))
            return new SigningRefusedException(SigningRefusalReason.IssuerMismatch,
                $"The certificate names issuer '{tbs.Issuer}', not '{certified}', the CA the generated key {key} was certified as.");
        if (shape.IsCa)
            return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                "A CA that is not yet committed certifies no other CA.");
        var subject = FindPending(shape.SubjectPublicKeyInfo);
        if (subject == null || subject.Purpose != SigningPurpose.Ceremony || subject.MayBecomeCa
            || subject.SpaceId != pending.SpaceId || subject.InstanceScope != pending.InstanceScope || subject.CeremonyId != pending.CeremonyId)
            return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                $"A CA being created certifies only the delegated keys the signer generated under the same ceremony and scope; the subject key of this certificate is not one.");
        return null;
    }

    /// <summary>The pending key with this DER SubjectPublicKeyInfo, or null.</summary>
    private PendingKey? FindPending(byte[] spki)
    {
        foreach (var pending in _pending.Values)
            if (pending.PublicKeyDer.AsSpan().SequenceEqual(spki))
                return pending;
        return null;
    }

    /// <summary>
    /// The rule every key-management operation shares: generation, import, commit and retire
    /// happen only under a ceremony or infrastructure context, and never while locked.
    /// <see cref="SigningPurpose.Bootstrap"/> manages no key: it would be held to no ceremony, so
    /// it moves only whole keystore files (<see cref="JudgeKeystoreFile"/>).
    /// </summary>
    private SigningRefusedException? JudgeKeyManagement(SigningContext context)
    {
        if (!_unlocked)
            return new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore.");
        if (context.Purpose is not (SigningPurpose.Ceremony or SigningPurpose.Infrastructure))
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"Keys are generated, imported, committed and retired only under a ceremony or infrastructure context, not {context.Purpose}.");
        return null;
    }

    /// <summary>The ceremony operation types that manage a CA key; no other ceremony licenses a key operation.</summary>
    private static readonly HashSet<string> KeyManagementCeremonies = new(StringComparer.Ordinal) { "CreateRootCA", "CreateIntermediateCA" };

    /// <summary>
    /// Holds a <see cref="SigningPurpose.Ceremony"/> context to a scope, then to the ceremony it
    /// names or to that scope's policy. The scope is the one the context states (a space, or
    /// <see cref="SigningContext.InstanceScope"/>), then the scope of the CA it names, then, with
    /// <paramref name="boundCertificateId"/>, the scope of the CA that owns that certificate; any
    /// two that disagree are <see cref="SigningRefusalReason.TenantMismatch"/>, and the owning CA's
    /// scope is the one whose policy applies. A CA not yet committed (one being created) is
    /// passed over when the context states its scope; a soft-deleted CA is not, and is held to its
    /// scope like any other. A context with no scope from any of these,
    /// or that states a space and the instance at once, is
    /// <see cref="SigningRefusalReason.ContextRequired"/>; a missing space is never the instance.
    /// A named ceremony must exist, be approved and unexpired, manage a key, name exactly this
    /// scope (null equals null), and target no other CA than the context names; anything else is
    /// <see cref="SigningRefusalReason.CeremonyNotApproved"/>. With no ceremony named,
    /// <see cref="JudgeCeremonyRequirementAsync"/> applies the scope's policy. Generation,
    /// import and commit are held to this; retiring a pending key is the undo of a failed
    /// ceremony and is not. An <see cref="SigningPurpose.Infrastructure"/> context is not held to
    /// it: its keys never become CA keys, and <see cref="JudgeCommitOwnerAsync"/> holds their
    /// commit to the CA whose delegated certificate they are bound to.
    /// </summary>
    private async Task<SigningRefusedException?> JudgeCeremonyAsync(SigningContext context, CancellationToken cancellationToken, Guid? boundCertificateId = null)
    {
        if (context.Purpose != SigningPurpose.Ceremony)
            return null;
        if (context.InstanceScope && context.SpaceId != null)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                $"The ceremony context states both the instance and space {context.SpaceId}; it names one scope.");

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

        var stated = context.InstanceScope || context.SpaceId != null;
        var scopeSpace = context.SpaceId;
        if (context.CaId is Guid caId)
        {
            var ca = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
                .Where(c => c.Id == caId)
                .Select(c => new { c.SpaceId })
                .FirstOrDefaultAsync(cancellationToken);
            if (ca == null && !stated)
                return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                    $"The context names CA {caId}, which the signer does not know, so the scope whose ceremony policy applies cannot be resolved.");
            if (ca != null)
            {
                if (stated && ca.SpaceId != scopeSpace)
                    return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                        $"CA {caId} belongs to {DescribeScope(ca.SpaceId)}, not {DescribeScope(scopeSpace)}.");
                (stated, scopeSpace) = (true, ca.SpaceId);
            }
        }
        if (boundCertificateId is Guid certificateId)
        {
            var owner = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
                .Where(c => c.CertificateId == certificateId || c.OcspResponderCertificateId == certificateId
                         || c.TsaCertificateId == certificateId || c.CmpSigningCertificateId == certificateId)
                .Select(c => new { c.Id, c.SpaceId })
                .FirstOrDefaultAsync(cancellationToken);
            if (owner != null)
            {
                if (stated && owner.SpaceId != scopeSpace)
                    return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                        $"Certificate {certificateId} belongs to CA {owner.Id} of {DescribeScope(owner.SpaceId)}, not {DescribeScope(scopeSpace)}; the owning CA's ceremony policy applies.");
                (stated, scopeSpace) = (true, owner.SpaceId);
            }
        }
        if (!stated)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                "Key management under a ceremony context states its scope, a space or the instance, or names the CA it is for; a context naming none cannot be held to a ceremony policy.");

        if (context.CeremonyId is not Guid ceremonyId)
            return await JudgeCeremonyRequirementAsync(db, scopeSpace, cancellationToken);

        var ceremony = await db.KeyCeremonies.AsNoTracking().FirstOrDefaultAsync(c => c.Id == ceremonyId, cancellationToken);
        if (ceremony == null)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"No ceremony {ceremonyId} exists; the signer manages keys under a ceremony it can verify.");
        if (!string.Equals(ceremony.Status, "Approved", StringComparison.Ordinal))
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} is {ceremony.Status}, not Approved.");
        if (ceremony.ExpiresAt <= DateTime.UtcNow)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} expired at {ceremony.ExpiresAt:O}; its approval no longer stands.");
        if (!KeyManagementCeremonies.Contains(ceremony.OperationType))
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} is a {ceremony.OperationType} ceremony, which manages no key.");
        if (ceremony.SpaceId != scopeSpace)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} was approved for {DescribeScope(ceremony.SpaceId)}, not {DescribeScope(scopeSpace)}.");
        if (context.CaId != null && Guid.TryParse(ceremony.TargetEntityId, out var target) && target != Guid.Empty && target != context.CaId)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} targets CA {target}, not CA {context.CaId}.");
        return null;
    }

    /// <summary>"the instance", or "space &lt;id&gt;", for refusal messages.</summary>
    private static string DescribeScope(Guid? spaceId) => spaceId == null ? "the instance" : $"space {spaceId}";

    /// <summary>
    /// Holds a ceremony context that names no ceremony to the policy of the scope
    /// <see cref="JudgeCeremonyAsync"/> resolved, read through <see cref="EffectivePolicyResolver"/>.
    /// A scope whose <c>RequireKeyCeremony</c> is set gets no key without a ceremony, and neither
    /// does a space the signer cannot find, since no waiver can be verified for it; both are
    /// <see cref="SigningRefusalReason.CeremonyRequired"/>.
    /// </summary>
    private static async Task<SigningRefusedException?> JudgeCeremonyRequirementAsync(ModularCADbContext db, Guid? scopeSpace, CancellationToken cancellationToken)
    {
        var policy = await new EffectivePolicyResolver(db).ResolveAsync(scopeSpace, cancellationToken);
        if (!policy.Found)
            return new SigningRefusedException(SigningRefusalReason.CeremonyRequired,
                $"No space {scopeSpace} is known to the signer; a key is managed for it only under a ceremony the signer can verify.");
        if (policy.RequireKeyCeremony)
            return new SigningRefusedException(SigningRefusalReason.CeremonyRequired,
                policy.SpaceId == null
                    ? "The instance requires a key ceremony and the context names none."
                    : $"Space {policy.SpaceId} requires a key ceremony and the context names none.");
        return null;
    }

    /// <summary>
    /// What a purpose may wrap. One row per purpose: a purpose that is not here wraps nothing.
    /// A backup wraps the configuration secrets its archive carries.
    /// </summary>
    private static readonly IReadOnlyDictionary<SigningPurpose, SecretKind> WrapRights =
        new Dictionary<SigningPurpose, SecretKind>
        {
            [SigningPurpose.Cmp] = SecretKind.CmpSharedSecret,
            [SigningPurpose.Certificate] = SecretKind.HeldPrivateKey,
            [SigningPurpose.Backup] = SecretKind.BackupConfigSecret,
        };

    /// <summary>
    /// What a purpose may unwrap, which is deliberately not what it may wrap: the issuance path
    /// that wraps a requester's held key has no right to read one back, and reading one back is
    /// the export right, which is a person's. A backup's configuration secrets are read back
    /// only by a restore, never by the backup that wrapped them.
    /// <see cref="SecretKind.KerberosRealmKey"/> appears in neither table, so nothing wraps or
    /// unwraps it until the caching question the design document raises is answered.
    /// </summary>
    private static readonly IReadOnlyDictionary<SigningPurpose, SecretKind> UnwrapRights =
        new Dictionary<SigningPurpose, SecretKind>
        {
            [SigningPurpose.Cmp] = SecretKind.CmpSharedSecret,
            [SigningPurpose.Export] = SecretKind.HeldPrivateKey,
            [SigningPurpose.Restore] = SecretKind.BackupConfigSecret,
        };

    /// <summary>
    /// The wrap policy: the signer is unlocked, the context names a caller, and the purpose is
    /// one the kind permits for this direction. Nothing is held to a CA or a space, because the
    /// wrapping key belongs to the signer and not to any CA, so there is no owner to hold it to;
    /// the context still names them and the audit still records them.
    /// </summary>
    private SigningRefusedException? JudgeSecretWrap(SigningContext context, SecretKind kind, bool wrapping)
    {
        if (!_unlocked)
            return new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore.");
        if (string.IsNullOrWhiteSpace(context.Caller))
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                "A secret is wrapped and unwrapped for a named caller; a context with no caller gets neither.");

        var rights = wrapping ? WrapRights : UnwrapRights;
        if (!rights.TryGetValue(context.Purpose, out var permitted) || permitted != kind)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"A {context.Purpose} context does not {(wrapping ? "wrap" : "unwrap")} a {kind}.");
        return null;
    }

    /// <summary>
    /// The key a wrapping key is derived from, and the material to derive it with. With
    /// <paramref name="requiredKeyId"/> null this is the key the signer designates for new
    /// wraps: the one whose SPKI is pinned for the default keystore, which is the same key
    /// <see cref="ISignerKeyPersistence"/> re-signs the keystore files with, falling back to the
    /// first signer the registry holds when no pin resolves. With a key id it is that key and no
    /// other, which is what lets an old blob outlive a rotation. The material is the key's PKCS#8
    /// encoding; the caller zeroes it. A key on a PKCS#11 token cannot serve, since the token
    /// does not hand the material out.
    /// </summary>
    private (byte[]? KeyId, byte[]? Material, SigningRefusedException? Refusal) ResolveWrappingKey(byte[]? requiredKeyId)
    {
        var signers = _keystore.GetSigners();
        if (signers.Count == 0)
            return (null, null, new SigningRefusedException(SigningRefusalReason.UnknownKey,
                "The signer holds no key to derive a wrapping key from."));

        CertificateAuthorityIdentity? chosen = null;
        if (requiredKeyId != null)
        {
            foreach (var candidate in signers)
            {
                if (SpkiDigest(candidate.PublicCertificate) is byte[] digest && digest.AsSpan().SequenceEqual(requiredKeyId))
                {
                    chosen = candidate;
                    break;
                }
            }
            if (chosen == null)
                return (null, null, new SigningRefusedException(SigningRefusalReason.UnknownKey,
                    $"The signer holds no key {WrappedSecretEnvelope.KeyIdText(requiredKeyId)}; the secret was wrapped under a key this keystore does not have."));
        }
        else
        {
            string? pinned = null;
            try
            {
                using var scope = _scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
                pinned = KeystoreService.GetPinnedSignerSpki(db, KeyRef.DefaultKeystore);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Signer: the pinned signer for {Keystore} could not be read; the first registered signer wraps.", KeyRef.DefaultKeystore);
            }

            if (pinned != null)
            {
                foreach (var candidate in signers)
                {
                    if (string.Equals(KeystoreService.ComputeSpkiSha256Hex(candidate.PublicCertificate), pinned, StringComparison.OrdinalIgnoreCase))
                    {
                        chosen = candidate;
                        break;
                    }
                }
            }
            chosen ??= signers[0];
        }

        var keyId = SpkiDigest(chosen.PublicCertificate);
        if (keyId == null)
            return (null, null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                "The designated wrapping key's public half cannot be encoded, so it cannot identify a wrapped secret."));

        var handle = _keystore.GetPrivateKeyFor(chosen.PublicCertificate);
        if (handle == null)
            return (keyId, null, new SigningRefusedException(SigningRefusalReason.UnknownKey,
                $"The signer holds no private key for the wrapping key {WrappedSecretEnvelope.KeyIdText(keyId)}."));
        if (handle is not SoftwarePrivateKeyHandle software)
            return (keyId, null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                "The designated wrapping key is held on a PKCS#11 token, which does not hand out the material a derived wrapping key needs."));

        return (keyId, PrivateKeyInfoFactory.CreatePrivateKeyInfo(software.PrivateKey).GetDerEncoded(), null);
    }

    /// <summary>SHA-256 over the DER-encoded SubjectPublicKeyInfo of a certificate, or null when it cannot be encoded.</summary>
    private static byte[]? SpkiDigest(X509Certificate certificate)
    {
        try
        {
            return SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(certificate.GetPublicKey()).GetDerEncoded());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Derives the wrapping key and encrypts: HKDF-SHA256 over the keystore key's PKCS#8
    /// encoding with a fresh 32-byte salt and the kind and key id as info, then AES-256-GCM
    /// under it with the blob's header as associated data. The derived key is zeroed before the
    /// blob is returned.
    /// </summary>
    private static byte[] Seal(SecretKind kind, byte[] keyId, byte[] material, byte[] secret)
    {
        var salt = RandomNumberGenerator.GetBytes(WrappedSecretEnvelope.SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(WrappedSecretEnvelope.NonceLength);
        var aad = WrappedSecretEnvelope.AssociatedData(kind, keyId);
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, material, 32, salt, WrappedSecretEnvelope.DerivationInfo(kind, keyId));
        try
        {
            var ciphertext = new byte[secret.Length];
            var tag = new byte[WrappedSecretEnvelope.TagLength];
            using var gcm = new AesGcm(key, WrappedSecretEnvelope.TagLength);
            gcm.Encrypt(nonce, secret, ciphertext, tag, aad);
            return WrappedSecretEnvelope.Build(kind, keyId, salt, nonce, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Re-derives the wrapping key from the blob's own salt and decrypts it. Throws
    /// <see cref="CryptographicException"/> when the blob does not authenticate, which is every
    /// case where the key, the header or the ciphertext is not the one that was sealed.
    /// </summary>
    private static byte[] Open(WrappedSecretHeader header, byte[] material)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, material, 32, header.Salt,
            WrappedSecretEnvelope.DerivationInfo(header.Kind, header.KeyId));
        try
        {
            var secret = new byte[header.Ciphertext.Length];
            using var gcm = new AesGcm(key, WrappedSecretEnvelope.TagLength);
            gcm.Decrypt(header.Nonce, header.Ciphertext, header.Tag, secret, header.AssociatedData);
            return secret;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Records a wrap or an unwrap. The hash is of the wrapped blob in both directions and never
    /// of the secret, which would make the audit a verification oracle for what it is protecting.
    /// </summary>
    private Task RecordSecretAsync(string operation, SigningContext context, SecretKind? kind, byte[]? keyId,
        bool allowed, string? reason, byte[]? dataHash, CancellationToken cancellationToken)
        => RecordAsync(operation, context, null, null, allowed, reason, dataHash, cancellationToken,
            kind, keyId == null ? null : WrappedSecretEnvelope.KeyIdText(keyId));

    /// <summary>
    /// The backup wrap: the keystore file the reference names, byte for byte as the persistence
    /// keeps it, encrypted under the keystore passphrases and signed by the pinned signer. It
    /// hands out no usable key, so it is allowed while locked; it is allowed under Backup only,
    /// to a named caller, and only for a reference to a whole keystore in the keystore-file
    /// wrap. The audit row names the keystore and carries the hash of the bytes that left.
    /// </summary>
    private async Task<byte[]> ExportKeystoreFileAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken)
    {
        var refusal = JudgeKeystoreFile(context, key, wrap.Format, ExportWrap.KeystoreFile, SigningPurpose.Backup);
        byte[]? bytes = null;
        if (refusal == null)
        {
            try
            {
                bytes = _persistence.ReadKeystoreFile(key.Keystore);
            }
            catch (FileNotFoundException)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.UnknownKey, $"The signer keeps no keystore file named '{key.Keystore}'.");
            }
            catch (ArgumentException ex)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.ContextRequired, ex.Message);
            }
        }
        if (refusal != null)
        {
            await RecordAsync("ExportKey", context, key, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        await RecordAsync("ExportKey", context, key, null, allowed: true, reason: null, SHA256.HashData(bytes!), cancellationToken);
        return bytes!;
    }

    /// <summary>
    /// The restore import: a whole keystore file from a backup replaces the one in place once
    /// its signature verifies against the pinned signer, which the persistence checks before it
    /// moves anything. Allowed under Restore or Bootstrap only, to a named caller, locked or
    /// not: restoring the keystore is how a signer comes to hold keys. A file that does not
    /// verify is refused as <see cref="SigningRefusalReason.IntegrityFailure"/>, audited as such,
    /// and nothing in place has changed. The keys in the restored file are served after the
    /// node restarts and unlocks it; nothing is loaded here.
    /// </summary>
    private async Task<KeyRef> ImportKeystoreFileAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken)
    {
        var key = KeyRef.ForKeystore(material.Keystore);
        var refusal = JudgeKeystoreFile(context, key, material.Format, KeyMaterial.KeystoreFile, SigningPurpose.Restore, SigningPurpose.Bootstrap);
        if (refusal == null && material.CertificateId != Guid.Empty)
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                "A keystore file is imported whole; it names a keystore, not a certificate.");
        var dataHash = SHA256.HashData(material.Wrapped);
        if (refusal == null)
        {
            try
            {
                _persistence.ImportKeystoreFile(material.Keystore, material.Wrapped);
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or CryptographicException or InvalidDataException)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.IntegrityFailure,
                    $"The keystore file '{material.Keystore}' offered for restore did not verify against the pinned signer: {ex.Message}");
            }
            catch (ArgumentException ex)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.ContextRequired, ex.Message);
            }
        }
        if (refusal != null)
        {
            await RecordAsync("ImportKey", context, key, null, allowed: false, refusal.Message, dataHash, cancellationToken);
            throw refusal;
        }

        _owners.Clear();
        await RecordAsync("ImportKey", context, key, null, allowed: true, reason: null, dataHash, cancellationToken);
        _logger.LogInformation("Signer: keystore file {Keystore} restored; its keys serve after the next unlock.", material.Keystore);
        return key;
    }

    /// <summary>
    /// What the two keystore-file operations share: the context names a caller, the purpose is
    /// one of those the operation allows, the reference names a whole keystore and the format is
    /// the keystore-file one. The lock state is not consulted: neither operation needs a key.
    /// </summary>
    private static SigningRefusedException? JudgeKeystoreFile(SigningContext context, KeyRef key, string format, string expectedFormat, params SigningPurpose[] allowed)
    {
        if (string.IsNullOrWhiteSpace(context.Caller))
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                "A keystore file moves only for a named caller; a context with no caller moves nothing.");
        if (!allowed.Contains(context.Purpose))
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"A keystore file moves whole only under {string.Join(" or ", allowed)}, not {context.Purpose}.");
        if (!key.IsKeystoreFile)
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The keystore-file wrap applies to a whole keystore, not to the key {key}.");
        if (!string.Equals(format, expectedFormat, StringComparison.OrdinalIgnoreCase))
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"A whole keystore moves only in the '{expectedFormat}' format, not '{format}'.");
        return null;
    }

    /// <summary>
    /// What every PKCS#12 export shares before the key is even looked at: the signer is
    /// unlocked, the context names a caller, the purpose is <see cref="SigningPurpose.Export"/>
    /// and nothing else, and the wrap is one the signer produces. A backup never takes a key out
    /// one at a time under a password the caller picks; it takes whole keystore files, which
    /// branch off before this check.
    /// </summary>
    private SigningRefusedException? JudgeExportContext(SigningContext context, ExportWrap wrap)
    {
        if (!_unlocked)
            return new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore.");
        if (string.IsNullOrWhiteSpace(context.Caller))
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                "An export names the caller it is for; a context with no caller exports nothing.");
        if (context.Purpose != SigningPurpose.Export)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                context.Purpose == SigningPurpose.Backup
                    ? "A backup takes whole keystore files, never a single key as PKCS#12."
                    : $"Keys leave the signer as PKCS#12 only under an Export context, not {context.Purpose}.");
        if (!string.Equals(wrap.Format, ExportWrap.Pkcs12, StringComparison.OrdinalIgnoreCase))
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The signer does not wrap an exported key as '{wrap.Format}'; it produces '{ExportWrap.Pkcs12}'.");
        return null;
    }

    /// <summary>
    /// The export policy table over the kind of key: only an end-entity key leaves, to its
    /// holder; a CA, responder, TSA, CMP or system key is never handed out as PKCS#12, under
    /// any purpose.
    /// </summary>
    private static SigningRefusedException? JudgeExport(CachedOwner owner, SigningContext context, KeyRef key)
    {
        if (context.Purpose != SigningPurpose.Export || owner.Kind != KeyKind.EndEntity)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"A {owner.Kind} key is not exported to a holder; only an end-entity key leaves under Export.");
        return null;
    }

    /// <summary>
    /// The key of an end-entity certificate is not in the keystore: before re-download ended the
    /// node wrapped it under a CA's public key and stored the wrap on the certificate row. This
    /// reads that wrap, finds the CA that made it by the serial the row records (or, for rows
    /// older than that column, the system signing CA), and unwraps it with that CA's software
    /// key. A row with no wrap is the normal case for every certificate issued since, and is
    /// refused with the reason that tells the holder where their key went.
    /// </summary>
    private async Task<(AsymmetricKeyParameter? Key, SigningRefusedException? Refusal)> UnwrapStoredEndEntityKeyAsync(
        CachedOwner owner, KeyRef key, CancellationToken cancellationToken)
    {
        CertificateEntity? row;
        using (var scope = _scopes.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            row = await db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.CertificateId == key.CertificateId, cancellationToken);
        }
        if (row == null || row.EncryptedPrivateKey == null || row.AesKeyEncryptionIv == null || row.EncryptedAesForPrivateKey == null)
            return (null, new SigningRefusedException(SigningRefusalReason.UnknownKey,
                $"The signer holds no key for {key}: a key the CA generates is delivered once, in the download that carries the request, and is not kept."));

        var trusted = _keystore.GetTrustedAuthorities();
        X509Certificate? wrapper = null;
        if (!string.IsNullOrEmpty(row.EncryptionCertSerialNumber))
            wrapper = trusted.FirstOrDefault(ca => CertificateUtil.FormatSerialNumber(ca.SerialNumber) == row.EncryptionCertSerialNumber);
        wrapper ??= trusted.FirstOrDefault(ca => ca.SubjectDN.ToString().Contains("System", StringComparison.OrdinalIgnoreCase));
        var handle = wrapper == null ? null : _keystore.GetPrivateKeyFor(wrapper);
        if (handle == null)
            return (null, new SigningRefusedException(SigningRefusalReason.UnknownKey,
                $"The stored key of {key} is wrapped under a CA the signer holds no key for ({row.EncryptionCertSerialNumber ?? "unrecorded"})."));
        if (handle is not SoftwarePrivateKeyHandle software)
            return (null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The stored key of {key} is wrapped under a CA whose key is held on a token that cannot unwrap it."));

        try
        {
            var unwrapped = KeyEncryptionUtil.DecryptPrivateKey(
                row.EncryptedAesForPrivateKey, row.AesKeyEncryptionIv, row.EncryptedPrivateKey,
                software.PrivateKey, wrapper!.GetPublicKey(), _keyWrapping?.GetPassphrase());
            return (unwrapped, null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Signer: the stored key of {Key} could not be unwrapped.", key);
            return (null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The stored key of {key} could not be unwrapped with the CA key that wrapped it."));
        }
    }

    /// <summary>
    /// A key the signer holds itself in its keystore: it must be a software key, since a PKCS#11
    /// key never leaves its token. The export policy lets only an end-entity key reach here.
    /// </summary>
    private (AsymmetricKeyParameter? Key, SigningRefusedException? Refusal) HeldSoftwareKey(CachedOwner owner, KeyRef key)
    {
        var handle = _keystore.GetPrivateKeyFor(owner.Certificate);
        if (handle == null)
            return (null, new SigningRefusedException(SigningRefusalReason.UnknownKey, $"The signer holds no private key for {key}."));
        if (handle is not SoftwarePrivateKeyHandle software)
            return (null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The key {key} is held on a PKCS#11 token and never leaves it."));
        return (software.PrivateKey, null);
    }

    /// <summary>
    /// Places the key and its certificate, followed by the chain the wrap carries, in a
    /// PKCS#12 under the wrap's password. The alias is the one the export service has always
    /// written, so the file opens in the same tools as before.
    /// </summary>
    private static byte[] WrapAsPkcs12(AsymmetricKeyParameter privateKey, X509Certificate certificate, ExportWrap wrap)
    {
        var entries = new List<X509CertificateEntry> { new(certificate) };
        foreach (var der in wrap.Chain ?? Array.Empty<byte[]>())
            entries.Add(new X509CertificateEntry(new X509Certificate(der)));

        var store = new Pkcs12StoreBuilder().Build();
        store.SetKeyEntry("certificate", new AsymmetricKeyEntry(privateKey), entries.ToArray());
        using var ms = new MemoryStream();
        store.Save(ms, wrap.Password.ToCharArray(), new SecureRandom());
        return ms.ToArray();
    }

    /// <summary>
    /// Holds a pending key to the scope and CA the generating context named, when it named
    /// them and the operating context names them too. A space and the instance never match.
    /// </summary>
    private static SigningRefusedException? HoldPendingToContext(PendingKey pending, SigningContext context, KeyRef key)
    {
        if ((pending.SpaceId != null && context.SpaceId != null && pending.SpaceId != context.SpaceId)
            || (pending.InstanceScope && context.SpaceId != null)
            || (pending.SpaceId != null && context.InstanceScope))
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"The generated key {key} was generated for {(pending.InstanceScope ? "the instance" : $"space {pending.SpaceId}")}, not {(context.InstanceScope ? "the instance" : $"space {context.SpaceId}")}.");
        if (pending.CaId != null && context.CaId != null && pending.CaId != context.CaId)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"The generated key {key} was generated for CA {pending.CaId}, not CA {context.CaId}.");
        return null;
    }

    /// <summary>
    /// Holds a CA-owned key to its CA: the context must name the owning CA, and a scope it
    /// states must be the owning CA's: its space, or the instance for an instance CA.
    /// </summary>
    private static SigningRefusedException? HoldToOwner(CachedOwner owner, SigningContext context, KeyRef key)
    {
        if (context.CaId == null)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                $"Signing with the {owner.Kind} key {key} requires the context to name the CA the operation is for.");
        if (context.CaId != owner.CaId)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"The {owner.Kind} key {key} belongs to CA {owner.CaId}, not CA {context.CaId}.");
        if ((context.SpaceId != null && context.SpaceId != owner.SpaceId) || (context.InstanceScope && owner.SpaceId != null))
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"The {owner.Kind} key {key} belongs to {DescribeScope(owner.SpaceId)}, not {(context.InstanceScope ? "the instance" : $"space {context.SpaceId}")}.");
        return null;
    }

    /// <summary>
    /// Holds a commit to the CA that owns <paramref name="certificateId"/>, soft-deleted or not.
    /// A key generated for a CA binds only to a certificate of that CA
    /// (<see cref="SigningRefusalReason.CaMismatch"/>). Under an infrastructure context the
    /// certificate must be the OCSP responder, TSA or CMP signer certificate of a CA
    /// (<see cref="SigningRefusalReason.PurposeNotPermitted"/> otherwise), and that CA is held to
    /// the context as <see cref="HoldToOwner"/> holds a signing key: the context names it, and a
    /// scope it states is that CA's.
    /// </summary>
    private async Task<SigningRefusedException?> JudgeCommitOwnerAsync(PendingKey pending, Guid certificateId, SigningContext context, KeyRef key, CancellationToken cancellationToken)
    {
        var infrastructure = context.Purpose == SigningPurpose.Infrastructure;
        if (pending.CaId == null && !infrastructure)
            return null;

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var owner = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .Where(c => c.CertificateId == certificateId || c.OcspResponderCertificateId == certificateId
                     || c.TsaCertificateId == certificateId || c.CmpSigningCertificateId == certificateId)
            .Select(c => new { c.Id, c.SpaceId, IsCaCertificate = c.CertificateId == certificateId })
            .FirstOrDefaultAsync(cancellationToken);

        if (pending.CaId is Guid pendingCa && owner?.Id != pendingCa)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"The generated key {key} was generated for CA {pendingCa}; certificate {certificateId} belongs to {(owner == null ? "no CA" : $"CA {owner.Id}")}.");
        if (!infrastructure)
            return null;
        if (owner == null || owner.IsCaCertificate)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"Certificate {certificateId} is no CA's OCSP responder, TSA or CMP signer certificate; an infrastructure key binds only to one.");
        if (context.CaId == null)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                $"Committing an infrastructure key requires the context to name the CA certificate {certificateId} belongs to.");
        if (context.CaId != owner.Id)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"Certificate {certificateId} belongs to CA {owner.Id}, not CA {context.CaId}.");
        if ((context.SpaceId != null && context.SpaceId != owner.SpaceId) || (context.InstanceScope && owner.SpaceId != null))
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"Certificate {certificateId} belongs to CA {owner.Id} of {DescribeScope(owner.SpaceId)}, not {(context.InstanceScope ? "the instance" : $"space {context.SpaceId}")}.");
        return null;
    }

    /// <summary>
    /// Reads the certificate row a key is being bound to and checks that it carries the key's
    /// public half. A row that is missing, unparseable or for another key is a
    /// <see cref="SigningRefusalReason.CertificateMismatch"/>.
    /// </summary>
    private async Task<(X509Certificate? Certificate, SigningRefusedException? Refusal)> MatchCertificateAsync(
        KeyRef key, Guid certificateId, byte[] publicKeyDer, CancellationToken cancellationToken)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var row = await db.Certificates.AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == certificateId, cancellationToken);
        var cert = row == null ? null : TryParse(row);
        if (cert == null)
            return (null, new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"No certificate row {certificateId} exists to bind the key {key} to."));

        var certPublicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(cert.GetPublicKey()).GetDerEncoded();
        if (!certPublicKeyDer.AsSpan().SequenceEqual(publicKeyDer))
            return (null, new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"Certificate {certificateId} does not carry the public key of {key}; the key is not bound to it."));
        return (cert, null);
    }

    /// <summary>
    /// Writes a key and its certificate through the persistence, then registers the identity so
    /// the key resolves at once, and forgets any classification of the certificate made before
    /// the key existed.
    /// </summary>
    private void Persist(SoftwarePrivateKeyHandle handle, X509Certificate certificate, KeyRef key)
    {
        var privateKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(handle.PrivateKey).GetDerEncoded();
        try
        {
            _persistence.Append(privateKeyDer, certificate.GetEncoded());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyDer);
        }
        _keystore.RegisterSigner(certificate, handle);
        _owners.TryRemove(key.CertificateId, out _);
        _logger.LogInformation("Signer: key committed for certificate {CertificateId} ({Subject}).", key.CertificateId, certificate.SubjectDN);
    }

    /// <summary>
    /// Works out what kind of key a certificate's is and which CA owns it, from the database.
    /// Cached for <see cref="ClassificationTtl"/>; a certificate that is not known is not cached,
    /// since the row it lacks may be written a moment later.
    /// </summary>
    private async Task<CachedOwner?> ClassifyAsync(Guid certificateId, CancellationToken cancellationToken)
    {
        if (_owners.TryGetValue(certificateId, out var cached) && cached.ExpiresAt > DateTime.UtcNow)
            return cached;

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

        var row = await db.Certificates.AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == certificateId, cancellationToken);
        if (row == null)
            return null;
        var cert = TryParse(row);
        if (cert == null)
        {
            _logger.LogWarning("Signer: certificate {CertificateId} could not be parsed from its row; refusing to sign with it.", certificateId);
            return null;
        }

        var ca = await db.CertificateAuthorities.AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == certificateId
                                   || c.OcspResponderCertificateId == certificateId
                                   || c.TsaCertificateId == certificateId
                                   || c.CmpSigningCertificateId == certificateId, cancellationToken);

        KeyOwner owner;
        if (ca == null)
            owner = new KeyOwner(row.IsCA ? KeyKind.Unknown : KeyKind.EndEntity, null, null);
        else if (ca.CertificateId == certificateId)
            owner = new KeyOwner(KeyKind.Ca, ca.Id, ca.SpaceId);
        else if (ca.OcspResponderCertificateId == certificateId)
            owner = new KeyOwner(KeyKind.OcspResponder, ca.Id, ca.SpaceId);
        else if (ca.TsaCertificateId == certificateId)
            owner = new KeyOwner(KeyKind.Tsa, ca.Id, ca.SpaceId);
        else
            owner = new KeyOwner(KeyKind.CmpSigner, ca.Id, ca.SpaceId);

        var entry = new CachedOwner(owner.Kind, owner.CaId, owner.SpaceId, cert, DateTime.UtcNow + ClassificationTtl);
        _owners[certificateId] = entry;
        return entry;
    }

    private static X509Certificate? TryParse(CertificateEntity row)
    {
        try
        {
            if (row.RawCertificate is { Length: > 0 })
                return new X509Certificate(row.RawCertificate);
            if (!string.IsNullOrWhiteSpace(row.Pem))
                return CertificateUtil.ParseFromPem(row.Pem);
        }
        catch
        {
            // Reported by the caller; an unparseable row is treated as not known.
        }
        return null;
    }

    /// <summary>
    /// Writes the decision. The signer's record is the point of the signer, so a sink that
    /// fails is an error. In process it does not withhold a signature the policy allowed: the
    /// node's own audit still sees the issuance, and a database that cannot take one insert has
    /// already stopped the caller before it got here. The signer role runs fail-closed instead:
    /// its record is the only one, so a decision it cannot write is refused as
    /// <see cref="SigningRefusalReason.AuditUnavailable"/> before any result leaves it, and the
    /// signature, key or file the operation produced is dropped with it.
    /// </summary>
    private async Task RecordAsync(string operation, SigningContext context, KeyRef? key, SignatureAlgorithm? algorithm,
        bool allowed, string? reason, byte[]? dataHash, CancellationToken cancellationToken,
        SecretKind? secretKind = null, string? wrappingKeyId = null)
    {
        var decision = new SignerDecision(DateTime.UtcNow, operation, context, key, algorithm, allowed, reason, dataHash, secretKind, wrappingKeyId);
        try
        {
            await _audit.RecordAsync(decision, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signer: audit record could not be written for {Operation} on {Key} by {Caller} ({Purpose}, allowed={Allowed}).",
                operation, key, context.Caller, context.Purpose, allowed);
            if (_failClosedOnAuditFailure)
                throw new SigningRefusedException(SigningRefusalReason.AuditUnavailable,
                    $"The signer could not record its decision on {operation} and does not act unrecorded: {ex.Message}");
        }
    }

    private readonly record struct KeyOwner(KeyKind Kind, Guid? CaId, Guid? SpaceId);

    private sealed record CachedOwner(KeyKind Kind, Guid? CaId, Guid? SpaceId, X509Certificate Certificate, DateTime ExpiresAt);

    /// <summary>
    /// A key generated but not yet committed: the reference the signer minted for it, the handle
    /// it signs with, its public half, and the context that generated it, which is the only
    /// context it signs under.
    /// </summary>
    private sealed record PendingKey(KeyRef Ref, SoftwarePrivateKeyHandle Handle, byte[] PublicKeyDer, SigningPurpose Purpose, Guid? SpaceId, Guid? CaId, bool InstanceScope, Guid? CeremonyId)
    {
        private readonly object _gate = new();

        /// <summary>
        /// Whether this key may be certified as a CA: it was generated under a ceremony context
        /// naming no existing CA, which is how CA creation generates a CA's key, and which the
        /// ceremony check held to the scope's ceremony or waiver. Delegated keys, generated under
        /// an infrastructure context or a ceremony context naming their CA, never may.
        /// </summary>
        public bool MayBecomeCa => Purpose == SigningPurpose.Ceremony && CaId == null;

        /// <summary>The subject this key was certified under as a CA, by its own self-signature or a parent's; null until then.</summary>
        public X509Name? CertifiedSubject { get; private set; }

        /// <summary>
        /// Records that this key is certified as a CA under <paramref name="subject"/>. A key is
        /// certified as a CA once: false when it already was.
        /// </summary>
        public bool TryCertify(X509Name subject)
        {
            lock (_gate)
            {
                if (CertifiedSubject != null)
                    return false;
                CertifiedSubject = subject;
                return true;
            }
        }

        /// <summary>Holds a fresh key pair pending under a new reference.</summary>
        public static PendingKey From(AsymmetricCipherKeyPair keyPair, SigningContext context) => new(
            new KeyRef(Guid.NewGuid()),
            new SoftwarePrivateKeyHandle(keyPair.Private),
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded(),
            context.Purpose, context.SpaceId, context.CaId, context.InstanceScope, context.CeremonyId);
    }
}
