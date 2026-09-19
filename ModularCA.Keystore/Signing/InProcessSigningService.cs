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
/// id and tenant come from the same row, and that is what the context is held to.
/// </para>
/// <para>
/// A key the signer generates or imports has no certificate yet. It is held pending, in the
/// signer's memory only, under a reference the signer mints, and signs only under the ceremony
/// or bootstrap context it was created in: that is how a new CA self-signs, signs its CSR, and
/// signs its infrastructure certificates before any row names it. <see cref="CommitKeyAsync"/>
/// binds the pending key to the certificate row that now carries its public key, persists the
/// pair through <see cref="ISignerKeyPersistence"/> and registers the identity; from then on the
/// key serves the policy for its kind. <see cref="RetireKeyAsync"/> discards a pending key. A
/// failure anywhere between generation and commit therefore leaves nothing on disk and nothing
/// that signs outside the ceremony that made it.
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
    public async Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(context);

        var dataHash = SHA256.HashData(data);
        var (handle, refusal) = await ResolveAsync(key, context, JudgeSign, JudgePending, cancellationToken);
        if (refusal != null)
        {
            await RecordAsync("Sign", context, key, algorithm, allowed: false, refusal.Message, dataHash, cancellationToken);
            throw refusal;
        }

        var signature = handle!.Sign(data, algorithm.Name);
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
        var (handle, refusal) = await ResolveAsync(key, context, JudgeDecrypt, RefusePendingDecrypt, cancellationToken);
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
    /// pair is persisted and registered at once, so the key serves the policy for its kind from
    /// this call on; the wrapped bytes are zeroed once parsed.
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
        refusal ??= await JudgeCeremonyAsync(context, cancellationToken);

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
    public async Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(context);

        var committed = new KeyRef(certificateId, key.Keystore);
        var refusal = JudgeKeyManagement(context) ?? await JudgeCeremonyAsync(context, cancellationToken);
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
    /// Two contexts export. Under <see cref="SigningPurpose.Export"/> an end-entity key goes to
    /// its holder: the key the node wrapped at request time and stored on the certificate row,
    /// before re-download ended, is unwrapped here with the CA key that wrapped it and
    /// re-wrapped as PKCS#12 under the holder's password, beside the chain the caller supplies.
    /// Under <see cref="SigningPurpose.Backup"/> every key the signer holds may leave the same
    /// way under the backup's password. The context must name its caller in either case, since
    /// the export right is a person's, and a PKCS#11 key never leaves its token. A certificate
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
            if (ca.CertificateId is Guid c) owners[c] = new KeyOwner(KeyKind.Ca, ca.Id, ca.TenantId);
            if (ca.OcspResponderCertificateId is Guid o) owners[o] = new KeyOwner(KeyKind.OcspResponder, ca.Id, ca.TenantId);
            if (ca.TsaCertificateId is Guid t) owners[t] = new KeyOwner(KeyKind.Tsa, ca.Id, ca.TenantId);
            if (ca.CmpSigningCertificateId is Guid m) owners[m] = new KeyOwner(KeyKind.CmpSigner, ca.Id, ca.TenantId);
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
                owner.Kind, owner.CaId, owner.TenantId,
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
    /// Resolves the key and judges the context: a pending key with <paramref name="judgePending"/>,
    /// a key the keystore holds with <paramref name="judge"/> over its classification. Returns
    /// the handle to use, or the refusal to record and throw; never both.
    /// </summary>
    private async Task<(IPrivateKeyHandle? Handle, SigningRefusedException? Refusal)> ResolveAsync(
        KeyRef key, SigningContext context,
        Func<CachedOwner, SigningContext, KeyRef, SigningRefusedException?> judge,
        Func<PendingKey, SigningContext, KeyRef, SigningRefusedException?> judgePending,
        CancellationToken cancellationToken)
    {
        if (!_unlocked)
            return (null, new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore."));

        if (_pending.TryGetValue(key.CertificateId, out var pending))
        {
            var pendingRefusal = judgePending(pending, context, key);
            return pendingRefusal != null ? (null, pendingRefusal) : (pending.Handle, null);
        }

        var owner = await ClassifyAsync(key.CertificateId, cancellationToken);
        if (owner == null)
            return (null, new SigningRefusedException(SigningRefusalReason.UnknownKey, $"No certificate {key} is known to the signer."));

        var handle = _keystore.GetPrivateKeyFor(owner.Certificate);
        if (handle == null)
            return (null, new SigningRefusedException(SigningRefusalReason.UnknownKey, $"The signer holds no private key for {key}."));

        var refusal = judge(owner, context, key);
        return refusal != null ? (null, refusal) : (handle, null);
    }

    /// <summary>
    /// The signing policy table. A key of a given kind signs for the purposes listed for it, and
    /// only for the CA that owns it; a caller that names a tenant must name the owning CA's tenant.
    /// </summary>
    private static SigningRefusedException? JudgeSign(CachedOwner owner, SigningContext context, KeyRef key)
    {
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
    /// generated under, ceremony or bootstrap, and only for the tenant and CA (when either was
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
    /// The rule every key-management operation shares: generation, import, commit and retire
    /// happen only under a ceremony or bootstrap context, and never while locked.
    /// </summary>
    private SigningRefusedException? JudgeKeyManagement(SigningContext context)
    {
        if (!_unlocked)
            return new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore.");
        if (context.Purpose is not (SigningPurpose.Ceremony or SigningPurpose.Bootstrap or SigningPurpose.Infrastructure))
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"Keys are generated, imported, committed and retired only under a ceremony, bootstrap or infrastructure context, not {context.Purpose}.");
        return null;
    }

    /// <summary>
    /// Verifies the ceremony a <see cref="SigningPurpose.Ceremony"/> context names, against the
    /// database and read-only: the ceremony exists, is approved, has not expired, names the
    /// tenant the context names, and names no other CA than the one the context names.
    /// Anything else is <see cref="SigningRefusalReason.CeremonyNotApproved"/>. A ceremony
    /// context that names no ceremony is held to the tenant's own policy instead, by
    /// <see cref="JudgeCeremonyRequirementAsync"/>: a tenant that requires ceremonies gets no
    /// key without one, a tenant that does not creates its CAs directly, as before. Generation,
    /// import and commit are held to this; retiring a pending key is the undo of a failed
    /// ceremony and is not. A <see cref="SigningPurpose.Bootstrap"/> context is not held to
    /// either: no tenant or ceremony exists yet when the node bootstraps.
    /// </summary>
    private async Task<SigningRefusedException?> JudgeCeremonyAsync(SigningContext context, CancellationToken cancellationToken)
    {
        if (context.Purpose != SigningPurpose.Ceremony)
            return null;
        if (context.CeremonyId is not Guid ceremonyId)
            return await JudgeCeremonyRequirementAsync(context, cancellationToken);

        KeyCeremonyEntity? ceremony;
        using (var scope = _scopes.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            ceremony = await db.KeyCeremonies.AsNoTracking().FirstOrDefaultAsync(c => c.Id == ceremonyId, cancellationToken);
        }

        if (ceremony == null)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"No ceremony {ceremonyId} exists; the signer manages keys under a ceremony it can verify.");
        if (!string.Equals(ceremony.Status, "Approved", StringComparison.Ordinal))
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} is {ceremony.Status}, not Approved.");
        if (ceremony.ExpiresAt <= DateTime.UtcNow)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} expired at {ceremony.ExpiresAt:O}; its approval no longer stands.");
        if (context.TenantId != null && ceremony.TenantId != context.TenantId)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} was approved for tenant {ceremony.TenantId?.ToString() ?? "none"}, not tenant {context.TenantId}.");
        if (context.CaId != null && Guid.TryParse(ceremony.TargetEntityId, out var target) && target != Guid.Empty && target != context.CaId)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} targets CA {target}, not CA {context.CaId}.");
        return null;
    }

    /// <summary>
    /// Holds a ceremony context that names no ceremony to the tenant's own policy, read from
    /// the database: the tenant the context names, or, when it names none, the tenant of the
    /// CA it names. A tenant whose <c>RequireKeyCeremony</c> is set gets no key without a
    /// ceremony, and neither does a tenant the signer cannot find, since no waiver can be
    /// verified for it; both are <see cref="SigningRefusalReason.CeremonyRequired"/>. A
    /// context naming neither tenant nor CA cannot be held to any tenant and is
    /// <see cref="SigningRefusalReason.ContextRequired"/>. A tenant that does not require
    /// ceremonies is allowed through, which is the stage-2 behaviour unchanged.
    /// </summary>
    private async Task<SigningRefusedException?> JudgeCeremonyRequirementAsync(SigningContext context, CancellationToken cancellationToken)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

        var tenantId = context.TenantId;
        if (tenantId == null && context.CaId is Guid caId)
        {
            tenantId = await db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.Id == caId)
                .Select(ca => (Guid?)ca.TenantId)
                .FirstOrDefaultAsync(cancellationToken);
            if (tenantId == null)
                return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                    $"The context names CA {caId}, which the signer does not know, so the tenant whose ceremony policy applies cannot be resolved.");
        }
        if (tenantId == null)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                "Key management without a ceremony names the tenant or the CA the key is for; a context naming neither cannot be held to a tenant's ceremony policy.");

        var requirement = await db.Tenants.AsNoTracking()
            .Where(t => t.Id == tenantId)
            .Select(t => (bool?)t.RequireKeyCeremony)
            .FirstOrDefaultAsync(cancellationToken);
        if (requirement == null)
            return new SigningRefusedException(SigningRefusalReason.CeremonyRequired,
                $"No tenant {tenantId} is known to the signer; a key is managed for it only under a ceremony the signer can verify.");
        if (requirement.Value)
            return new SigningRefusedException(SigningRefusalReason.CeremonyRequired,
                $"Tenant {tenantId} requires a key ceremony and the context names none.");
        return null;
    }

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
    /// What every export shares before the key is even looked at: the signer is unlocked, the
    /// context names a caller, the purpose is <see cref="SigningPurpose.Export"/> or
    /// <see cref="SigningPurpose.Backup"/>, and the wrap is one the signer produces.
    /// </summary>
    private SigningRefusedException? JudgeExportContext(SigningContext context, ExportWrap wrap)
    {
        if (!_unlocked)
            return new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore.");
        if (string.IsNullOrWhiteSpace(context.Caller))
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                "An export names the caller it is for; a context with no caller exports nothing.");
        if (context.Purpose is not (SigningPurpose.Export or SigningPurpose.Backup))
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"Keys leave the signer only under an Export or Backup context, not {context.Purpose}.");
        if (!string.Equals(wrap.Format, ExportWrap.Pkcs12, StringComparison.OrdinalIgnoreCase))
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The signer does not wrap an exported key as '{wrap.Format}'; it produces '{ExportWrap.Pkcs12}'.");
        return null;
    }

    /// <summary>
    /// The export policy table over the kind of key. Under Export only an end-entity key leaves,
    /// to its holder; a CA or infrastructure key is never handed to a person through the API.
    /// Under Backup every key the signer holds leaves, whatever its kind, since a backup is the
    /// whole keystore.
    /// </summary>
    private static SigningRefusedException? JudgeExport(CachedOwner owner, SigningContext context, KeyRef key)
    {
        if (context.Purpose == SigningPurpose.Export && owner.Kind != KeyKind.EndEntity)
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
    /// A key the signer holds itself, for a backup: it must be a software key, since a PKCS#11
    /// key never leaves its token and a backup of the token is the token's own affair.
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
    /// Holds a pending key to the tenant and CA the generating context named, when it named
    /// them and the operating context names them too.
    /// </summary>
    private static SigningRefusedException? HoldPendingToContext(PendingKey pending, SigningContext context, KeyRef key)
    {
        if (pending.TenantId != null && context.TenantId != null && pending.TenantId != context.TenantId)
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"The generated key {key} was generated for tenant {pending.TenantId}, not tenant {context.TenantId}.");
        if (pending.CaId != null && context.CaId != null && pending.CaId != context.CaId)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"The generated key {key} was generated for CA {pending.CaId}, not CA {context.CaId}.");
        return null;
    }

    /// <summary>
    /// Holds a CA-owned key to its CA: the context must name the owning CA, and a tenant it
    /// names must be the owning CA's tenant.
    /// </summary>
    private static SigningRefusedException? HoldToOwner(CachedOwner owner, SigningContext context, KeyRef key)
    {
        if (context.CaId == null)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                $"Signing with the {owner.Kind} key {key} requires the context to name the CA the operation is for.");
        if (context.CaId != owner.CaId)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"The {owner.Kind} key {key} belongs to CA {owner.CaId}, not CA {context.CaId}.");
        if (context.TenantId != null && context.TenantId != owner.TenantId)
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"The {owner.Kind} key {key} belongs to tenant {owner.TenantId}, not tenant {context.TenantId}.");
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
            owner = new KeyOwner(KeyKind.Ca, ca.Id, ca.TenantId);
        else if (ca.OcspResponderCertificateId == certificateId)
            owner = new KeyOwner(KeyKind.OcspResponder, ca.Id, ca.TenantId);
        else if (ca.TsaCertificateId == certificateId)
            owner = new KeyOwner(KeyKind.Tsa, ca.Id, ca.TenantId);
        else
            owner = new KeyOwner(KeyKind.CmpSigner, ca.Id, ca.TenantId);

        var entry = new CachedOwner(owner.Kind, owner.CaId, owner.TenantId, cert, DateTime.UtcNow + ClassificationTtl);
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
        bool allowed, string? reason, byte[]? dataHash, CancellationToken cancellationToken)
    {
        var decision = new SignerDecision(DateTime.UtcNow, operation, context, key, algorithm, allowed, reason, dataHash);
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

    private readonly record struct KeyOwner(KeyKind Kind, Guid? CaId, Guid? TenantId);

    private sealed record CachedOwner(KeyKind Kind, Guid? CaId, Guid? TenantId, X509Certificate Certificate, DateTime ExpiresAt);

    /// <summary>
    /// A key generated but not yet committed: the reference the signer minted for it, the handle
    /// it signs with, its public half, and the context that generated it, which is the only
    /// context it signs under.
    /// </summary>
    private sealed record PendingKey(KeyRef Ref, SoftwarePrivateKeyHandle Handle, byte[] PublicKeyDer, SigningPurpose Purpose, Guid? TenantId, Guid? CaId)
    {
        /// <summary>Holds a fresh key pair pending under a new reference.</summary>
        public static PendingKey From(AsymmetricCipherKeyPair keyPair, SigningContext context) => new(
            new KeyRef(Guid.NewGuid()),
            new SoftwarePrivateKeyHandle(keyPair.Private),
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded(),
            context.Purpose, context.TenantId, context.CaId);
    }
}
