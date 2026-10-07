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
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The SSH half of the in-process signer: the lifecycle of the keys in
/// <see cref="KeyRef.SshKeystore"/>. An SSH CA key has no certificate, so nothing here goes
/// through the certificate classification, the certificate registry or the pending keys of the
/// X.509 half. What stands in for the certificate is the <c>SshCaKeys</c> row, and the tie
/// between a key and its row is the public key, compared as OpenSSH encodes it.
/// </summary>
/// <remarks>
/// <para>
/// A key is an SSH key because it is in the SSH keystore, never because a row says so. The
/// registry holds SSH keys apart from every other key, each bound to a row id when it was
/// loaded, committed or imported (<see cref="ISignerKeyRegistry.GetSshKey"/>), and a reference
/// naming the SSH keystore is resolved only there. A row that points at the public key of an
/// X.509 key therefore finds no key, and the database can only choose among the keys the file
/// already holds. The binding is checked on load, on commit and on import, and again whenever a
/// key is listed: a row that no longer carries the key's public half does not get the key.
/// </para>
/// <para>
/// A generated key is pending until committed, as an X.509 key is, but in a map of its own
/// (<see cref="_pendingSsh"/>): the X.509 half cannot find it, so it signs nothing, is certified
/// as nothing and commits to no certificate; and the SSH commit cannot find an X.509 key.
/// </para>
/// </remarks>
public sealed partial class InProcessSigningService
{
    private readonly ConcurrentDictionary<Guid, PendingSshKey> _pendingSsh = new();

    /// <summary>
    /// Held by commit, import and retire from their first check to their last write, so two
    /// calls cannot both find a row without a key, or a pending key still pending, and write twice.
    /// </summary>
    private readonly SemaphoreSlim _sshKeyWrites = new(1, 1);

    /// <summary>Waits for <see cref="_sshKeyWrites"/>; disposing the result releases it.</summary>
    private async Task<IDisposable> HoldSshKeyWritesAsync(CancellationToken cancellationToken)
    {
        await _sshKeyWrites.WaitAsync(cancellationToken);
        return new SshKeyWritesHeld(_sshKeyWrites);
    }

    private sealed class SshKeyWritesHeld(SemaphoreSlim writes) : IDisposable
    {
        public void Dispose() => writes.Release();
    }

    /// <summary>Whether the reference names the SSH keystore, which is what routes it to this half.</summary>
    private static bool IsSshRef(KeyRef key) => string.Equals(key.Keystore, KeyRef.SshKeystore, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// What generation, commit and retire of an SSH CA key share on top of
    /// <see cref="JudgeKeyManagement"/>: a ceremony context and nothing else, so an
    /// infrastructure context, which is held to no ceremony, never makes an SSH CA key; and the
    /// instance as the stated scope (<see cref="JudgeSshScope"/>).
    /// </summary>
    private static SigningRefusedException? JudgeSshKeyManagement(SigningContext context)
    {
        if (context.Purpose != SigningPurpose.Ceremony)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"An SSH CA key is generated, committed and retired only under a ceremony context, not {context.Purpose}.");
        return JudgeSshScope(context);
    }

    /// <summary>
    /// SSH CAs are instance CAs: a context that names a space is
    /// <see cref="SigningRefusalReason.TenantMismatch"/>, and one that does not state the
    /// instance is <see cref="SigningRefusalReason.ContextRequired"/>, since an unstated scope is
    /// never read as the instance.
    /// </summary>
    private static SigningRefusedException? JudgeSshScope(SigningContext context)
    {
        if (context.SpaceId != null)
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"SSH CAs are instance CAs; the context names space {context.SpaceId}.");
        if (!context.InstanceScope)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                "An SSH CA key operation states the instance as its scope; this context states no scope.");
        return null;
    }

    /// <summary>
    /// The first of two checks on what an SSH CA key may be: the spec names RSA, ECDSA or
    /// Ed25519, and an RSA size of at least <see cref="SshCertificateRules.MinRsaBits"/>, before
    /// any key is generated. <see cref="JudgeSshKey"/> then judges the key itself.
    /// </summary>
    private static SigningRefusedException? JudgeSshKeySpec(KeySpec spec)
    {
        var algorithm = (spec.Algorithm ?? string.Empty).ToUpperInvariant();
        if (algorithm is not ("RSA" or "ECDSA" or "ED25519"))
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"An SSH CA key is Ed25519, ECDSA P-256, P-384 or P-521, or RSA of at least {SshCertificateRules.MinRsaBits} bits; '{spec.Algorithm}' is none of them.");
        if (algorithm == "RSA" && (!int.TryParse(spec.SizeOrCurve, out var bits) || bits < SshCertificateRules.MinRsaBits))
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"An RSA SSH CA key is at least {SshCertificateRules.MinRsaBits} bits; '{spec.SizeOrCurve}' is not.");
        return null;
    }

    /// <summary>
    /// What an SSH CA key may be, judged on the key: its public half has an OpenSSH encoding of
    /// a type a certificate can be signed with (Ed25519, ECDSA P-256, P-384 or P-521, RSA), and
    /// an RSA modulus of at least <see cref="SshCertificateRules.MinRsaBits"/> bits. A generated
    /// key and an imported key are both held to it. Returns the OpenSSH form of the key.
    /// </summary>
    private static (SshPublicKey? PublicKey, SigningRefusedException? Refusal) JudgeSshKey(AsymmetricKeyParameter publicKey)
    {
        SshPublicKey ssh;
        try
        {
            ssh = SshPublicKey.FromKeyParameter(publicKey);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            return (null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The key cannot be an SSH CA key: {ex.Message}"));
        }
        if (!SshKeyTypes.Certifiable.Contains(ssh.KeyType))
            return (null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"A {ssh.KeyType} key cannot be an SSH CA key; SSH certificates are signed with Ed25519, ECDSA or RSA."));
        if (ssh.KeyType == SshKeyTypes.Rsa && ssh.KeySizeBits < SshCertificateRules.MinRsaBits)
            return (null, new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"An RSA SSH CA key is at least {SshCertificateRules.MinRsaBits} bits; this one is {ssh.KeySizeBits}."));
        return (ssh, null);
    }

    /// <summary>
    /// Holds a freshly generated SSH CA key pending, under a reference in the SSH keystore. The
    /// key is judged first (<see cref="JudgeSshKey"/>); the audit row is written before the key
    /// becomes reachable, as for any generated key. A pending SSH key signs nothing and decrypts
    /// nothing: it waits for <see cref="CommitSshKeyAsync"/> or <see cref="RetireSshKeyAsync"/>.
    /// </summary>
    private async Task<GeneratedKey> HoldPendingSshKeyAsync(AsymmetricCipherKeyPair keyPair, SigningContext context, CancellationToken cancellationToken)
    {
        var (publicKey, refusal) = JudgeSshKey(keyPair.Public);
        if (refusal != null)
        {
            await RecordAsync("GenerateKey", context, null, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        var pending = new PendingSshKey(
            new KeyRef(Guid.NewGuid(), KeyRef.SshKeystore),
            new SoftwarePrivateKeyHandle(keyPair.Private),
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded(),
            publicKey!,
            context.CaId);
        await RecordAsync("GenerateKey", context, pending.Ref, null, allowed: true, reason: null, SHA256.HashData(pending.PublicKeyDer), cancellationToken);
        _pendingSsh[pending.Ref.CertificateId] = pending;
        return new GeneratedKey(pending.Ref, pending.PublicKeyDer);
    }

    /// <summary>
    /// Commits a pending SSH CA key to the <c>SshCaKeys</c> row <paramref name="sshCaKeyId"/> and
    /// appends it to the SSH keystore. Allowed only under a ceremony context at instance scope,
    /// under a <c>CreateSshCa</c> ceremony or the instance's waiver
    /// (<see cref="JudgeCeremonyAsync"/>). The row must carry the key's public half, have storage
    /// <see cref="SshCaKeyStorage.Signer"/>, be enabled and not already have a key; its CA must
    /// be an SSH CA of the instance, enabled and not deleted, and be the CA the context names
    /// (<see cref="JudgeSshRow"/>). A key generated naming a CA commits only for that CA.
    /// </summary>
    private async Task CommitSshKeyAsync(KeyRef key, Guid sshCaKeyId, SigningContext context, CancellationToken cancellationToken)
    {
        using var writing = await HoldSshKeyWritesAsync(cancellationToken);
        var committed = new KeyRef(sshCaKeyId, KeyRef.SshKeystore);
        var refusal = JudgeKeyManagement(context) ?? JudgeSshKeyManagement(context)
            ?? await JudgeCeremonyAsync(context, cancellationToken, licensing: SshKeyCeremonies);
        PendingSshKey? pending = null;
        if (refusal == null && !_pendingSsh.TryGetValue(key.CertificateId, out pending))
            refusal = new SigningRefusedException(SigningRefusalReason.UnknownKey, $"No generated SSH CA key awaits commit under {key}.");
        if (refusal == null)
            refusal = HoldPendingSshToContext(pending!, context, key);
        if (refusal == null)
        {
            var row = await ReadSshRowAsync(sshCaKeyId, cancellationToken);
            refusal = JudgeSshRow(row, pending!.PublicKey, context, committed, SshCaKeyStorage.Signer, requireEnabled: true);
        }
        if (refusal == null && _keystore.GetSshKey(sshCaKeyId) != null)
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The signer already holds a key for SSH CA key row {sshCaKeyId}; a row never changes key.");

        if (refusal != null)
        {
            await RecordAsync("CommitKey", context, committed, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        await RecordAsync("CommitKey", context, committed, null, allowed: true, reason: null, SHA256.HashData(pending!.PublicKeyDer), cancellationToken);
        PersistSshKey(new SshKeyBinding(sshCaKeyId, pending.PublicKey, pending.Handle), append: true);
        _pendingSsh.TryRemove(key.CertificateId, out _);
    }

    /// <summary>
    /// The one import <see cref="SigningPurpose.SshKeyMigration"/> permits, and the only way a
    /// key enters the SSH keystore from outside: a PKCS#8 key for an <c>SshCaKeys</c> row whose
    /// storage is <see cref="SshCaKeyStorage.LegacyFile"/> and which carries the key's public
    /// half, of an SSH CA of the instance that the context names. It needs no ceremony, because
    /// it creates no key and no trust. A disabled row is imported too: the point is to take the
    /// key off the node. The key is held to <see cref="JudgeSshKey"/> as a generated one is.
    /// </summary>
    /// <remarks>
    /// The import is safe to repeat. When the signer already holds this key for the row, the
    /// call succeeds and writes nothing, which is what lets a migration that crashed after the
    /// import run again. When it holds another key for the row, the call is refused: a row
    /// never changes key. The wrapped bytes are zeroed once parsed.
    /// </remarks>
    private async Task<KeyRef> ImportSshKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken)
    {
        using var writing = await HoldSshKeyWritesAsync(cancellationToken);
        var key = new KeyRef(material.CertificateId, KeyRef.SshKeystore);
        SigningRefusedException? refusal = null;
        if (!_unlocked)
            refusal = new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore.");
        else if (context.Purpose != SigningPurpose.SshKeyMigration)
            refusal = new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"A key enters {KeyRef.SshKeystore} only under an {SigningPurpose.SshKeyMigration} context, not {context.Purpose}.");
        else if (!string.Equals(material.Format, KeyMaterial.Pkcs8, StringComparison.OrdinalIgnoreCase))
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"Key material in format '{material.Format}' cannot be imported; the signer accepts '{KeyMaterial.Pkcs8}'.");
        refusal ??= JudgeSshScope(context);

        AsymmetricKeyParameter? privateKey = null;
        SshPublicKey? publicKey = null;
        byte[]? publicKeyDer = null;
        if (refusal == null)
        {
            try
            {
                privateKey = PrivateKeyFactory.CreateKey(material.Wrapped);
                (publicKey, refusal) = JudgeSshKey(KeystoreService.GetPublicFromPrivate(privateKey));
                if (publicKey != null)
                    publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey.KeyParameter).GetDerEncoded();
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

        if (refusal == null)
        {
            var row = await ReadSshRowAsync(material.CertificateId, cancellationToken);
            refusal = JudgeSshRow(row, publicKey!, context, key, SshCaKeyStorage.LegacyFile, requireEnabled: false);
        }

        var bound = refusal == null ? _keystore.GetSshKey(material.CertificateId) : null;
        if (bound != null && !bound.PublicKey.Equals(publicKey))
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The signer already holds a different key for SSH CA key row {material.CertificateId}; a row never changes key.");

        if (refusal != null)
        {
            await RecordAsync("ImportKey", context, key, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        var publicHash = SHA256.HashData(publicKeyDer!);
        if (bound != null)
        {
            await RecordAsync("ImportKey", context, key, null, allowed: true,
                "The signer already holds this key for the row; nothing was written.", publicHash, cancellationToken);
            return key;
        }

        // The same key under another row is already in the file: it is bound, not written twice.
        var held = _keystore.GetSshKeys().FirstOrDefault(k => k.PublicKey.Equals(publicKey));
        await RecordAsync("ImportKey", context, key, null, allowed: true, reason: null, publicHash, cancellationToken);
        PersistSshKey(new SshKeyBinding(material.CertificateId, publicKey!, held?.Handle ?? new SoftwarePrivateKeyHandle(privateKey!)), append: held == null);
        return key;
    }

    /// <summary>
    /// Discards a pending SSH CA key, which was never written anywhere. Held to
    /// <see cref="JudgeSshKeyManagement"/> and to the CA the key was generated for, but to no
    /// ceremony, as the retire of any pending key is. A committed SSH CA key cannot be retired;
    /// disabling its SSH CA is what takes it out of service.
    /// </summary>
    private async Task RetireSshKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken)
    {
        using var writing = await HoldSshKeyWritesAsync(cancellationToken);
        var refusal = JudgeKeyManagement(context) ?? JudgeSshKeyManagement(context);
        PendingSshKey? pending = null;
        if (refusal == null && !_pendingSsh.TryGetValue(key.CertificateId, out pending))
        {
            refusal = _keystore.GetSshKey(key.CertificateId) != null
                ? new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                    $"The key {key} is committed to its SSH CA key row and cannot be retired; disable the SSH CA instead.")
                : new SigningRefusedException(SigningRefusalReason.UnknownKey, $"No generated SSH CA key awaits commit under {key}.");
        }
        if (refusal == null)
            refusal = HoldPendingSshToContext(pending!, context, key);

        if (refusal != null)
        {
            await RecordAsync("RetireKey", context, key, null, allowed: false, refusal.Message, null, cancellationToken);
            throw refusal;
        }

        _pendingSsh.TryRemove(key.CertificateId, out _);
        await RecordAsync("RetireKey", context, key, null, allowed: true, reason: null, SHA256.HashData(pending!.PublicKeyDer), cancellationToken);
    }

    /// <summary>
    /// The SSH CA keys the signer holds, for <see cref="ListKeysAsync"/>: one entry per bound row
    /// that still exists and still carries the public key the signer holds for it, of the CA the
    /// context names when it names one. A key whose row is gone or carries another key is not
    /// listed, since it is not served.
    /// </summary>
    private async Task<List<KeyInfo>> ListSshKeysAsync(ModularCADbContext db, SigningContext context, CancellationToken cancellationToken)
    {
        var keys = new List<KeyInfo>();
        var held = _keystore.GetSshKeys();
        if (held.Count == 0)
            return keys;

        var ids = held.Select(k => k.KeyId).ToList();
        var rows = await db.SshCaKeys.AsNoTracking()
            .Where(k => ids.Contains(k.Id))
            .Select(k => new { k.Id, k.PublicKey, k.CertificateAuthorityId })
            .ToListAsync(cancellationToken);
        var caIds = rows.Select(r => r.CertificateAuthorityId).Distinct().ToList();
        var spaces = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .Where(c => caIds.Contains(c.Id))
            .Select(c => new { c.Id, c.SpaceId })
            .ToDictionaryAsync(c => c.Id, c => c.SpaceId, cancellationToken);

        foreach (var row in rows)
        {
            if (context.CaId is Guid caId && row.CertificateAuthorityId != caId)
                continue;
            var binding = held.First(k => k.KeyId == row.Id);
            if (SshRowKey.Parse(row.PublicKey) is not { } rowKey || !rowKey.Equals(binding.PublicKey))
                continue;
            keys.Add(new KeyInfo(
                new KeyRef(row.Id, KeyRef.SshKeystore),
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(binding.PublicKey.KeyParameter).GetDerEncoded(),
                KeyKind.SshCa, row.CertificateAuthorityId, spaces.GetValueOrDefault(row.CertificateAuthorityId),
                binding.Handle is Pkcs11PrivateKeyHandle ? SignerHealth.Pkcs11Backend : SignerHealth.SoftwareBackend));
        }
        return keys;
    }

    /// <summary>
    /// Holds a pending SSH CA key to the CA the generating context named, when it named one and
    /// the operating context names one too. The scope needs no holding: every SSH key operation
    /// states the instance.
    /// </summary>
    private static SigningRefusedException? HoldPendingSshToContext(PendingSshKey pending, SigningContext context, KeyRef key)
    {
        if (pending.CaId != null && context.CaId != null && pending.CaId != context.CaId)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"The generated SSH CA key {key} was generated for CA {pending.CaId}, not CA {context.CaId}.");
        return null;
    }

    /// <summary>
    /// The binding of a key to an <c>SshCaKeys</c> row, for commit and import. The row must
    /// exist and carry <paramref name="publicKey"/>, compared as OpenSSH encodes it
    /// (<see cref="SigningRefusalReason.CertificateMismatch"/> otherwise); its storage must be
    /// <paramref name="requiredStorage"/>; its CA must exist, be an SSH CA and have no space;
    /// and the context must name that CA. With <paramref name="requireEnabled"/> the row and its
    /// CA must also be enabled and the CA not deleted, which a commit needs and the migration of
    /// an existing key does not.
    /// </summary>
    private static SigningRefusedException? JudgeSshRow(SshRow? row, SshPublicKey publicKey, SigningContext context, KeyRef key, string requiredStorage, bool requireEnabled)
    {
        if (row == null)
            return new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"No SSH CA key row {key.CertificateId} exists to bind the key to.");
        if (row.PublicKey == null)
            return new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"SSH CA key row {row.Id} does not carry a public key the signer can read; the key is not bound to it.");
        if (!row.PublicKey.Equals(publicKey))
            return new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"SSH CA key row {row.Id} does not carry the public key of {key}; the key is not bound to it.");
        if (!string.Equals(row.KeyStorage, requiredStorage, StringComparison.Ordinal))
            return new SigningRefusedException(
                requiredStorage == SshCaKeyStorage.LegacyFile ? SigningRefusalReason.PurposeNotPermitted : SigningRefusalReason.OperationUnsupported,
                $"SSH CA key row {row.Id} has storage '{row.KeyStorage}'; this operation binds a key only to a row whose storage is '{requiredStorage}'.");
        if (!row.CaExists || !row.CaIsSshCa)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"CA {row.CaId} is not an SSH CA; an SSH CA key binds only to a row of one.");
        if (row.CaSpaceId != null)
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"CA {row.CaId} belongs to space {row.CaSpaceId}; SSH CAs are instance CAs.");
        if (requireEnabled && (!row.IsEnabled || !row.CaIsEnabled || row.CaIsDeleted))
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"SSH CA key row {row.Id} or its CA {row.CaId} is disabled or deleted; no key is committed to it.");
        if (context.CaId == null)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                $"Binding a key to SSH CA key row {row.Id} requires the context to name the SSH CA it belongs to.");
        if (context.CaId != row.CaId)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"SSH CA key row {row.Id} belongs to CA {row.CaId}, not CA {context.CaId}.");
        return null;
    }

    /// <summary>
    /// Reads an <c>SshCaKeys</c> row and what the signer needs of its CA, soft-deleted or not.
    /// Null when there is no such row. Never cached: a row is read each time a key is bound to it.
    /// </summary>
    private async Task<SshRow?> ReadSshRowAsync(Guid sshCaKeyId, CancellationToken cancellationToken)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var row = await db.SshCaKeys.AsNoTracking()
            .Where(k => k.Id == sshCaKeyId)
            .Select(k => new { k.Id, k.PublicKey, k.KeyStorage, k.IsEnabled, k.CertificateAuthorityId })
            .FirstOrDefaultAsync(cancellationToken);
        if (row == null)
            return null;
        var ca = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .Where(c => c.Id == row.CertificateAuthorityId)
            .Select(c => new { c.IsSshCa, c.IsEnabled, c.IsDeleted, c.SpaceId })
            .FirstOrDefaultAsync(cancellationToken);
        return new SshRow(row.Id, SshRowKey.Parse(row.PublicKey), row.KeyStorage, row.IsEnabled, row.CertificateAuthorityId,
            ca != null, ca?.IsSshCa ?? false, ca?.IsEnabled ?? false, ca?.IsDeleted ?? false, ca?.SpaceId);
    }

    /// <summary>
    /// Binds an SSH CA key to its row in the registry, after writing it to the SSH keystore
    /// through the persistence when <paramref name="append"/> is set, so the key resolves at
    /// once. Nothing is written to the trust keystore and nothing joins the signers.
    /// </summary>
    private void PersistSshKey(SshKeyBinding binding, bool append)
    {
        if (append)
        {
            var privateKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(((SoftwarePrivateKeyHandle)binding.Handle).PrivateKey).GetDerEncoded();
            try
            {
                _persistence.AppendSshKey(privateKeyDer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyDer);
            }
        }
        _keystore.RegisterSshKey(binding);
        _logger.LogInformation("Signer: SSH CA key committed for SSH CA key row {SshCaKeyId} ({Fingerprint}).", binding.KeyId, binding.PublicKey.Fingerprint);
    }

    /// <summary>An <c>SshCaKeys</c> row as the signer reads it, with the state of its CA.</summary>
    private sealed record SshRow(Guid Id, SshPublicKey? PublicKey, string KeyStorage, bool IsEnabled, Guid CaId,
        bool CaExists, bool CaIsSshCa, bool CaIsEnabled, bool CaIsDeleted, Guid? CaSpaceId);

    /// <summary>
    /// An SSH CA key generated but not yet committed: the reference the signer minted for it in
    /// the SSH keystore, its handle, its public half in both encodings, and the CA the
    /// generating context named, if any. It is always a ceremony key of the instance.
    /// </summary>
    private sealed record PendingSshKey(KeyRef Ref, SoftwarePrivateKeyHandle Handle, byte[] PublicKeyDer, SshPublicKey PublicKey, Guid? CaId);
}
