using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Keystore.Adapters;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Models;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// A key the journal signs with, over a handle the signer holds: the system key through its
/// handle, software or PKCS#11, and the checkpoint key through a software handle. The algorithm
/// is the one the product uses for a key of that kind.
/// </summary>
internal sealed class HandleJournalKey : IJournalSigningKey
{
    private readonly IPrivateKeyHandle _handle;

    public HandleJournalKey(IPrivateKeyHandle handle, AsymmetricKeyParameter publicKey)
    {
        _handle = handle ?? throw new ArgumentNullException(nameof(handle));
        PublicKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded();
        Algorithm = SignatureAlgorithm.ForPublicKey(publicKey).Name;
    }

    /// <inheritdoc />
    public byte[] PublicKey { get; }

    /// <inheritdoc />
    public string Algorithm { get; }

    /// <inheritdoc />
    public byte[] Sign(byte[] message) => _handle.Sign(message, Algorithm);
}

/// <summary>
/// The journal's keys as the signer holds them: the system key, the checkpoint key, and how
/// the checkpoint key is made and kept.
/// </summary>
/// <remarks>
/// <para>
/// <b>The system key</b> is the key of the system signing CA: the signer whose SPKI is pinned for
/// <c>ca-certs.keystore</c>, which is the key that signs the keystore files. It signs for the
/// journal only when a checkpoint key is made or changed.
/// </para>
/// <para>
/// <b>The checkpoint key</b> is a key of the instance's own, used for nothing else, kept as the
/// last entry of <c>journal.keystore</c>, which is created, encrypted, signed and pinned like
/// <c>ssh-ca.keystore</c>. It is of the system key's family: RSA of the same size (4096 bits at
/// most) for an RSA system key, ECDSA on the same curve, Ed25519, Ed448, or the same ML-DSA
/// parameter set. For an SLH-DSA system key it is ML-DSA-65, since a hash-based signature every
/// second is too large and too slow.
/// </para>
/// <para>
/// Where the system key cannot be exported, which is a key on a PKCS#11 token, the keystore
/// file cannot be signed, so no file is written: the checkpoint key is then made anew at each
/// start and held in memory, and the system key signs for it on the token each time.
/// </para>
/// </remarks>
internal static class SignerJournalKeys
{
    /// <summary>
    /// Builds the options a journal writer opens with: the instance identifier, the system key,
    /// the checkpoint key (loaded, or made and stored), and the old keys the signer still holds.
    /// </summary>
    public static JournalWriterOptions Options(SignerJournalSettings settings, ISignerKeyRegistry registry, string keystoresDirectory,
        string yamlPath, ModularCADbContext db, Action<string> log)
    {
        var signers = registry.GetSigners();
        if (signers.Count == 0)
            throw new JournalUnavailableException("The signer holds no key, so the journal has no system key to sign its checkpoint key.");
        var pinned = KeystoreService.GetPinnedSignerSpki(db, KeyRef.DefaultKeystore);
        var system = signers.FirstOrDefault(s => pinned != null
                         && string.Equals(KeystoreService.ComputeSpkiSha256Hex(s.PublicCertificate), pinned, StringComparison.OrdinalIgnoreCase))
                     ?? signers[0];
        var systemHandle = registry.GetPrivateKeyFor(system.PublicCertificate)
            ?? throw new JournalUnavailableException("The signer holds no private key for the system signing CA, so the journal's checkpoint key cannot be signed.");
        var systemKey = new HandleJournalKey(systemHandle, system.PublicCertificate.GetPublicKey());
        var instanceId = InstanceId(db, pinned) ?? Convert.ToHexStringLower(JournalSignatures.KeyHash(systemKey.PublicKey));

        var keys = new List<AsymmetricKeyParameter>();
        if (systemHandle.CanExport)
        {
            var path = Path.Combine(keystoresDirectory, KeyRef.JournalKeystore);
            keys.AddRange(KeystoreService.LoadJournalKeys(path, yamlPath, db, log).Select(k => k.PrivateKey));
            if (keys.Count == 0)
            {
                var made = Generate(system.PublicCertificate.GetPublicKey());
                Store(path, yamlPath, db, made.Private, systemHandle, system.PublicCertificate);
                keys.Add(made.Private);
                log($"The journal's checkpoint key was made ({KeyAlgorithmPolicy.DetectKeyAlgorithm(made.Public)}) and stored in {KeyRef.JournalKeystore}.");
            }
        }
        else
        {
            keys.Add(Generate(system.PublicCertificate.GetPublicKey()).Private);
            log("The system key is not exportable (a PKCS#11 key), so no keystore file can be signed for the journal's checkpoint key: "
                + "a checkpoint key was made for this run and is held in memory; the system key signed for it on the token.");
        }

        var held = keys.Select(k => (IJournalSigningKey)new HandleJournalKey(new SoftwarePrivateKeyHandle(k), KeystoreService.GetPublicFromPrivate(k))).ToList();
        foreach (var signer in signers)
        {
            if (registry.GetPrivateKeyFor(signer.PublicCertificate) is { } handle)
                held.Add(new HandleJournalKey(handle, signer.PublicCertificate.GetPublicKey()));
        }

        return new JournalWriterOptions
        {
            Directory = JournalLayout.Current(settings.Directory),
            InstanceId = instanceId,
            CheckpointKey = held[keys.Count - 1],
            SystemKey = systemKey,
            Incarnation = settings.Incarnation,
            Version = settings.Version,
            FindHeldKey = hash => held.FirstOrDefault(k => JournalSignatures.KeyHash(k.PublicKey).AsSpan().SequenceEqual(hash)),
            Log = log,
        };
    }

    /// <summary>
    /// The instance identifier as the node keeps it: the stored <c>Instance_Id</c> setting, or
    /// the value the node would store, which is the first keystore pin. Null when neither is
    /// there or the database cannot say.
    /// </summary>
    public static string? InstanceId(ModularCADbContext db, string? pinned)
    {
        try
        {
            var stored = db.Settings.AsNoTracking().Where(s => s.Key == ReservedSettingKeys.InstanceId).Select(s => s.ValueJson).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(stored))
            {
                using var document = System.Text.Json.JsonDocument.Parse(stored);
                if (document.RootElement.ValueKind == System.Text.Json.JsonValueKind.String
                    && document.RootElement.GetString()?.Trim() is { Length: > 0 } id)
                    return id;
            }
            var first = db.Keystores.AsNoTracking()
                .Where(k => k.SigningCaSpkiSha256 != null && k.SigningCaSpkiSha256 != "")
                .OrderBy(k => k.Id).Select(k => k.SigningCaSpkiSha256).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(first))
                return first.Trim().ToLowerInvariant();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A database without the settings table, or one that did not answer: the pin the caller read stands in.
        }
        return string.IsNullOrWhiteSpace(pinned) ? null : pinned.Trim().ToLowerInvariant();
    }

    /// <summary>Generates a checkpoint key of the system key's family.</summary>
    public static AsymmetricCipherKeyPair Generate(AsymmetricKeyParameter systemPublicKey)
    {
        var (algorithm, size) = systemPublicKey switch
        {
            RsaKeyParameters rsa => ("RSA", rsa.Modulus.BitLength switch { <= 2048 => "2048", <= 3072 => "3072", _ => "4096" }),
            ECPublicKeyParameters ec => ("ECDSA", ec.Parameters.Curve.FieldSize switch { <= 256 => "P-256", <= 384 => "P-384", _ => "P-521" }),
            Ed25519PublicKeyParameters => ("Ed25519", string.Empty),
            Ed448PublicKeyParameters => ("Ed448", string.Empty),
            MLDsaPublicKeyParameters mlDsa => (mlDsa.Parameters.Name, string.Empty),
            _ => ("ML-DSA-65", string.Empty),
        };
        return KeyAlgorithmPolicy.GenerateKeyPair(algorithm, size);
    }

    private static void Store(string path, string yamlPath, ModularCADbContext db, AsymmetricKeyParameter checkpointKey,
        IPrivateKeyHandle systemHandle, X509Certificate systemCertificate)
    {
        var systemDer = systemHandle.ExportPrivateKeyDer()
            ?? throw new JournalUnavailableException("The system signing CA's key could not be exported to sign the journal's keystore file.");
        var keyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(checkpointKey).GetDerEncoded();
        try
        {
            KeystoreService.AppendOrCreateEntries(path, yamlPath, KeyRef.JournalKeystore, new[] { keyDer },
                PrivateKeyFactory.CreateKey(systemDer), KeystoreService.ComputeSpkiSha256Hex(systemCertificate), db);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(systemDer);
            CryptographicOperations.ZeroMemory(keyDer);
        }
    }
}
