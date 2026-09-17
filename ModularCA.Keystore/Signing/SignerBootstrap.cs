using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Keystore.Adapters;
using ModularCA.Keystore.Hsm;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The startup unlock, behind the signer. <see cref="Unlock"/> decrypts the keystore files
/// with the main and secondary passphrases the keystore configuration holds, pairs the keys
/// with their certificates and keeps the handles in a registry that only this object and the
/// signer it creates can reach; <see cref="Locked"/> is the state of setup mode and of a load
/// that failed. The node holds the bootstrap, registers <see cref="Certificates"/> for the
/// services that need CA certificates, and asks <see cref="CreateSigner"/> for the one door to
/// the keys. It never receives a key, a handle or the registry.
/// </summary>
public sealed class SignerBootstrap
{
    private readonly MultiCARegistry _registry;
    private string _backend = SignerHealth.SoftwareBackend;

    private SignerBootstrap(MultiCARegistry registry, bool unlocked)
    {
        _registry = registry;
        Unlocked = unlocked;
    }

    /// <summary>Whether the keystores were decrypted; the signer reports this as its health.</summary>
    public bool Unlocked { get; }

    /// <summary>The certificates the node loaded, with no key on them, for the services that need them.</summary>
    public IKeystoreCertificates Certificates => _registry;

    /// <summary>
    /// Unlocks the keystores under <paramref name="keystorePath"/>. Throws what the keystore
    /// loader throws: a <see cref="System.Security.SecurityException"/>,
    /// <see cref="System.Security.Cryptography.CryptographicException"/> or
    /// <see cref="InvalidDataException"/> for a file that does not verify, which the node treats
    /// as fatal; anything else for a file or database that could not be read.
    /// </summary>
    /// <param name="yamlPath">The keystore configuration file.</param>
    /// <param name="keystorePath">The directory holding <c>ca-certs.keystore</c> and <c>ca-trust.keystore</c>.</param>
    /// <param name="dbConnectionString">The application database, for the pinned signer.</param>
    public static SignerBootstrap Unlock(string yamlPath, string keystorePath, string dbConnectionString)
    {
        var loaded = StartupKeystoreLoader.LoadAll(keystorePath, yamlPath, dbConnectionString);
        var signers = loaded.FullCAs
            .Select(x => (x.Cert, (IPrivateKeyHandle)new SoftwarePrivateKeyHandle(x.PrivateKey)))
            .ToList();
        return new SignerBootstrap(new MultiCARegistry(signers, loaded.TrustedCAs), unlocked: true);
    }

    /// <summary>A bootstrap that holds nothing and reports locked: setup mode, or a keystore that could not be read.</summary>
    public static SignerBootstrap Locked() => new(MultiCARegistry.Empty(), unlocked: false);

    /// <summary>
    /// Adds the PKCS#11-backed CAs to the registry: every enabled CA whose key storage is
    /// <c>Pkcs11</c> and whose key is found on the token under its label. The signer then
    /// reports the PKCS#11 backend. Returns the certificates that were added, for the node to
    /// report.
    /// </summary>
    public IReadOnlyList<X509Certificate> AddHsmSigners(Pkcs11SessionManager hsm, string dbConnectionString)
    {
        var added = new List<X509Certificate>();
        foreach (var (cert, handle) in StartupKeystoreLoader.LoadHsmSigners(hsm, dbConnectionString))
        {
            _registry.RegisterSigner(cert, handle);
            added.Add(cert);
        }
        _backend = SignerHealth.Pkcs11Backend;
        return added;
    }

    /// <summary>
    /// Creates the in-process signer over the registry: the one door to the keys, judging every
    /// request against its policy and writing its own audit row. A key it commits is appended
    /// to the keystore files through <see cref="FileKeystorePersistence"/>, under the passphrases
    /// the keystore configuration holds and re-signed by the pinned system signer.
    /// </summary>
    /// <param name="keystoresDirectory">The directory holding the keystore files.</param>
    /// <param name="yamlPath">The keystore configuration file.</param>
    /// <param name="scopes">Opens database scopes of the signer's own.</param>
    /// <param name="audit">Where the signer records its decisions.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="keyWrapping">The passphrase non-RSA key wraps are derived from, for unwrapping a stored end-entity key.</param>
    public ISigningService CreateSigner(
        string keystoresDirectory,
        string yamlPath,
        IServiceScopeFactory scopes,
        ISignerAuditSink audit,
        ILogger<InProcessSigningService> logger,
        IKeyWrappingPassphraseProvider? keyWrapping)
    {
        return new InProcessSigningService(
            _registry,
            scopes,
            audit,
            new FileKeystorePersistence(keystoresDirectory, yamlPath, scopes, _registry),
            logger,
            unlocked: Unlocked,
            backend: _backend,
            keyWrapping: keyWrapping);
    }
}
