using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Models;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// Appends committed keys to the keystore files the node loads at startup: the private key to
/// <c>ca-certs.keystore</c>, the certificate to <c>ca-trust.keystore</c>, through
/// <see cref="KeystoreService.AppendEntries"/>, which decrypts the file with the main and
/// secondary passphrases the keystore configuration already holds, re-encrypts it with the new
/// entry, and re-signs it with the system signer whose SPKI is pinned for the file. The system
/// signer is resolved from the registry here, inside the keystore project, so no caller of the
/// signer has to hold it.
/// </summary>
public sealed class FileKeystorePersistence : ISignerKeyPersistence
{
    private const string CertsKeystore = "ca-certs.keystore";
    private const string TrustKeystore = "ca-trust.keystore";

    private readonly string _keystoresDirectory;
    private readonly string _yamlPath;
    private readonly IServiceScopeFactory _scopes;
    private readonly ISignerKeyRegistry _registry;

    /// <summary>
    /// Creates the persistence over the keystore directory and configuration file.
    /// </summary>
    /// <param name="keystoresDirectory">The directory holding <c>ca-certs.keystore</c> and <c>ca-trust.keystore</c>.</param>
    /// <param name="yamlPath">The keystore configuration file the secondary passphrases fall back to.</param>
    /// <param name="scopes">Opens a database scope of its own for the pinned signer and the pin MAC refresh.</param>
    /// <param name="registry">The runtime registry the system signer is resolved from.</param>
    public FileKeystorePersistence(string keystoresDirectory, string yamlPath, IServiceScopeFactory scopes, ISignerKeyRegistry registry)
    {
        _keystoresDirectory = keystoresDirectory ?? throw new ArgumentNullException(nameof(keystoresDirectory));
        _yamlPath = yamlPath ?? throw new ArgumentNullException(nameof(yamlPath));
        _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    /// <inheritdoc />
    public void Append(byte[] privateKeyPkcs8Der, byte[] certificateDer)
    {
        ArgumentNullException.ThrowIfNull(privateKeyPkcs8Der);
        ArgumentNullException.ThrowIfNull(certificateDer);

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var (systemSigner, systemSignerDer) = ResolveSystemSigner(db);
        try
        {
            KeystoreService.AppendEntries(
                Path.Combine(_keystoresDirectory, CertsKeystore), _yamlPath, CertsKeystore,
                new[] { privateKeyPkcs8Der }, systemSigner, db);
            KeystoreService.AppendEntries(
                Path.Combine(_keystoresDirectory, TrustKeystore), _yamlPath, TrustKeystore,
                new[] { certificateDer }, systemSigner, db);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(systemSignerDer);
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<string> ListKeystoreFiles()
    {
        if (!Directory.Exists(_keystoresDirectory))
            return Array.Empty<string>();
        return Directory.GetFiles(_keystoresDirectory, "*.keystore", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName)
            .Where(n => n != null)
            .Select(n => n!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();
    }

    /// <inheritdoc />
    public byte[] ReadKeystoreFile(string name)
    {
        return File.ReadAllBytes(PathFor(name));
    }

    /// <inheritdoc />
    /// <remarks>
    /// The bytes are written beside the live file first, as <c>name.restoring</c>, and verified
    /// there: the pin for <paramref name="name"/> is authenticated with the secondary passphrase
    /// when one can be resolved, and the file's signature is checked against it. Only then is
    /// the live file moved to <c>name.bak.&lt;timestamp&gt;</c> and the verified file moved into
    /// place. A verification failure deletes the staged file and leaves the live one untouched.
    /// When the secondary passphrase cannot be resolved the pin is read without its MAC and the
    /// gap is said aloud, as the restore did before the signer owned this step.
    /// </remarks>
    public void ImportKeystoreFile(string name, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        var livePath = PathFor(name);
        Directory.CreateDirectory(_keystoresDirectory);
        var stagedPath = livePath + ".restoring";
        try
        {
            File.WriteAllBytes(stagedPath, bytes);
            ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly(stagedPath);

            using (var scope = _scopes.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
                var pinned = ResolvePinnedSpki(db, name);
                KeystoreService.VerifyKeystoreFileSignature(stagedPath, db, pinned);
            }

            if (File.Exists(livePath))
                File.Move(livePath, $"{livePath}.bak.{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}");
            File.Move(stagedPath, livePath);
        }
        finally
        {
            try { if (File.Exists(stagedPath)) File.Delete(stagedPath); } catch { /* the staged file is not the live one */ }
        }
    }

    /// <summary>
    /// The pin a restored file is verified against. Authenticated through its MAC when the
    /// secondary passphrase for the keystore resolves, which is the normal case on the host the
    /// keystore belongs to; otherwise the unauthenticated pin, with a warning, since the
    /// alternative is refusing every restore on a host whose keystore.yaml is not yet in place.
    /// </summary>
    private string? ResolvePinnedSpki(ModularCADbContext db, string name)
    {
        string? secondary = null;
        string? whyNot = null;
        try
        {
            secondary = Config.KeystoreYamlLoader.LoadSecondaryPassphrase(_yamlPath, name);
        }
        catch (Exception ex)
        {
            whyNot = ex.Message;
        }

        if (secondary != null)
            return KeystoreService.LoadVerifiedPinnedSpki(db, name, secondary);

        Console.WriteLine(
            $"  [WARNING] Could not resolve the secondary passphrase for '{name}' ({whyNot}), " +
            "so its SPKI pin could not be authenticated. Signature verification proceeds " +
            "against an UNVERIFIED pin. Set MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE or " +
            "restore config/keystore.yaml before re-running to close this gap.");
        return KeystoreService.GetPinnedSignerSpki(db, name);
    }

    /// <summary>
    /// The path of a keystore file by name. The name is a file name and nothing else: a
    /// separator or a parent reference in it is refused, so a name from an archive cannot
    /// reach outside the keystore directory.
    /// </summary>
    private string PathFor(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name != Path.GetFileName(name) || name.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException($"'{name}' is not a keystore file name.", nameof(name));
        return Path.Combine(_keystoresDirectory, name);
    }

    /// <summary>
    /// Resolves the exportable system signer that re-signs the keystore files after a write,
    /// matching the SPKI pinned for <c>ca-certs.keystore</c>. The pinned signer is not
    /// necessarily the first registered one, which is whatever came first out of the keystore
    /// file, usually the Root CA, and signing with the wrong one produces a keystore whose
    /// signature no longer matches the pin.
    /// </summary>
    private (AsymmetricKeyParameter Signer, byte[] Der) ResolveSystemSigner(ModularCADbContext db)
    {
        var signers = _registry.GetSigners();
        if (signers.Count < 1)
            throw new InvalidOperationException("Need at least 1 signer in registry for keystore operations");

        var pinnedSpki = KeystoreService.GetPinnedSignerSpki(db, CertsKeystore);
        CertificateAuthorityIdentity? matched = null;
        if (pinnedSpki != null)
        {
            foreach (var s in signers)
            {
                if (string.Equals(KeystoreService.ComputeSpkiSha256Hex(s.PublicCertificate), pinnedSpki, StringComparison.OrdinalIgnoreCase))
                {
                    matched = s;
                    break;
                }
            }
        }
        matched ??= signers[0];

        var handle = _registry.GetPrivateKeyFor(matched.PublicCertificate)
            ?? throw new InvalidOperationException("System signer private key handle is null");
        if (!handle.CanExport)
            throw new NotSupportedException(
                "The system CA signer is backed by a non-exportable key handle (e.g. HSM). " +
                "Runtime keystore writes currently require an exportable signer.");

        var der = handle.ExportPrivateKeyDer()
            ?? throw new InvalidOperationException("System signer private key DER export returned null");
        try
        {
            return (PrivateKeyFactory.CreateKey(der), der);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(der);
            throw;
        }
    }
}
