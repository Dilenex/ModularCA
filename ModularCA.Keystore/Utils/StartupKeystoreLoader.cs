using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Keystore.Hsm;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Utils;

/// <summary>
/// Loads keystore files (CA private keys, trusted certificates and SSH CA keys) at application startup, for
/// <see cref="Signing.SignerBootstrap"/>. Internal: the key parameters it returns never leave
/// the keystore project.
/// </summary>
internal static class StartupKeystoreLoader
{
    /// <summary>
    /// Loads signing keys and trusted CA certificates from their respective keystore files.
    /// </summary>
    public static (List<KeystoreService.CertKey> Signers, List<X509Certificate> TrustedCAs) LoadKeystorePairs(string yamlPath, string dbConnStr)
    {
        string certPath = Path.Combine(AppContext.BaseDirectory, "keystores", "ca-certs.keystore");
        string trustPath = Path.Combine(AppContext.BaseDirectory, "keystores", "ca-trust.keystore");
        var db = new ModularCADbContext(
            new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(dbConnStr)
                .Options
        );

        var signerCerts = KeystoreService.LoadCertKeys(certPath, yamlPath, db);
        var trustedCerts = KeystoreService.LoadTrustedCerts(trustPath, yamlPath, db);
        return (signerCerts, trustedCerts);
    }

    /// <summary>
    /// Loads all keystore data: private keys, matched cert-key pairs, and trusted CA certificates.
    /// </summary>
    public static (List<KeystoreService.CertKey> Signers, List<KeystoreService.CertWithKey> FullCAs, List<X509Certificate> TrustedCAs) LoadAll(string keystorePath, string yamlPath, string dbConnStr)
    {
        var db = new ModularCADbContext(
            new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(dbConnStr)
                .Options
        );

        return LoadAll(keystorePath, yamlPath, db);
    }

    /// <summary>
    /// Loads all keystore data, as the connection-string overload does, through a database the
    /// caller opened.
    /// </summary>
    public static (List<KeystoreService.CertKey> Signers, List<KeystoreService.CertWithKey> FullCAs, List<X509Certificate> TrustedCAs) LoadAll(string keystorePath, string yamlPath, ModularCADbContext db)
    {
        var certPath = Path.Combine(keystorePath, "ca-certs.keystore");
        var trustPath = Path.Combine(keystorePath, "ca-trust.keystore");

        var privKeys = KeystoreService.LoadCertKeys(certPath, yamlPath, db);
        var trustCAs = KeystoreService.LoadTrustedCerts(trustPath, yamlPath, db);
        var fullCAs = KeystoreService.MatchCertsWithKeys(privKeys, trustCAs);

        return (privKeys, fullCAs, trustCAs);
    }

    /// <summary>
    /// Loads the SSH CA keys from <c>ssh-ca.keystore</c> and binds each to the <c>SshCaKeys</c>
    /// rows that carry its public key. A key no row carries is not returned, so it is never
    /// served; the signer checks the binding again each time a key is used. An install with no
    /// SSH keystore returns nothing. Throws what <see cref="KeystoreService.LoadSshKeys"/> throws.
    /// </summary>
    public static List<SshKeyBinding> LoadSshKeys(string keystorePath, string yamlPath, ModularCADbContext db)
    {
        var keys = KeystoreService.LoadSshKeys(Path.Combine(keystorePath, KeyRef.SshKeystore), yamlPath, db);
        var bindings = new List<SshKeyBinding>();
        if (keys.Count == 0)
            return bindings;

        var rows = db.SshCaKeys.AsNoTracking()
            .Select(k => new { k.Id, k.PublicKey })
            .ToList()
            .Select(r => (r.Id, Key: SshRowKey.Parse(r.PublicKey)))
            .Where(r => r.Key != null)
            .ToList();

        foreach (var key in keys)
        {
            SshPublicKey publicKey;
            try
            {
                publicKey = SshPublicKey.FromKeyParameter(KeystoreService.GetPublicFromPrivate(key.PrivateKey));
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or FormatException)
            {
                Console.WriteLine($"[WARNING] {KeyRef.SshKeystore} holds a key that is not an SSH key ({ex.Message}); it is not served.");
                continue;
            }

            var handle = new SoftwarePrivateKeyHandle(key.PrivateKey);
            var bound = 0;
            foreach (var row in rows)
            {
                if (!row.Key!.Equals(publicKey) || bindings.Any(b => b.KeyId == row.Id))
                    continue;
                bindings.Add(new SshKeyBinding(row.Id, publicKey, handle));
                bound++;
            }
            if (bound == 0)
                Console.WriteLine($"[WARNING] {KeyRef.SshKeystore} holds the key {publicKey.Fingerprint}, which no SSH CA key row carries; it is not served.");
        }
        return bindings;
    }

    /// <summary>
    /// Loads HSM-backed CA signers by matching CA entities whose <c>KeyStorageType</c>
    /// is "Pkcs11" to private key objects found on the PKCS#11 token. Each CA's key is bound by
    /// <see cref="Pkcs11KeyBinder"/>: the label must name exactly one private key object, held
    /// the way an HSM key must be, whose public key is the CA certificate's. A bound CA returns
    /// its certificate paired with a non-exporting <see cref="IPrivateKeyHandle"/> that delegates
    /// signing to the HSM; a CA whose key is refused is returned among the refusals and logged as
    /// an error, and gets no handle. A label no object carries is logged and skipped, as before.
    /// </summary>
    /// <param name="hsm">An open PKCS#11 session manager connected to the HSM.</param>
    /// <param name="dbConnStr">PostgreSQL connection string for the ModularCA database.</param>
    /// <returns>
    /// The (certificate, key handle) pairs for every enabled PKCS#11-backed CA whose key was
    /// found and bound, and the CAs whose key was found and refused.
    /// </returns>
    public static (List<(X509Certificate Cert, IPrivateKeyHandle KeyHandle)> Signers, List<HsmKeyRefusal> Refused) LoadHsmSigners(
        Pkcs11SessionManager hsm,
        string dbConnStr)
    {
        var db = new ModularCADbContext(
            new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(dbConnStr)
                .Options
        );

        var hsmCas = db.CertificateAuthorities
            .Include(ca => ca.Certificate)
            .Where(ca => ca.KeyStorageType == "Pkcs11" && ca.IsEnabled)
            .ToList();

        var results = new List<(X509Certificate Cert, IPrivateKeyHandle KeyHandle)>();
        var refused = new List<HsmKeyRefusal>();

        foreach (var ca in hsmCas)
        {
            if (ca.Certificate == null || string.IsNullOrEmpty(ca.HsmKeyLabel))
                continue;

            var cert = new X509Certificate(ca.Certificate.RawCertificate);
            var binding = Pkcs11KeyBinder.Bind(hsm, ca.HsmKeyLabel, cert);
            if (binding.NotFound)
            {
                Console.WriteLine($"[HSM] WARNING: Key '{ca.HsmKeyLabel}' not found on token for CA '{ca.Name}' — skipping.");
                continue;
            }
            if (binding.Key == null)
            {
                Console.Error.WriteLine($"[HSM] ERROR: refusing the key labelled '{ca.HsmKeyLabel}' for CA '{ca.Name}': {binding.Refusal} " +
                    "The CA signs nothing until the token or the CA's HsmKeyLabel is corrected and the signer restarted.");
                refused.Add(new HsmKeyRefusal(cert, ca.HsmKeyLabel, ca.Name, binding.Refusal!));
                continue;
            }

            var pkcs11Handle = new Pkcs11PrivateKeyHandle(hsm, binding.Key, ca.HsmKeyLabel,
                EcdsaSignatureEncoding.ComponentLength(cert.GetPublicKey()));
            results.Add((cert, pkcs11Handle));
        }

        return (results, refused);
    }
}