using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Hsm;
using ModularCA.Keystore.Services;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Utils;

/// <summary>
/// Loads keystore files (CA private keys and trusted certificates) at application startup, for
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
                .UseMySql(dbConnStr, ServerVersion.AutoDetect(dbConnStr))
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
        var certPath = Path.Combine(keystorePath, "ca-certs.keystore");
        var trustPath = Path.Combine(keystorePath, "ca-trust.keystore");

        var db = new ModularCADbContext(
            new DbContextOptionsBuilder<ModularCADbContext>()
                .UseMySql(dbConnStr, ServerVersion.AutoDetect(dbConnStr))
                .Options
        );

        var privKeys = KeystoreService.LoadCertKeys(certPath, yamlPath, db);
        var trustCAs = KeystoreService.LoadTrustedCerts(trustPath, yamlPath, db);
        var fullCAs = KeystoreService.MatchCertsWithKeys(privKeys, trustCAs);

        return (privKeys, fullCAs, trustCAs);
    }

    /// <summary>
    /// Loads HSM-backed CA signers by matching CA entities whose <c>KeyStorageType</c>
    /// is "Pkcs11" to private key objects found on the PKCS#11 token. Each matching CA
    /// returns a certificate paired with a non-exporting <see cref="IPrivateKeyHandle"/>
    /// that delegates signing to the HSM.
    /// </summary>
    /// <param name="hsm">An open PKCS#11 session manager connected to the HSM.</param>
    /// <param name="dbConnStr">MySQL connection string for the ModularCA database.</param>
    /// <returns>
    /// A list of (certificate, key handle) tuples for every enabled PKCS#11-backed CA
    /// whose key was successfully located on the token.
    /// </returns>
    public static List<(X509Certificate Cert, IPrivateKeyHandle KeyHandle)> LoadHsmSigners(
        Pkcs11SessionManager hsm,
        string dbConnStr)
    {
        var db = new ModularCADbContext(
            new DbContextOptionsBuilder<ModularCADbContext>()
                .UseMySql(dbConnStr, ServerVersion.AutoDetect(dbConnStr))
                .Options
        );

        var hsmCas = db.CertificateAuthorities
            .Include(ca => ca.Certificate)
            .Where(ca => ca.KeyStorageType == "Pkcs11" && ca.IsEnabled)
            .ToList();

        var results = new List<(X509Certificate Cert, IPrivateKeyHandle KeyHandle)>();

        foreach (var ca in hsmCas)
        {
            if (ca.Certificate == null || string.IsNullOrEmpty(ca.HsmKeyLabel))
                continue;

            var cert = new X509Certificate(ca.Certificate.RawCertificate);
            var keyHandle = hsm.FindPrivateKey(ca.HsmKeyLabel);
            if (keyHandle == null)
            {
                Console.WriteLine($"[HSM] WARNING: Key '{ca.HsmKeyLabel}' not found on token for CA '{ca.Name}' — skipping.");
                continue;
            }

            var pkcs11Handle = new Pkcs11PrivateKeyHandle(hsm, keyHandle, ca.HsmKeyLabel);
            results.Add((cert, pkcs11Handle));
        }

        return results;
    }
}