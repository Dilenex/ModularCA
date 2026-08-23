using ModularCA.Database;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.KeystoreFormat;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
// KeystorePasswordWrapping lives alongside KeystoreDbPassphraseLoader in this namespace.
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto;
using System.Text;
using static ModularCA.Keystore.Services.KeystoreService;

namespace ModularCA.Bootstrap;

/// <summary>
/// Handles writing certificate and key entries to keystore files on disk,
/// persisting keystore metadata to the database, and saving keystore passwords.
/// </summary>
public static class BootstrapKeystoreWriter
{
    /// <summary>
    /// Writes all pending keystore entries to their respective keystore files, signed by the system CA.
    /// Groups entries by keystore name and delegates to <see cref="WriteKeystoreFile"/> for each.
    /// The <paramref name="systemCaCert"/> is optional; when supplied the CA's
    /// SPKI SHA-256 is persisted on the keystore row so runtime loads can pin-verify the file
    /// signature and reject any re-signing by another CA in the database.
    /// </summary>
    public static void WriteCertsToKeystore(
        Dictionary<string, string> keystorePasswords,
        Dictionary<string, string> secondaryPasswords,
        List<AddKeystoreEntry> keystoreEntries,
        AsymmetricKeyParameter systemCaSigner,
        ModularCADbContext db,
        Org.BouncyCastle.X509.X509Certificate? systemCaCert = null)
    {
        var keystoreGroups = keystoreEntries.GroupBy(e => e.Keystore);

        // Pre-compute the signing-CA SPKI SHA-256 if the cert was supplied. We store
        // the hex on every Keystores row so runtime loads can pin-verify the file signature.
        string? pinnedSpkiHex = null;
        if (systemCaCert != null)
        {
            pinnedSpkiHex = KeystoreService.ComputeSpkiSha256Hex(systemCaCert);
        }

        foreach (var group in keystoreGroups)
        {
            var keystoreName = group.Key;
            var keystorePath = Path.Combine(AppContext.BaseDirectory, "keystores", keystoreName);
            var mainPass = keystorePasswords[keystoreName];
            var secondaryPass = secondaryPasswords[keystoreName];

            var keystoreService = new KeystoreService(
                keystorePath,
                mainPass,
                secondaryPass,
                systemCaSigner
            );

            foreach (var entry in group)
            {
                keystoreService.AddEntry(entry.Payload, entry.SecondaryPass);
            }
            WriteKeystoreFile(keystoreService, keystoreName, mainPass, secondaryPass, db, pinnedSpkiHex);

            // Emit a file-only audit event for the keystore write so
            // BootstrapAuditReplayService can replay it into the audit DB once it's
            // reachable on first startup. We log once per keystore file (matching the
            // runtime CaCreationService pattern of one KeystoreKeyAdded per file).
            BootstrapAuditLog.LogKeystoreWrite(
                keystoreName,
                AuditActionType.KeystoreKeyAdded,
                subjectDn: systemCaCert?.SubjectDN?.ToString(),
                thumbprint: pinnedSpkiHex);
        }
    }

    /// <summary>
    /// Saves a single keystore file to disk and records its scrypt parameters
    /// and encrypted passphrase blob in the database. The optional
    /// <paramref name="pinnedSigningCaSpkiHex"/> is the SHA-256 fingerprint of the
    /// keystore-signing CA's SPKI, persisted on the DB row.
    /// </summary>
    public static void WriteKeystoreFile(
        KeystoreService keystoreService,
        string keystoreName,
        string mainPass,
        string secondaryPass,
        ModularCADbContext db,
        string? pinnedSigningCaSpkiHex = null)
    {
        var scryptParams = keystoreService.Save();
        var file = new KeystoreFile
        {
            ScryptSalt = Convert.ToBase64String(scryptParams.Salt),
            ScryptN = scryptParams.Params.N,
            ScryptR = scryptParams.Params.R,
            ScryptP = scryptParams.Params.P
        };
        // "ModularCA:PassWrap" is a domain-separation tag, not a secret.
        // The wrap's actual secrecy comes from secondaryPass, which after bootstrap should
        // be sourced from MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE rather than keystore.yaml.
        var kek = ScryptKeyDeriver.DeriveFileKey(KeystorePasswordWrapping.WrapDomainTag, secondaryPass, file);
        var blob = AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes(mainPass), kek);
        var theBlob = blob.nonce.Concat(blob.ciphertext).Concat(blob.tag).ToArray();
        AddKeystoreEntryToDb(keystoreName, theBlob, scryptParams, db, pinnedSigningCaSpkiHex, secondaryPass);
    }

    /// <summary>
    /// Inserts a keystore metadata record (name, scrypt parameters, encrypted blob) into the
    /// database. <paramref name="pinnedSigningCaSpkiHex"/> records the SHA-256 fingerprint of the
    /// CA that signed the keystore so runtime loads can refuse signatures from any other CA.
    /// <para>
    /// The master passphrase is deliberately NOT a parameter. It used to be, solely to store an
    /// unsalted SHA-256 of it in a column nothing read. The passphrase reaches the database only
    /// inside <paramref name="theBlob"/>, AES-GCM encrypted under the wrapping KEK.
    /// </para>
    /// </summary>
    public static void AddKeystoreEntryToDb(
        string keystoreName,
        byte[] theBlob,
        KeystoreSaveResult scryptParams,
        ModularCADbContext db,
        string? pinnedSigningCaSpkiHex = null,
        string? secondaryPassForMac = null)
    {
        var keystoreEntry = new KeystoreEntryEntity
        {
            Name = keystoreName,
            Passblob = theBlob,
            Salt = Convert.ToBase64String(scryptParams.Salt),
            ScryptN = scryptParams.Params.N,
            ScryptR = scryptParams.Params.R,
            ScryptP = scryptParams.Params.P,
            CreatedAt = DateTime.UtcNow,
            Enabled = true,
            SigningCaSpkiSha256 = pinnedSigningCaSpkiHex,
            // Compute the MAC at row-creation time when we have both the pin
            // and the secondary passphrase. DB-write-only compromise cannot forge a matching
            // MAC because the key comes from the secondary (not stored in DB).
            SigningCaSpkiSha256Mac = (!string.IsNullOrEmpty(pinnedSigningCaSpkiHex) && !string.IsNullOrEmpty(secondaryPassForMac))
                ? KeystoreService.ComputeSpkiPinMac(pinnedSigningCaSpkiHex, secondaryPassForMac!)
                : null,
        };
        db.Keystores.Add(keystoreEntry);
        db.SaveChanges();
        Console.WriteLine($"✓ Keystore '{keystoreName}' entry added to database.");
    }

    /// <summary>
    /// Writes the secondary keystore passphrases to <c>config/keystore.yaml</c> so a brand-new
    /// install has something on disk to bootstrap the first keystore unlock.
    /// </summary>
    /// <remarks>
    /// Asymmetry note: at runtime the canonical source for the secondary passphrase
    /// is the <c>MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE</c> environment variable. The on-disk YAML
    /// file is written here (and tightened to owner-only) only because bootstrap generates the
    /// secondary passphrase before any operator can export an env var. After bootstrap completes,
    /// operators are expected to copy the value into their secret manager / systemd EnvironmentFile,
    /// export it, and remove or further restrict <c>config/keystore.yaml</c>. The runtime loader
    /// (<see cref="ModularCA.Keystore.Config.KeystoreYamlLoader.LoadSecondaryPassphrase"/>) prefers
    /// the env var over the file when both are available.
    /// </remarks>
    public static void WriteKeystorePasswordsToFile(string configDir, Dictionary<string, string> keystorePasswords, Dictionary<string, string> secondaryPasses)
    {
        var yamlLines = keystorePasswords.Select(kvp =>
        {
            var secondary = secondaryPasses.TryGetValue(kvp.Key, out string? value) ? value : "";
            return $"{kvp.Key}: {secondary}";
        }).ToList();

        var yamlPath = Path.Combine(configDir, "keystore.yaml");
        File.WriteAllLines(yamlPath, yamlLines);
        FileSecurityUtil.SetOwnerOnly(yamlPath);

        Console.WriteLine($"\n📝 Secondary passphrases written to: {yamlPath}");
        Console.WriteLine($"   After bootstrap, export these as JSON in the {ModularCA.Keystore.Config.KeystoreYamlLoader.SecondaryPassphraseEnvVar}");
        Console.WriteLine($"   environment variable and tighten/remove {yamlPath} (the runtime loader prefers the env var).");
    }
}
