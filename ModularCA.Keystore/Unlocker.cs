using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Utils;
using MySqlConnector;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Keystore;

/// <summary>
/// Break-glass CLI that decrypts and displays or exports keystore entries.
/// <para>
/// Verifies the keystore's file-level signature against the pinned signing CA — and the MAC
/// protecting that pin — before decrypting any entry, verifies each entry's own signature, and
/// refuses to write decrypted output to disk unless the operator passes
/// <c>--insecure-no-verify</c>. Without a DB-backed verification step, an attacker who knows the
/// passphrases could swap <c>keystores/ca-certs.keystore</c> and use the Unlocker to extract
/// attacker-controlled CA private keys.
/// </para>
/// <para>
/// Decryption goes through <see cref="KeystoreService.DecryptEntries"/> rather than a local
/// loop. It previously had its own, which passed the file master key straight to AES-GCM. That
/// is correct only through MCAKSTR v3; v4 gives each entry an HKDF-derived key, so the tool
/// failed the authentication tag on every entry of every keystore the product had written. A
/// recovery tool that only runs during a disaster is exactly the code that must not carry its
/// own copy of a format-dependent routine.
/// </para>
/// </summary>
public static class Unlocker
{
    /// <summary>
    /// Parses command-line arguments and decrypts keystore entries to stdout (as PEM) or to
    /// file (as DER). The default mode requires a DB-backed signature verification;
    /// <c>--insecure-no-verify</c> opts out explicitly, and writing decrypted output to disk
    /// requires that flag either way.
    /// </summary>
    public static void Run(string[] args)
    {
        var path = GetArg(args, "--keystore") ?? throw new ArgumentException("Missing --keystore");
        var yamlPath = GetArg(args, "--yaml") ?? "config/keystore.yaml";
        var outputPath = GetArg(args, "--output"); // optional
        var print = args.Contains("--print");
        var insecureNoVerify = args.Contains("--insecure-no-verify");

        Console.WriteLine($"Loading keystore: {path}");

        var keystore = KeystoreFileParser.Parse(path);
        var keystoreName = Path.GetFileName(path);
        // The format version decides how entry keys are derived, so it is the first thing an
        // operator needs when a recovery attempt misbehaves.
        Console.WriteLine($"Keystore format: v{keystore.FormatVersion}");

        // Loaded before the verification block because the SPKI pin's MAC is keyed by the
        // secondary passphrase, so the pin cannot be validated without it.
        var secondaryPass = KeystoreYamlLoader.LoadSecondaryPassphrase(yamlPath, keystoreName);
        string? pinnedSpki = null;

        // The trust keystore holds X.509 certificates; every other keystore holds PKCS#8
        // private keys. Both are DER on disk and indistinguishable without parsing, so the
        // PEM label is taken from the keystore name.
        var pemLabel = keystoreName.Equals("ca-trust.keystore", StringComparison.OrdinalIgnoreCase)
            ? "CERTIFICATE"
            : "PRIVATE KEY";

        // Verify the file-level signature against the pinned signing CA unless
        // the operator explicitly opted out. The pin comes from the Keystores row in the app
        // DB; legacy rows fall through to the loud-warning "any IsCA cert" path in
        // FindValidSigner and the operator should run --backfill-keystore-pins --write to
        // close the gap.
        ModularCADbContext? db = null;
        try
        {
            if (!insecureNoVerify)
            {
                db = OpenAppDb();
                if (db == null)
                {
                    Console.Error.WriteLine(
                        "[ERROR] Unlocker could not open the app database. Re-run with " +
                        "--insecure-no-verify to force an offline decryption (will NOT write output " +
                        "unless that flag is set).");
                    Environment.Exit(1);
                    return;
                }

                // Verify the pin's own MAC before trusting it. GetPinnedSignerSpki, used here
                // previously, returns the pin unchecked — so a DB-write-only compromise could
                // swap it and this tool would validate the keystore against the attacker's CA.
                pinnedSpki = KeystoreService.LoadVerifiedPinnedSpki(db, keystoreName, secondaryPass);
                try
                {
                    KeystoreService.VerifyKeystoreFileSignature(path, db, pinnedSpki);
                }
                catch (SecurityException ex)
                {
                    Console.Error.WriteLine($"[ERROR] Keystore signature verification failed: {ex.Message}");
                    Console.Error.WriteLine("        Refusing to decrypt — pass --insecure-no-verify to override.");
                    Environment.Exit(2);
                    return;
                }

                Console.WriteLine("Keystore file-level signature verified against pinned CA.");
            }
            else
            {
                Console.Error.WriteLine(
                    "[WARNING] Unlocker running with --insecure-no-verify. Keystore signature is NOT checked; " +
                    "this mode exists for disaster recovery and must not be used in production.");
            }

            // Refuse to write decrypted plaintext key material to disk unless the
            // operator explicitly opted out via --insecure-no-verify. The file signature check
            // above doesn't make writing DER private keys to an arbitrary path safe by itself
            // (ACLs on the output directory are up to the operator), so the flag remains a
            // mandatory acknowledgement that the operator accepts the consequences.
            var writeRequested = !string.IsNullOrWhiteSpace(outputPath);
            if (writeRequested && !insecureNoVerify)
            {
                Console.Error.WriteLine(
                    "[ERROR] Unlocker refuses to write decrypted private keys to disk without " +
                    "--insecure-no-verify. Re-run with that flag to acknowledge the risk.");
                Environment.Exit(3);
                return;
            }

            var mainPassBytes = ReadMainPassphraseBytes();

            byte[]? key = null;
            try
            {
                key = ScryptKeyDeriver.DeriveFileKey(mainPassBytes, secondaryPass, keystore);

                // Decrypt through KeystoreService rather than calling AES-GCM directly. The
                // direct call was correct only up to format v3; v4 gives every entry its own
                // HKDF-derived key, so the old loop failed the authentication tag on every
                // entry of every keystore the product writes.
                KeystoreService.DecryptEntries(
                    keystore,
                    key,
                    db,
                    pinnedSpki,
                    verifyEntrySignatures: !insecureNoVerify,
                    (index, decrypted) =>
                    {
                        if (print || string.IsNullOrWhiteSpace(outputPath))
                        {
                            // Entries hold DER, not text. Decoding as UTF-8 produced mojibake
                            // and, worse, looked like a decryption failure. PEM is what an
                            // operator can actually feed to openssl or re-import.
                            Console.WriteLine($"Entry {index}:");
                            Console.WriteLine(ToPem(decrypted, pemLabel));
                        }
                        else
                        {
                            var outputName = outputPath!;
                            var numberedPath = keystore.Entries.Count > 1
                                ? Path.Combine(Path.GetDirectoryName(outputName) ?? string.Empty,
                                    $"{Path.GetFileNameWithoutExtension(outputName)}_{index}{Path.GetExtension(outputName)}")
                                : outputName;

                            File.WriteAllBytes(numberedPath, decrypted);
                            FileSecurityUtil.SetOwnerOnly(numberedPath);
                            Console.WriteLine($"Entry {index} written to: {numberedPath}");
                        }
                    });

                Console.WriteLine($"Decrypted {keystore.Entries.Count} entr" +
                                  $"{(keystore.Entries.Count == 1 ? "y" : "ies")} successfully.");
            }
            catch (CryptographicException ex)
            {
                // An authentication-tag failure here means the derived key is wrong, which in
                // practice is a passphrase problem — say so instead of surfacing the raw
                // "tag mismatch", which reads like file corruption and sends operators looking
                // in the wrong place during an incident.
                Console.Error.WriteLine(
                    $"[ERROR] Entry decryption failed: {ex.Message}");
                Console.Error.WriteLine(
                    insecureNoVerify
                        ? "        The keystore parsed cleanly, so this is almost certainly a wrong " +
                          "main or secondary passphrase."
                        : "        The keystore parsed and its file signature verified, so this is " +
                          "almost certainly a wrong main or secondary passphrase.");
                Environment.Exit(4);
                return;
            }
            finally
            {
                if (key != null)
                    CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(mainPassBytes);
            }
        }
        finally
        {
            db?.Dispose();
        }
    }

    /// <summary>
    /// Opens a <see cref="ModularCADbContext"/> against the runtime app database using
    /// <c>config/config.yaml</c> + <c>config/db.yaml</c> — mirroring the loader path the API
    /// uses at startup. Returns null if the config files are missing (a brand-new install
    /// that has never been bootstrapped).
    /// </summary>
    private static ModularCADbContext? OpenAppDb()
    {
        try
        {
            var configDir = Path.Combine(AppContext.BaseDirectory, "config");
            var configPath = Path.Combine(configDir, "config.yaml");
            var dbYamlPath = Path.Combine(configDir, "db.yaml");
            if (!File.Exists(configPath))
                return null;

            var cfg = YamlConfigLoader.Load(configPath);
            if (File.Exists(dbYamlPath))
            {
                var dbYaml = YamlDbConfigLoader.Load(dbYamlPath);
                if (dbYaml != null)
                {
                    cfg.DB.App.Host = dbYaml.App.Host;
                    cfg.DB.App.Port = dbYaml.App.Port;
                    cfg.DB.App.Database = dbYaml.App.Database;
                    cfg.DB.App.Username = dbYaml.App.Username;
                    cfg.DB.App.Password = dbYaml.App.Password;
                    cfg.DB.App.SslMode = dbYaml.App.SslMode;
                }
            }

            // TLS-Required by default; unparseable values clamp to Required.
            var sslMode = Enum.TryParse<MySqlSslMode>(cfg.DB.App.SslMode, ignoreCase: true, out var _ssl)
                ? _ssl : MySqlSslMode.Required;
            var builder = new MySqlConnectionStringBuilder
            {
                Server = cfg.DB.App.Host,
                Port = (uint)cfg.DB.App.Port,
                Database = cfg.DB.App.Database,
                UserID = cfg.DB.App.Username,
                Password = cfg.DB.App.Password,
                SslMode = sslMode,
            };
            var connStr = builder.ConnectionString;
            var options = new DbContextOptionsBuilder<ModularCADbContext>()
                .UseMySql(connStr, ServerVersion.AutoDetect(connStr))
                .Options;
            return new ModularCADbContext(options);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARNING] Unlocker failed to open app DB for signature verification: {ex.Message}");
            return null;
        }
    }

    private static string? GetArg(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index < args.Length - 1 ? args[index + 1] : null;
    }

    /// <summary>
    /// Prompts for the main passphrase without echoing it, returning raw UTF-8 bytes the caller
    /// can zero.
    /// <para>
    /// This used to be <c>Console.ReadLine()</c> into a <c>string</c>: the passphrase that
    /// protects every CA private key was echoed to the terminal — into scrollback, screen
    /// shares and session recordings — and then pinned on the managed heap where it could not
    /// be erased. Falls back to echoing only when stdin is redirected, where character-by-
    /// character reading is not available; that path is announced.
    /// </para>
    /// </summary>
    private static byte[] ReadMainPassphraseBytes()
    {
        Console.Write("Enter main passphrase: ");

        if (Console.IsInputRedirected)
        {
            Console.WriteLine();
            Console.Error.WriteLine(
                "[WARNING] stdin is redirected; the passphrase cannot be read without echo.");
            var piped = Console.ReadLine();
            if (string.IsNullOrEmpty(piped))
                throw new InvalidOperationException("Main passphrase is required.");
            return Encoding.UTF8.GetBytes(piped);
        }

        var chars = new List<char>();
        try
        {
            while (true)
            {
                var pressed = Console.ReadKey(intercept: true);
                if (pressed.Key == ConsoleKey.Enter) break;
                if (pressed.Key == ConsoleKey.Backspace)
                {
                    if (chars.Count > 0) chars.RemoveAt(chars.Count - 1);
                    continue;
                }
                if (!char.IsControl(pressed.KeyChar)) chars.Add(pressed.KeyChar);
            }
            Console.WriteLine();

            if (chars.Count == 0)
                throw new InvalidOperationException("Main passphrase is required.");

            return Encoding.UTF8.GetBytes(chars.ToArray());
        }
        finally
        {
            // The List<char> itself still held the secret; clear it before it reaches the GC.
            for (int i = 0; i < chars.Count; i++) chars[i] = '\0';
        }
    }

    /// <summary>
    /// Wraps a DER buffer as PEM. Keystore entries hold either a PKCS#8 private key
    /// (<c>ca-certs.keystore</c>) or an X.509 certificate (<c>ca-trust.keystore</c>); the label
    /// is chosen from the keystore name so the output is directly usable rather than merely
    /// readable.
    /// </summary>
    private static string ToPem(byte[] der, string label)
    {
        var body = Convert.ToBase64String(der);
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).AppendLine("-----");
        for (int i = 0; i < body.Length; i += 64)
            sb.AppendLine(body.Substring(i, Math.Min(64, body.Length - i)));
        sb.Append("-----END ").Append(label).AppendLine("-----");
        return sb.ToString();
    }
}
