using System.Text;
using System.Text.Json;
using YamlDotNet.RepresentationModel;

namespace ModularCA.Keystore.Config
{
    /// <summary>
    /// Loads per-keystore secondary passphrases. Resolution order is:
    /// (1) the <c>MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE</c> environment variable when set —
    /// either a JSON map of <c>{"keystoreName": "passphrase"}</c> or a single literal applied
    /// to every keystore; and (2) the on-disk YAML file at <c>config/keystore.yaml</c> as a
    /// bootstrap-only fallback.
    /// </summary>
    /// <remarks>
    /// The on-disk YAML file is required to bootstrap a brand new install (the
    /// secondary passphrase is generated before any operator can set an env var). After
    /// bootstrap the operator should export <c>MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE</c>
    /// and remove or tighten <c>config/keystore.yaml</c>. The runtime path logs a one-time
    /// startup banner indicating which source supplied the passphrase so operators can
    /// verify the env var is being honored.
    /// </remarks>
    public static class KeystoreYamlLoader
    {
        /// <summary>
        /// Environment variable name consulted before reading the on-disk YAML file.
        /// May be set to a JSON object (<c>{"ca-certs.keystore": "..."}</c>) or a single
        /// literal passphrase that is applied to every keystore lookup.
        /// </summary>
        public const string SecondaryPassphraseEnvVar = "MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE";

        private static int _bannerLogged;

        /// <summary>
        /// Retrieves the secondary passphrase for the specified keystore name.
        /// Environment variable wins over the on-disk YAML file. Returns the literal
        /// string assigned to the keystore name in the YAML file, or the env var value
        /// if it is a single literal. Throws <see cref="KeyNotFoundException"/> if no
        /// source contains a passphrase for the keystore. <c>ssh-ca.keystore</c> has no entry of
        /// its own in either source: it shares the secondary passphrase of
        /// <c>ca-certs.keystore</c>, and that is the entry looked up for it.
        /// </summary>
        /// <param name="yamlPath">Filesystem path to the keystore.yaml fallback file.</param>
        /// <param name="keystoreName">The keystore identifier (file name) to look up.</param>
        public static string LoadSecondaryPassphrase(string yamlPath, string keystoreName)
        {
            var key = Path.GetFileName(keystoreName);
            if (string.Equals(key, ModularCA.Shared.Signing.KeyRef.SshKeystore, StringComparison.Ordinal))
                key = ModularCA.Shared.Signing.KeyRef.DefaultKeystore;

            // Source 1: environment variable
            var envValue = Environment.GetEnvironmentVariable(SecondaryPassphraseEnvVar);
            if (!string.IsNullOrEmpty(envValue))
            {
                var resolved = TryResolveFromEnv(envValue, key);
                if (resolved != null)
                {
                    LogBannerOnce("environment variable " + SecondaryPassphraseEnvVar);
                    return resolved;
                }
                // Env var is set but does not contain this specific keystore — fall through
                // to the YAML file. Do NOT throw; the env var may legitimately scope only
                // to a subset of keystores during a phased rollout.
            }

            // Source 2: on-disk YAML (bootstrap fallback)
            if (!File.Exists(yamlPath))
                throw new FileNotFoundException(
                    $"Secondary passphrase for '{key}' could not be resolved: env var '{SecondaryPassphraseEnvVar}' " +
                    $"is unset (or does not contain this keystore) and YAML fallback '{yamlPath}' does not exist.");

            using var reader = new StreamReader(yamlPath, Encoding.UTF8);

            var yaml = new YamlStream();
            yaml.Load(reader);

            if (yaml.Documents.Count == 0)
                throw new InvalidDataException("YAML file is empty or malformed");

            var root = (YamlMappingNode)yaml.Documents[0].RootNode;

            foreach (var entry in root.Children)
            {
                var currentKey = ((YamlScalarNode)entry.Key).Value;
                if (currentKey == key)
                {
                    LogBannerOnce("on-disk file " + yamlPath);
                    // Refuse to return an empty / whitespace-only passphrase.
                    // A blank value in YAML (operator typo or a partially-written file)
                    // used to silently become the empty string, which produced a
                    // deterministic scrypt key — a catastrophic misconfiguration. Now the
                    // loader fails loud so the operator must fix the file.
                    var raw = ((YamlScalarNode)entry.Value).Value;
                    if (string.IsNullOrWhiteSpace(raw))
                        throw new InvalidDataException(
                            $"Secondary passphrase for '{key}' in {yamlPath} is empty or whitespace. " +
                            "A blank passphrase produces a deterministic key and is refused. " +
                            $"Set {SecondaryPassphraseEnvVar} or populate the YAML with a real value.");
                    return raw;
                }
            }

            throw new KeyNotFoundException($"Secondary passphrase for '{key}' not found in {yamlPath}");
        }

        /// <summary>
        /// Parses the env var value as either a JSON map (<c>{"name":"value"}</c>) or a literal
        /// string applied to every lookup. Returns <c>null</c> when the env var is a JSON map
        /// that does not contain an entry for <paramref name="keystoreName"/>.
        /// </summary>
        private static string? TryResolveFromEnv(string envValue, string keystoreName)
        {
            var trimmed = envValue.TrimStart();
            if (trimmed.StartsWith('{'))
            {
                try
                {
                    using var doc = JsonDocument.Parse(envValue);
                    if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                        doc.RootElement.TryGetProperty(keystoreName, out var node) &&
                        node.ValueKind == JsonValueKind.String)
                    {
                        return node.GetString();
                    }
                    return null;
                }
                catch (JsonException)
                {
                    // Fall through to literal interpretation.
                }
            }

            // Single literal — apply to every keystore.
            return envValue;
        }

        private static void LogBannerOnce(string source)
        {
            if (System.Threading.Interlocked.Exchange(ref _bannerLogged, 1) == 0)
            {
                Console.WriteLine($"[STARTUP] Keystore secondary passphrase loaded from {source}");
            }
        }
    }
}
