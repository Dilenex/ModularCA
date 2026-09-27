using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Loads one-time setup database credentials from setup-database.yaml.
/// This file contains root DB creds and is deleted after successful setup.
/// </summary>
public static class YamlSetupDatabaseLoader
{
    /// <summary>
    /// Literal placeholder strings that ship in the <c>setup-database.yaml.example</c> /
    /// <c>BootstrapConfig.yaml.example</c> files. If an operator copies the example in place
    /// and forgets to edit the password line, the load-time validator below trips immediately
    /// with a clear error instead of surfacing the bootstrap as a confusing PostgreSQL "password
    /// authentication failed" error.
    /// </summary>
    private static readonly string[] PlaceholderPasswords = new[]
    {
        "your-superuser-password-here",
        "your-root-password-here",
        "REPLACE-WITH-ROOT-PASSWORD",
        "changeme",
    };

    /// <summary>
    /// Deserializes the supplied <c>setup-database.yaml</c> file. Returns <c>null</c> when the
    /// file does not exist. Throws <see cref="InvalidOperationException"/> when the root password
    /// still contains one of the example placeholder strings.
    /// </summary>
    public static SetupDatabaseConfig? Load(string path)
    {
        if (!File.Exists(path)) return null;
        var yaml = File.ReadAllText(path);
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        var config = deserializer.Deserialize<SetupDatabaseConfig>(yaml);
        if (config?.SqlRoot?.Password != null && IsPlaceholderPassword(config.SqlRoot.Password))
        {
            throw new InvalidOperationException(
                $"setup-database.yaml at '{path}' still contains the example placeholder " +
                $"password ('{config.SqlRoot.Password}'). Replace SqlRoot.Password with the real " +
                "superuser database credentials before running bootstrap.");
        }
        return config;
    }

    /// <summary>
    /// Returns true when <paramref name="password"/> exactly matches one of the example
    /// placeholder strings shipped in the .example files. Comparison is ordinal and
    /// case-insensitive to defend against copy/paste with altered case.
    /// </summary>
    public static bool IsPlaceholderPassword(string? password)
    {
        if (string.IsNullOrEmpty(password)) return false;
        foreach (var placeholder in PlaceholderPasswords)
        {
            if (string.Equals(password, placeholder, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Writes a <see cref="SetupDatabaseConfig"/> to the specified path as YAML.
    /// </summary>
    public static void Write(string path, SetupDatabaseConfig config)
    {
        var serializer = new SerializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .Build();
        File.WriteAllText(path, serializer.Serialize(config));
        FileSecurityUtil.SetOwnerOnly(path);
    }

    public class SetupDatabaseConfig
    {
        public SqlConnectionConfig SqlRoot { get; set; } = new();
        public SqlConnectionConfig SqlApp { get; set; } = new();
        public SqlConnectionConfig SqlAudit { get; set; } = new();
    }

    public class SqlConnectionConfig
    {
        public string Host { get; set; } = "localhost";
        public int Port { get; set; } = 5432;
        public string Database { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// TLS mode captured from the setup wizard and persisted to <c>setup-database.yaml</c>.
        /// Copied into <c>db.yaml</c> during bootstrap so runtime connections honor the operator's
        /// choice. Valid values: <c>"None"</c>, <c>"Preferred"</c>, <c>"Required"</c>,
        /// <c>"VerifyCA"</c>, <c>"VerifyFull"</c>. Defaults to <c>"Required"</c>.
        /// </summary>
        public string SslMode { get; set; } = "Require";
    }
}
