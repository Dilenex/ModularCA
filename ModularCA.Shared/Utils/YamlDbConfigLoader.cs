using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Loads and writes runtime database credentials from/to db.yaml.
/// This file is generated during setup and survives resets.
/// </summary>
public static class YamlDbConfigLoader
{
    public static DbYamlConfig? Load(string path)
    {
        if (!File.Exists(path)) return null;
        var yaml = File.ReadAllText(path);
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        return deserializer.Deserialize<DbYamlConfig>(yaml);
    }

    public static void Write(string path, DbYamlConfig config)
    {
        var serializer = new SerializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .Build();
        var yaml = "# Auto-generated runtime database credentials — do not edit unless you know what you're doing\n"
            + serializer.Serialize(config);
        File.WriteAllText(path, yaml);
        FileSecurityUtil.SetOwnerOnly(path);
    }

    public class DbYamlConfig
    {
        public DbInstanceConfig App { get; set; } = new();
        public DbInstanceConfig Audit { get; set; } = new();
    }

    public class DbInstanceConfig
    {
        public string Host { get; set; } = "localhost";

        /// <summary>Server port. Defaults to PostgreSQL's 5432.</summary>
        public int Port { get; set; } = 5432;
        public string Database { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// TLS mode for the PostgreSQL connection. Round-trips to/from db.yaml. Accepts both
        /// the Npgsql spellings (<c>"Disable"</c>, <c>"Allow"</c>, <c>"Prefer"</c>,
        /// <c>"Require"</c>) and the MySQL ones this file used to carry (<c>"None"</c>,
        /// <c>"Preferred"</c>, <c>"Required"</c>), plus <c>"VerifyCA"</c> and
        /// <c>"VerifyFull"</c>. Defaults to <c>"Require"</c> so fresh installs get encrypted
        /// transport by default.
        /// </summary>
        public string SslMode { get; set; } = "Require";
    }
}
