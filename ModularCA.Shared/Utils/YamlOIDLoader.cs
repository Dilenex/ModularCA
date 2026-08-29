using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Shared.Utils
{
    /// <summary>
    /// Loads OID seed configuration (standard and extended key usage) from a YAML file.
    /// Falls back to a built-in default set if the file is missing.
    /// </summary>
    public static class YamlOIDLoader
    {
        /// <summary>
        /// Reads and deserializes an OID seed configuration from the specified YAML file path.
        /// If the file does not exist, returns the built-in default OID set.
        /// </summary>
        public static OIDSeedConfig Load(string path)
        {
            if (!File.Exists(path))
                return GetDefaultOIDConfig();

            var yaml = File.ReadAllText(path);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(PascalCaseNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            return deserializer.Deserialize<OIDSeedConfig>(yaml);
        }

        /// <summary>
        /// Returns a built-in OID configuration with standard key usage and extended key usage OIDs.
        /// Used as a fallback when OIDSeed.yaml is not present (e.g., Docker deployments, setup wizard).
        /// </summary>
        public static OIDSeedConfig GetDefaultOIDConfig()
        {
            return new OIDSeedConfig
            {
                OID = new OID
                {
                    StandardKeyUsage = new Dictionary<string, string>
                    {
                        ["digitalSignature"] = "2.5.29.15.0",
                        ["nonRepudiation"] = "2.5.29.15.1",
                        ["keyEncipherment"] = "2.5.29.15.2",
                        ["dataEncipherment"] = "2.5.29.15.3",
                        ["keyAgreement"] = "2.5.29.15.4",
                        ["keyCertSign"] = "2.5.29.15.5",
                        ["crlSign"] = "2.5.29.15.6",
                        ["encipherOnly"] = "2.5.29.15.7",
                        ["decipherOnly"] = "2.5.29.15.8",
                    },
                    ExtendedKeyUsage = new Dictionary<string, string>
                    {
                        ["serverAuth"] = "1.3.6.1.5.5.7.3.1",
                        ["clientAuth"] = "1.3.6.1.5.5.7.3.2",
                        ["codeSigning"] = "1.3.6.1.5.5.7.3.3",
                        ["emailProtection"] = "1.3.6.1.5.5.7.3.4",
                        ["timeStamping"] = "1.3.6.1.5.5.7.3.8",
                        ["OCSPSigning"] = "1.3.6.1.5.5.7.3.9",
                        ["smartcardLogon"] = "1.3.6.1.4.1.311.20.2.2",
                        // Kerberos PKINIT KDC authentication (RFC 4556 id-pkinit-KPKdc).
                        // A domain controller must hold a certificate carrying this before it
                        // will accept smart-card logon; without one PKINIT fails at the KDC with
                        // KDC_ERR_PADATA_TYPE_NOSUPP, which reads as a client problem and is not.
                        ["kdcAuthentication"] = "1.3.6.1.5.2.3.5",
                    }
                }
            };
        }

        public class OIDSeedConfig
        {
            public OID OID { get; set; } = new();
        }

        public class OID
        {
            public Dictionary<string, string>? StandardKeyUsage { get; set; } = new();
            public Dictionary<string, string>? ExtendedKeyUsage { get; set; } = new();
        }
    }
}
