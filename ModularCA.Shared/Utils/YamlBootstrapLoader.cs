using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Shared.Utils
{
    /// <summary>
    /// Loads CA bootstrap configuration from bootstrap.yaml for unattended setup.
    /// Database credentials are handled separately by <see cref="YamlSetupDatabaseLoader"/> and <see cref="YamlDbConfigLoader"/>.
    /// </summary>
    public static class YamlBootstrapLoader
    {
        /// <summary>
        /// Deserializes a bootstrap.yaml file into a <see cref="BootstrapConfig"/>.
        /// </summary>
        public static BootstrapConfig Load(string path)
        {
            var yaml = File.ReadAllText(path);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(PascalCaseNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            return deserializer.Deserialize<BootstrapConfig>(yaml);
        }

        public class BootstrapConfig
        {
            public CaConfig CA { get; set; } = new();
            public SigningProfileConfig SigningProfile { get; set; } = new();
            public HttpsApiConfig HttpsApi { get; set; } = new();
            public FeaturesConfig Features { get; set; } = new();
        }

        /// <summary>
        /// Feature flags written into the database during bootstrap.
        /// ACME/EST/SCEP/CMP default to <c>false</c> so a first-run install does not expose
        /// enrollment protocols the operator has not explicitly opted into; CRL/OCSP remain
        /// on because a working PKI cannot function without them.
        /// </summary>
        public class FeaturesConfig
        {
            public bool CRL { get; set; } = true;
            public bool OCSP { get; set; } = true;
            public bool ACME { get; set; } = false;
            public bool EST { get; set; } = false;
            public bool SCEP { get; set; } = false;
            public bool CMP { get; set; } = false;
            /// <summary>Windows autoenrollment (MS-WSTEP). Off by default like the other enrollment protocols.</summary>
            public bool MSAE { get; set; } = false;
        }

        /// <summary>
        /// Web TLS certificate configuration loaded from bootstrap.yaml. Controls the
        /// certificate issued for the management UI / API listener at the end of bootstrap.
        /// Class name is retained for backwards compatibility with existing bootstrap.yaml files.
        /// </summary>
        public class HttpsApiConfig
        {
            /// <summary>Common Name (CN) — primary DNS name or hostname of the management UI.</summary>
            public string CN { get; set; } = "ModularCA API";

            /// <summary>Organization (O) — subject DN component. Optional.</summary>
            public string? Organization { get; set; }

            /// <summary>Organizational Unit (OU) — subject DN component. Optional.</summary>
            public string? OrganizationalUnit { get; set; }

            /// <summary>Locality / city (L) — subject DN component. Optional.</summary>
            public string? Locality { get; set; }

            /// <summary>State / province (ST) — subject DN component. Optional.</summary>
            public string? State { get; set; }

            /// <summary>Country (C) — 2-letter ISO-3166 code for the subject DN. Optional.</summary>
            public string? Country { get; set; }

            /// <summary>
            /// Pre-computed full subject DN string. When non-empty this takes precedence over
            /// the individual CN / O / OU / L / ST / C fields in the issuer pipeline. The setup
            /// wizard populates this with the DN that was validated against the ACME request
            /// profile so the issued cert exactly matches what the operator approved.
            /// </summary>
            public string? SubjectDn { get; set; }

            /// <summary>Subject Alternative Names. Each entry is typed as "DNS:host" or "IP:addr".</summary>
            public List<string> SANs { get; set; } = new() { "DNS:localhost", "IP:127.0.0.1" };

            /// <summary>HTTPS port the management UI listens on.</summary>
            public int Port { get; set; } = 8443;

            /// <summary>
            /// Plain-HTTP port used for CRL, OCSP and AIA distribution. Set to 0 to disable plain
            /// HTTP, in which case no CDP/AIA URL is embedded in issued certificates.
            /// <para>
            /// This was previously hardcoded as <c>8080</c> where config.yaml is written and not
            /// represented here at all, so the AIA/CDP builder had nothing correct to read and
            /// pointed at the TLS port instead. It is a config field now so the listener and the
            /// URLs embedded in certificates come from one value.
            /// </para>
            /// </summary>
            public int HttpPort { get; set; } = 8080;

            /// <summary>
            /// Web TLS certificate validity in days. Default 397 — the CA/Browser Forum maximum
            /// for publicly-trusted server certificates (effective 2020). The issuing signing
            /// profile may enforce a shorter ceiling.
            /// </summary>
            public int ValidityDays { get; set; } = 397;
        }

        public class CaConfig
        {
            public string Algorithm { get; set; } = "RSA";
            public int KeySize { get; set; } = 4096;
            public int ValidityYears { get; set; } = 10;
            public CaSubjectConfig Subject { get; set; } = new();
        }

        public class CaSubjectConfig
        {
            public string? CN { get; set; }
            public string? O { get; set; }
            public List<string>? OU { get; set; }
            public List<string>? DC { get; set; }
            public string? L { get; set; }
            public string? ST { get; set; }
            public string? C { get; set; }
        }

        public class SigningProfileConfig
        {
            public string Name { get; set; } = "default";
            public bool IsCa { get; set; } = true;
            public List<string>? KeyUsages { get; set; }
            public List<string>? ExtendedKeyUsages { get; set; }
        }
    }
}
