namespace ModularCA.Shared.Models.Setup;

/// <summary>
/// Request model for the initial system setup wizard.
/// Contains all configuration needed to bootstrap a new ModularCA instance.
/// </summary>
public class SetupRequest
{
    public SetupOrganization Organization { get; set; } = new();
    public SetupRootCa RootCa { get; set; } = new();
    public SetupAdmin Admin { get; set; } = new();
    public SetupFeatures Features { get; set; } = new();
    public SetupWebTlsCertificate WebTlsCertificate { get; set; } = new();
    public SetupDatabase Database { get; set; } = new();
    public SetupSecurity Security { get; set; } = new();
    public SetupNetwork Network { get; set; } = new();
}

/// <summary>
/// Organization / tenant details for the setup wizard.
/// </summary>
public class SetupOrganization
{
    /// <summary>Organization/tenant name (e.g., "Acme Corp").</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description for the tenant.</summary>
    public string? Description { get; set; }
}

/// <summary>
/// Root CA certificate subject and key configuration for the setup wizard.
/// </summary>
public class SetupRootCa
{
    /// <summary>Root CA Common Name (e.g., "Acme Corp Root CA").</summary>
    public string CommonName { get; set; } = string.Empty;

    /// <summary>Organization name for the CA subject (usually same as tenant name).</summary>
    public string Organization { get; set; } = string.Empty;

    /// <summary>Organizational unit (optional).</summary>
    public string? OrganizationalUnit { get; set; }

    /// <summary>Locality/city (optional).</summary>
    public string? Locality { get; set; }

    /// <summary>State/province (optional).</summary>
    public string? State { get; set; }

    /// <summary>2-letter country code (optional).</summary>
    public string? Country { get; set; }

    /// <summary>Key algorithm: RSA, ECDSA, Ed25519, etc.</summary>
    [System.Text.Json.Serialization.JsonPropertyName("keyAlgorithm")]
    public string Algorithm { get; set; } = "ECDSA";

    /// <summary>
    /// Key size / parameter set. String-typed so it can carry the full range of algorithm
    /// parameters without information loss:
    /// <list type="bullet">
    ///   <item><c>"2048"</c>, <c>"3072"</c>, <c>"4096"</c>, <c>"7680"</c>, <c>"8192"</c> for RSA</item>
    ///   <item><c>"P-256"</c>, <c>"P-384"</c>, <c>"P-521"</c> (or <c>"256"</c>/<c>"384"</c>/<c>"521"</c>) for ECDSA</item>
    ///   <item><c>null</c> / empty for Ed25519 / Ed448 (no parameter)</item>
    ///   <item><c>null</c> / empty for ML-DSA / SLH-DSA when the variant is encoded in <see cref="Algorithm"/> (e.g. <c>"SLH-DSA-SHA2-128F"</c>)</item>
    /// </list>
    /// Bootstrap readers convert this to the int form expected by
    /// <c>CertificateRequestModel.KeySize</c> via <see cref="SetupKeySizeParser.ParseToInt"/>.
    /// </summary>
    public string? KeySize { get; set; } = "384";

    /// <summary>CA certificate validity in years.</summary>
    public int ValidityYears { get; set; } = 10;
}

/// <summary>
/// Initial admin user configuration for the setup wizard.
/// </summary>
public class SetupAdmin
{
    public string Username { get; set; } = "superadmin";
    public string? Password { get; set; }
    public string? Email { get; set; }
}

/// <summary>
/// Protocol feature flags to enable/disable during initial setup.
/// CRL and OCSP stay on by default because every working PKI needs them;
/// ACME/EST/SCEP/CMP default to <c>false</c> so a first-run install does not expose an
/// enrollment surface the operator has not explicitly opted into. The wizard lets the
/// operator re-enable any of them per protocol.
/// </summary>
public class SetupFeatures
{
    [System.Text.Json.Serialization.JsonPropertyName("enableCrl")]
    public bool Crl { get; set; } = true;
    [System.Text.Json.Serialization.JsonPropertyName("enableOcsp")]
    public bool Ocsp { get; set; } = true;
    [System.Text.Json.Serialization.JsonPropertyName("enableAcme")]
    public bool Acme { get; set; } = false;
    [System.Text.Json.Serialization.JsonPropertyName("enableEst")]
    public bool Est { get; set; } = false;
    [System.Text.Json.Serialization.JsonPropertyName("enableScep")]
    public bool Scep { get; set; } = false;
    [System.Text.Json.Serialization.JsonPropertyName("enableCmp")]
    public bool Cmp { get; set; } = false;
    /// <summary>Windows autoenrollment (MS-WSTEP over HTTPS).</summary>
    [System.Text.Json.Serialization.JsonPropertyName("enableMsae")]
    public bool Msae { get; set; } = false;
}

/// <summary>
/// Web TLS certificate configuration for the setup wizard. This cert is issued at the end of
/// bootstrap using the "Web TLS (Internal)" request profile + Main Certificate Profile + the
/// signing profile of the user-created (non-system) CA. All subject/SAN/validity fields are
/// operator-editable in the setup wizard and validated against the request profile rules
/// before issuance. Subject-DN fields default to empty so the wizard never silently inserts
/// a placeholder organization or locale into the cert — operators must explicitly opt in.
/// </summary>
public class SetupWebTlsCertificate
{
    /// <summary>Common Name (CN) — primary DNS name or hostname of the management UI.</summary>
    public string CommonName { get; set; } = "modularca.local";

    /// <summary>Organization (O). Empty by default; the wizard never silently inserts an O field.</summary>
    public string Organization { get; set; } = "";

    /// <summary>Organizational Unit (OU). Empty by default; the wizard never silently inserts an OU field.</summary>
    public string OrganizationalUnit { get; set; } = "";

    /// <summary>Locality / city (L).</summary>
    public string Locality { get; set; } = "";

    /// <summary>State or province (ST).</summary>
    public string State { get; set; } = "";

    /// <summary>Country (C) — 2-letter ISO-3166 code.</summary>
    public string Country { get; set; } = "US";

    /// <summary>Subject Alternative Names. Each entry is typed as "DNS:host" or "IP:addr".
    /// Default seed is <c>localhost</c> + the host loopbacks; <c>SetupController.GetDefaults</c>
    /// merges <see cref="System.Net.Dns.GetHostName"/> and the incoming <c>Host</c> header at
    /// request time so the operator does not have to type the wizard's own hostname to avoid
    /// the issued Web TLS cert failing browser hostname verification.</summary>
    public List<string> Sans { get; set; } = new() { "DNS:localhost", "IP:127.0.0.1" };

    /// <summary>Key algorithm for the Web TLS certificate key pair (e.g., ECDSA, RSA).</summary>
    public string KeyAlgorithm { get; set; } = "ECDSA";

    /// <summary>Key size in bits (e.g., 256 for ECDSA P-256, 2048 for RSA).</summary>
    public int KeySize { get; set; } = 256;

    /// <summary>
    /// Validity in days. Default 397 — the CA/Browser Forum maximum for publicly-trusted
    /// server certificates (effective 2020). The issuing signing profile may enforce a shorter
    /// ceiling; validation happens at bootstrap time against the "Web TLS (Internal)" request
    /// profile.
    /// </summary>
    public int ValidityDays { get; set; } = 397;
}

/// <summary>
/// Database connection configuration for the setup wizard.
/// </summary>
public class SetupDatabase
{
    public string RootHost { get; set; } = "localhost";
    public int RootPort { get; set; } = 3306;
    public string RootUsername { get; set; } = "root";
    public string RootPassword { get; set; } = string.Empty;
    public string AppDatabase { get; set; } = "modularca-app";
    public string AppUsername { get; set; } = "modularca_app";
    public string AuditDatabase { get; set; } = "modularca-audit";
    public string AuditUsername { get; set; } = "modularca_audit";

    /// <summary>
    /// TLS mode for the MySQL connection selected by the operator in the setup wizard.
    /// Propagates into <c>setup-database.yaml</c> and ultimately <c>db.yaml</c> so runtime
    /// connections honor the same policy. Valid values: <c>"None"</c>, <c>"Preferred"</c>,
    /// <c>"Required"</c>, <c>"VerifyCA"</c>, <c>"VerifyFull"</c>. Defaults to
    /// <c>"Required"</c> to use encrypted transport on fresh installs.
    /// </summary>
    public string SslMode { get; set; } = "Required";

    /// <summary>
    /// When true, the audit database is dropped and recreated during setup, discarding any
    /// history from a previous install. Defaults to false: audit rows survive a reinstall,
    /// which is what makes them tamper-evidence rather than a log the next install erases.
    /// <para>
    /// Only meaningful when re-running setup over a host that already holds an audit database —
    /// on a genuinely fresh machine there is nothing to preserve either way.
    /// </para>
    /// </summary>
    public bool WipeAuditDatabase { get; set; }
}

/// <summary>
/// Security-related settings for the setup wizard (Step 6).
/// Covers login lockout, JWT, Swagger, WebAuthn, and backup scheduling.
/// </summary>
public class SetupSecurity
{
    /// <summary>
    /// Maximum consecutive failed login attempts before lockout. Seeded into the
    /// <c>SecurityPolicy</c> table (not config.yaml) — operators can tune this
    /// post-setup via <c>PUT /api/v1/admin/security-policy</c>.
    /// </summary>
    public int MaxFailedLoginAttempts { get; set; } = 5;

    /// <summary>
    /// Duration in minutes a locked-out account remains locked. Seeded into the
    /// <c>SecurityPolicy</c> table (not config.yaml).
    /// </summary>
    public int LockoutMinutes { get; set; } = 15;

    /// <summary>JWT access-token lifetime in minutes.</summary>
    public int JwtExpirationMinutes { get; set; } = 30;

    /// <summary>Whether the Swagger/OpenAPI UI is exposed. Defaults to false to minimize the exposed surface; admins opt in via the setup wizard or PUT /admin/config.</summary>
    public bool SwaggerEnabled { get; set; } = false;

    /// <summary>Whether WebAuthn (FIDO2) passwordless login is enabled.</summary>
    public bool WebAuthnEnabled { get; set; } = true;

    /// <summary>Whether automated backups are enabled.</summary>
    public bool BackupEnabled { get; set; } = true;

    /// <summary>Cron expression for the backup schedule.</summary>
    public string BackupSchedule { get; set; } = "0 2 * * *";
}

/// <summary>
/// Network and infrastructure settings for the setup wizard (Step 7).
/// Owns the public-host identity (<see cref="PublicDomain"/>) and all transport ports —
/// the Kestrel bind ports (<see cref="HttpPort"/>, <see cref="HttpsPort"/>) and the
/// public-facing ports clients actually connect to (<see cref="HttpPublicPort"/>,
/// <see cref="HttpsPublicPort"/>) which differ when behind a reverse proxy.
/// Also covers listen address, mTLS toggle/subdomain, backup storage, and logging.
/// </summary>
public class SetupNetwork
{
    /// <summary>IP address the HTTPS listener binds to.</summary>
    public string ListenAddress { get; set; } = "0.0.0.0";

    /// <summary>
    /// Whether mTLS client-certificate login is enabled. Seeded into
    /// <c>Mtls.Enabled</c> in config.yaml. Can be flipped post-setup via the admin UI.
    /// </summary>
    public bool MtlsEnabled { get; set; } = false;

    /// <summary>
    /// Subdomain used for mTLS authentication (e.g., "mtls" or "mtls.ca.example.com").
    /// SNI-gated on the main HTTPS listener — no separate port needed. Requires DNS
    /// and a Web TLS cert SAN covering this hostname.
    /// </summary>
    public string MtlsAuthSubdomain { get; set; } = string.Empty;

    /// <summary>Directory path where backup archives are written.</summary>
    public string BackupOutputPath { get; set; } = "backups";

    /// <summary>Number of backup archives to retain before oldest are pruned.</summary>
    public int BackupRetentionCount { get; set; } = 10;

    /// <summary>Minimum log level (Verbose, Debug, Information, Warning, Error, Fatal).</summary>
    public string LogLevel { get; set; } = "Information";

    /// <summary>Number of days to retain log files before deletion.</summary>
    public int LogRetentionDays { get; set; } = 30;

    /// <summary>
    /// Public domain (hostname or IP) used to build HTTP/HTTPS base URLs for AIA, CDP,
    /// OCSP, ACME, and management-UI redirects. Bare hostname only — no scheme, no path.
    /// Embedded into the issued Web TLS cert as a SAN by the wizard's derivation logic.
    /// </summary>
    public string? PublicDomain { get; set; }

    /// <summary>
    /// HTTP bind port for Kestrel (CRL/OCSP/AIA plain-HTTP listener). Default 8080.
    /// Set to 0 to disable plain HTTP. The cert doesn't care about this port (TLS embeds
    /// no port info); it's strictly a transport-layer concern.
    /// </summary>
    public int HttpPort { get; set; } = 8080;

    /// <summary>
    /// HTTPS bind port for the Kestrel listener. Default 8443. Issued Web TLS cert SANs
    /// must be reachable on this port for hostname verification to succeed.
    /// </summary>
    public int HttpsPort { get; set; } = 8443;

    /// <summary>
    /// Public-facing HTTP port that clients connect to for CRL/OCSP/AIA. May differ from
    /// <see cref="HttpPort"/> when behind a reverse proxy (proxy on 80, Kestrel on 8080).
    /// Used to build AIA/CDP URLs embedded in certificates. When null, falls back to
    /// <see cref="HttpPort"/>.
    /// </summary>
    public int? HttpPublicPort { get; set; }

    /// <summary>
    /// Public-facing HTTPS port that clients connect to. May differ from
    /// <see cref="HttpsPort"/> when behind a reverse proxy. Used to build management-UI URLs,
    /// ACME directory URLs, and the WebAuthn origin. When null, falls back to
    /// <see cref="HttpsPort"/>.
    /// </summary>
    public int? HttpsPublicPort { get; set; }
}

/// <summary>
/// Response model returned after setup initialization completes.
/// </summary>
public class SetupResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? AdminUsername { get; set; }
    public string? AdminPassword { get; set; }
    public List<string> Warnings { get; set; } = new();
}

/// <summary>
/// Response model for the GET /api/v1/setup/defaults endpoint.
/// </summary>
public class SetupDefaultsResponse
{
    public List<string> Algorithms { get; set; } = new();
    public List<string> KeySizes { get; set; } = new();
    public List<string> SignatureAlgorithms { get; set; } = new();
    public SetupRootCa DefaultRootCa { get; set; } = new();
    public SetupFeatures DefaultFeatures { get; set; } = new();
    public SetupWebTlsCertificate DefaultWebTlsCertificate { get; set; } = new();
}

/// <summary>
/// Normalises the string-typed <see cref="SetupRootCa.KeySize"/> into the integer form expected by
/// <c>CertificateRequestModel.KeySize</c> and the downstream key-generation path. ECDSA "P-256" /
/// "P-384" / "P-521" map to their bit sizes. RSA digits parse directly. Ed25519 / Ed448 and PQC
/// parameter sets (where the variant is encoded in the algorithm name — e.g.
/// <c>"SLH-DSA-SHA2-128F"</c>) return <c>0</c>; the key-generation code ignores the integer size
/// for those algorithms and selects the parameter set from the algorithm name instead.
/// </summary>
public static class SetupKeySizeParser
{
    /// <summary>
    /// Parses a setup-wizard key-size string for the given algorithm into the integer form the
    /// bootstrap certificate-request pipeline expects. Null / empty strings fall back to the
    /// algorithm's natural default (RSA → 2048, ECDSA → 256, everything else → 0).
    /// </summary>
    public static int ParseToInt(string algorithm, string? keySize)
    {
        var upper = (algorithm ?? string.Empty).ToUpperInvariant();

        if (string.IsNullOrWhiteSpace(keySize))
        {
            if (upper == "RSA") return 2048;
            if (upper == "ECDSA") return 256;
            return 0;
        }

        if (upper == "ECDSA")
        {
            return keySize.ToUpperInvariant() switch
            {
                "P-256" or "SECP256R1" => 256,
                "P-384" or "SECP384R1" => 384,
                "P-521" or "SECP521R1" => 521,
                _ => int.TryParse(keySize, out var n) ? n : 256,
            };
        }

        // RSA / EdDSA / PQC: direct parse first. If the string carries a PQC variant suffix
        // (e.g. "128f") the algorithm name is what actually selects the parameter set inside
        // KeyGenerationUtil, so stripping to digits still yields a well-formed int.
        if (int.TryParse(keySize, out var parsed))
            return parsed;

        var digits = new string(keySize.Where(char.IsDigit).ToArray());
        if (int.TryParse(digits, out var digitsOnly))
            return digitsOnly;

        return upper == "RSA" ? 2048 : 0;
    }

    /// <summary>
    /// Resolves the canonical key-algorithm string expected by <c>KeyGenerationUtil</c> and
    /// <c>KeyAlgorithmPolicy</c> from the wizard's (family, variant) pair. Expands the ML-DSA
    /// and SLH-DSA family names — which the UI sends as bare <c>"ML-DSA"</c> / <c>"SLH-DSA"</c>
    /// with the parameter set in <see cref="SetupRootCa.KeySize"/> (e.g. <c>"65"</c>,
    /// <c>"128f"</c>) — into the fully-qualified BouncyCastle name (<c>"ML-DSA-65"</c>,
    /// <c>"SLH-DSA-SHA2-128F"</c>). Algorithms whose variant is not carried in keySize
    /// (RSA, ECDSA, Ed25519, Ed448, already-qualified PQC names) pass through unchanged.
    /// </summary>
    public static string ResolveAlgorithm(string algorithm, string? keySize)
    {
        if (string.IsNullOrWhiteSpace(algorithm)) return algorithm ?? string.Empty;
        var upper = algorithm.ToUpperInvariant();

        if (upper == "ML-DSA" && !string.IsNullOrWhiteSpace(keySize))
        {
            // Accept "44" / "65" / "87".
            var digits = new string(keySize.Where(char.IsDigit).ToArray());
            return digits switch
            {
                "44" => "ML-DSA-44",
                "65" => "ML-DSA-65",
                "87" => "ML-DSA-87",
                _ => "ML-DSA-65",
            };
        }

        if (upper == "SLH-DSA" && !string.IsNullOrWhiteSpace(keySize))
        {
            // Accept SHA2 variants "128f" / "128s" / "192f" / "192s" / "256f" / "256s".
            return keySize.ToUpperInvariant() switch
            {
                "128F" => "SLH-DSA-SHA2-128F",
                "128S" => "SLH-DSA-SHA2-128S",
                "192F" => "SLH-DSA-SHA2-192F",
                "192S" => "SLH-DSA-SHA2-192S",
                "256F" => "SLH-DSA-SHA2-256F",
                "256S" => "SLH-DSA-SHA2-256S",
                _ => "SLH-DSA-SHA2-128F",
            };
        }

        return algorithm;
    }
}
