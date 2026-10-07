using ModularCA.Shared.Models.Config;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Overlays environment variable values onto secret fields in <see cref="SystemConfig"/>.
/// After YAML config is loaded, this class checks for known env vars and applies any that are set.
/// Tracks which paths were sourced from env vars so PersistConfig() can avoid writing them to disk.
/// </summary>
public class EnvVarConfigOverlay
{
    private readonly HashSet<string> _envSourcedPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Config paths that were populated from environment variables. Read-only to consumers
    /// — the underlying set is mutated only by <see cref="Apply"/> (called once at startup),
    /// keeping the contract clear that runtime code should treat env-sourced paths as
    /// effectively immutable.
    /// </summary>
    public IReadOnlySet<string> EnvSourcedPaths => _envSourcedPaths;

    private static readonly (string EnvVar, string Path, Action<SystemConfig, string> Setter)[] Mappings =
    [
        ("MODULARCA__JWT__SECRET", "JWT.Secret", (c, v) => c.JWT.Secret = v),
        ("MODULARCA__DB__APP__PASSWORD", "DB.App.Password", (c, v) => c.DB.App.Password = v),
        ("MODULARCA__DB__AUDIT__PASSWORD", "DB.Audit.Password", (c, v) => c.DB.Audit.Password = v),
        // SslMode can be overridden from the environment so operators
        // can tighten transport security (e.g. VerifyFull) without editing db.yaml in place.
        // Valid values are translated to Npgsql.SslMode by PostgresConnection.ParseSslMode;
        // unparseable values clamp back to Require at the connection-builder layer.
        ("MODULARCA__DB__APP__SSLMODE", "DB.App.SslMode", (c, v) => c.DB.App.SslMode = v),
        ("MODULARCA__DB__AUDIT__SSLMODE", "DB.Audit.SslMode", (c, v) => c.DB.Audit.SslMode = v),
        ("MODULARCA__LDAPAUTH__BINDPASSWORD", "LdapAuth.BindPassword", (c, v) => c.LdapAuth.BindPassword = v),
        ("MODULARCA__EMAIL__PASSWORD", "Email.Password", (c, v) => c.Email.Password = v),
        ("MODULARCA__EMAIL__OAUTH2CLIENTSECRET", "Email.OAuth2ClientSecret", (c, v) => c.Email.OAuth2ClientSecret = v),
        ("MODULARCA__EMAIL__OAUTH2ACCESSTOKEN", "Email.OAuth2AccessToken", (c, v) => c.Email.OAuth2AccessToken = v),
        ("MODULARCA__EMAIL__OAUTH2CLIENTID", "Email.OAuth2ClientId", (c, v) => c.Email.OAuth2ClientId = v),
        // Note: Https.CertificatePassword is intentionally excluded. The PFX password is a
        // local file artifact that gets regenerated on TLS cert reissue. Overriding it via env
        // var would cause the server to fail on restart after a reissue (env var has old password,
        // PFX on disk has new one).
        ("MODULARCA__INTEGRATIONAPI__APIKEY", "IntegrationApi.ApiKey", (c, v) => c.IntegrationApi.ApiKey = v),
        ("MODULARCA__CERTMANAGER__APIKEY", "CertManager.ApiKey", (c, v) => c.CertManager.ApiKey = v),
        ("MODULARCA__HSM__PIN", "Hsm.Pin", (c, v) => c.Hsm.Pin = v),
    ];

    /// <summary>
    /// Checks each known env var and overlays non-empty values onto the config.
    /// Logs the config path (never the value) for each override applied.
    /// </summary>
    public void Apply(SystemConfig config)
    {
        foreach (var (envVar, path, setter) in Mappings)
        {
            var value = Environment.GetEnvironmentVariable(envVar);
            if (!string.IsNullOrEmpty(value))
            {
                setter(config, value);
                _envSourcedPaths.Add(path);
                Console.WriteLine($"[INF] Config secret overridden from environment variable: {path}");
            }
        }

        if (_envSourcedPaths.Count > 0)
            Console.WriteLine($"[INF] Applied {_envSourcedPaths.Count} secret(s) from environment variables");
    }

    /// <summary>
    /// Master list of secret-bearing config paths and their getter/setter pairs. Used by
    /// <see cref="WithSecretsProtected"/> to temporarily null env-sourced secrets before
    /// serializing <see cref="SystemConfig"/> to disk. Adding a new secret to this list
    /// extends protection to every persist site at once — there is exactly one source of
    /// truth instead of three duplicated <c>Protect(...)</c> blocks across callers.
    /// <para>
    /// Note: <c>Https.CertificatePassword</c> is intentionally absent (matches
    /// <see cref="Mappings"/> exclusion). The PFX password is a per-cert artifact that
    /// must persist to <c>config.yaml</c> so the next process restart can load the PFX.
    /// </para>
    /// </summary>
    private static readonly (string Path, Func<SystemConfig, string?> Getter, Action<SystemConfig, string?> Setter)[] SecretAccessors =
    [
        ("JWT.Secret", c => c.JWT.Secret, (c, v) => c.JWT.Secret = v!),
        ("DB.App.Password", c => c.DB.App.Password, (c, v) => c.DB.App.Password = v!),
        ("DB.Audit.Password", c => c.DB.Audit.Password, (c, v) => c.DB.Audit.Password = v!),
        ("LdapAuth.BindPassword", c => c.LdapAuth.BindPassword, (c, v) => c.LdapAuth.BindPassword = v!),
        ("Email.Password", c => c.Email.Password, (c, v) => c.Email.Password = v!),
        ("Email.OAuth2ClientSecret", c => c.Email.OAuth2ClientSecret, (c, v) => c.Email.OAuth2ClientSecret = v!),
        ("Email.OAuth2AccessToken", c => c.Email.OAuth2AccessToken, (c, v) => c.Email.OAuth2AccessToken = v!),
        ("Email.OAuth2ClientId", c => c.Email.OAuth2ClientId, (c, v) => c.Email.OAuth2ClientId = v!),
        ("IntegrationApi.ApiKey", c => c.IntegrationApi.ApiKey, (c, v) => c.IntegrationApi.ApiKey = v!),
        ("CertManager.ApiKey", c => c.CertManager.ApiKey, (c, v) => c.CertManager.ApiKey = v!),
        ("Hsm.Pin", c => c.Hsm.Pin, (c, v) => c.Hsm.Pin = v!),
    ];

    // Serializes WithSecretsProtected across all callers. The overlay is registered as a
    // singleton and the SystemConfig instance is also a singleton (one per process), so
    // two concurrent operator PUTs from different controllers (AdminConfigController,
    // AdminSchedulerController, WebTlsProvisioningService Stage 2) could otherwise
    // interleave: thread A nulls a secret → thread B serializes (writes null to YAML) →
    // thread B restores → thread A writes (now sees its own null) → corrupted on-disk
    // config or YAML missing secrets entirely. Each individual controller may have its
    // own narrower lock, but only this lock covers cross-controller races.
    private readonly object _persistLock = new();

    /// <summary>
    /// Executes <paramref name="body"/> with all env-sourced secret fields temporarily
    /// nulled in <paramref name="config"/>, restoring them in a <c>finally</c>. Use this
    /// around any code that serializes <see cref="SystemConfig"/> to disk so env-sourced
    /// secrets do not leak from the running process into <c>config.yaml</c>. If
    /// <paramref name="body"/> throws, the exception propagates and the original values
    /// are still restored. Cross-thread-safe via an internal lock.
    /// </summary>
    public void WithSecretsProtected(SystemConfig config, Action body)
    {
        lock (_persistLock)
        {
            var restoreActions = new List<Action>(SecretAccessors.Length);
            foreach (var (path, getter, setter) in SecretAccessors)
            {
                if (EnvSourcedPaths.Contains(path))
                {
                    var saved = getter(config);
                    setter(config, null);
                    restoreActions.Add(() => setter(config, saved));
                }
            }

            try
            {
                body();
            }
            finally
            {
                foreach (var restore in restoreActions) restore();
            }
        }
    }
}
