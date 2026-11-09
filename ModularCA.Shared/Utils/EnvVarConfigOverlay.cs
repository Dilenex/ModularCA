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

    private readonly Dictionary<string, Func<string?>> _released = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Clears the secret at <paramref name="path"/> (one of the secret paths, e.g.
    /// <c>Hsm.Pin</c>) from <paramref name="config"/> once it has been used, so the running
    /// process no longer holds it as a string. A secret that came from the file is put back for
    /// the length of each <see cref="WithSecretsProtected"/> write, read again through
    /// <paramref name="reread"/>, so rewriting <c>config.yaml</c> keeps it there instead of
    /// writing the cleared value. A secret from the environment is left out of the file as before.
    /// </summary>
    /// <param name="config">The running configuration.</param>
    /// <param name="path">The secret's path.</param>
    /// <param name="reread">Reads the value the file holds now.</param>
    /// <exception cref="ArgumentException"><paramref name="path"/> is not a secret path.</exception>
    public void Release(SystemConfig config, string path, Func<string?> reread)
    {
        var accessor = SecretAccessors.FirstOrDefault(a => string.Equals(a.Path, path, StringComparison.OrdinalIgnoreCase));
        if (accessor.Path == null)
            throw new ArgumentException($"{path} is not a secret path.", nameof(path));
        lock (_persistLock)
        {
            accessor.Setter(config, string.Empty);
            if (!EnvSourcedPaths.Contains(accessor.Path))
                _released[accessor.Path] = reread;
        }
    }

    /// <summary>
    /// Executes <paramref name="body"/> with all env-sourced secret fields temporarily
    /// nulled in <paramref name="config"/>, and every secret cleared by <see cref="Release"/>
    /// temporarily put back from the file, restoring them in a <c>finally</c>. Use this
    /// around any code that serializes <see cref="SystemConfig"/> to disk so env-sourced
    /// secrets do not leak from the running process into <c>config.yaml</c>, and released ones
    /// are not lost from it. If <paramref name="body"/> throws, the exception propagates and the
    /// original values are still restored. Cross-thread-safe via an internal lock.
    /// </summary>
    public void WithSecretsProtected(SystemConfig config, Action body)
    {
        lock (_persistLock)
        {
            var restoreActions = new List<Action>(SecretAccessors.Length);
            try
            {
                foreach (var (path, getter, setter) in SecretAccessors)
                {
                    if (EnvSourcedPaths.Contains(path))
                    {
                        var saved = getter(config);
                        setter(config, null);
                        restoreActions.Add(() => setter(config, saved));
                    }
                    else if (_released.TryGetValue(path, out var reread))
                    {
                        // Read before anything changes: a file that cannot be read stops the write.
                        var fromFile = reread();
                        var saved = getter(config);
                        setter(config, fromFile);
                        restoreActions.Add(() => setter(config, saved));
                    }
                }

                body();
            }
            finally
            {
                foreach (var restore in restoreActions) restore();
            }
        }
    }
}
