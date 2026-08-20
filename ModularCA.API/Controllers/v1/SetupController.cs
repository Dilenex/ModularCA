using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Middleware;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Shared.Models.Setup;
using ModularCA.Shared.Utils;
using Serilog;

namespace ModularCA.API.Controllers.v1;

/// <summary>
/// Unauthenticated setup wizard endpoints for initial system configuration.
/// All endpoints return 404 once the system has been configured (at least one CA exists).
/// Explicit <see cref="AllowAnonymousAttribute"/> so the global
/// <c>FallbackPolicy</c> does not block the wizard before the first user exists.
/// </summary>
[ApiController]
[Route("api/v1/setup")]
[AllowAnonymous]
public class SetupController(ModularCADbContext db, IHostApplicationLifetime appLifetime, IServiceProvider serviceProvider) : ControllerBase
{
    /// <summary>
    /// Process-wide serialization gate for <see cref="Initialize"/>.
    /// A second concurrent caller returns HTTP 409 Conflict immediately so two parallel
    /// POST bodies cannot both execute <c>BootstrapService.RunFromSetupRequest</c> and
    /// race each other's <c>EnsureDeleted</c> / <c>Migrate</c> / keystore writes. The
    /// MySQL advisory lock below layers defense-in-depth for multi-instance deployments.
    /// </summary>
    private static readonly System.Threading.SemaphoreSlim _initializeLock = new(1, 1);
    /// <summary>
    /// Returns the SHA-256 fingerprint of the setup-mode self-signed
    /// Web TLS certificate that is currently being served. The operator compares this value
    /// to the fingerprint the server prints on its console at boot (and to the browser's
    /// cert-details dialog) to detect MITM on the first contact of the wizard. Only reachable
    /// when the system is unconfigured; returns 404 once bootstrap has completed.
    /// </summary>
    /// <summary>
    /// KC-11: Defense-in-depth localhost check. Even if the setup-mode middleware is
    /// misconfigured or bypassed, each endpoint rejects non-loopback callers directly.
    /// Returns a 403 result when the caller is not on localhost, or null when access is allowed.
    /// Also validates the one-time setup token from the <c>X-Setup-Token</c> header when
    /// a token has been configured (i.e., the server is running in setup mode).
    /// </summary>
    private IActionResult? RejectNonLocalRequest()
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress;
        if (remoteIp == null) return null;

        // Always allow loopback
        if (IPAddress.IsLoopback(remoteIp) || remoteIp.Equals(IPAddress.IPv6Loopback))
        {
            // Still validate setup token even for loopback callers
            var tokenReject = RejectInvalidSetupToken();
            if (tokenReject != null) return tokenReject;
            return null;
        }

        // When --setup-local is set, also allow RFC 1918 private networks
        if (Startup.SetupNetworkMode.IsPrivateNetworkAllowed && IsRfc1918(remoteIp))
        {
            var tokenReject = RejectInvalidSetupToken();
            if (tokenReject != null) return tokenReject;
            return null;
        }

        var message = Startup.SetupNetworkMode.IsPrivateNetworkAllowed
            ? "Setup wizard is only accessible from localhost or private networks."
            : "Setup wizard is only accessible from localhost. Use --setup-local to allow private network access.";
        return StatusCode(403, new { error = message });
    }

    /// <summary>
    /// Network-only check (no token required). Used by read-only informational endpoints
    /// like <c>/status</c> and <c>/fingerprint</c> that the setup UI needs to call before
    /// the operator has entered the setup token.
    /// </summary>
    private IActionResult? RejectNonLocalRequestNoToken()
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress;
        if (remoteIp == null) return null;
        if (IPAddress.IsLoopback(remoteIp) || remoteIp.Equals(IPAddress.IPv6Loopback))
            return null;
        if (Startup.SetupNetworkMode.IsPrivateNetworkAllowed && IsRfc1918(remoteIp))
            return null;

        var message = Startup.SetupNetworkMode.IsPrivateNetworkAllowed
            ? "Setup wizard is only accessible from localhost or private networks."
            : "Setup wizard is only accessible from localhost. Use --setup-local to allow private network access.";
        return StatusCode(403, new { error = message });
    }

    /// <summary>
    /// KC-11: Validates the one-time setup token from the <c>X-Setup-Token</c> header.
    /// Returns a 403 result when the token is missing or invalid, 403 with an
    /// "expired" message once the TTL has elapsed, or null when valid. Skips
    /// validation when no token has been configured (non-setup mode).
    /// <para>
    /// Delegates to <see cref="Startup.SetupTokenHolder.ValidateToken"/> so the
    /// compare runs in constant time over UTF-8 bytes and the 30-minute TTL is
    /// enforced uniformly. Failed validations are logged at <c>Warning</c> level
    /// with the caller's IP so operators see the probe trail; the token value
    /// itself is never logged.
    /// </para>
    /// </summary>
    private IActionResult? RejectInvalidSetupToken()
    {
        var providedToken = HttpContext.Request.Headers["X-Setup-Token"].FirstOrDefault();
        var result = Startup.SetupTokenHolder.ValidateToken(providedToken);

        switch (result)
        {
            case Startup.SetupTokenHolder.ValidationResult.NotInSetupMode:
            case Startup.SetupTokenHolder.ValidationResult.Valid:
                return null;

            case Startup.SetupTokenHolder.ValidationResult.Missing:
                Log.Warning(
                    "Setup wizard: missing X-Setup-Token from {CallerIp} on {Path}",
                    HttpContext.Connection.RemoteIpAddress, HttpContext.Request.Path);
                return StatusCode(403, new { error = "Setup token is required. Copy the token from the server console output." });

            case Startup.SetupTokenHolder.ValidationResult.Expired:
                Log.Warning(
                    "Setup wizard: expired setup token presented from {CallerIp} on {Path}",
                    HttpContext.Connection.RemoteIpAddress, HttpContext.Request.Path);
                return StatusCode(403, new { error = "Setup token has expired. Restart the server to generate a new token." });

            case Startup.SetupTokenHolder.ValidationResult.Invalid:
            default:
                Log.Warning(
                    "Setup wizard: invalid setup token presented from {CallerIp} on {Path}",
                    HttpContext.Connection.RemoteIpAddress, HttpContext.Request.Path);
                return StatusCode(403, new { error = "Invalid setup token." });
        }
    }

    /// <summary>
    /// Checks if an IP address is in an RFC 1918 private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    /// </summary>
    private static bool IsRfc1918(IPAddress ip)
    {
        // Handle IPv4-mapped IPv6 addresses
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();

        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10                                           // 10.0.0.0/8
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)   // 172.16.0.0/12
            || (bytes[0] == 192 && bytes[1] == 168);                   // 192.168.0.0/16
    }

    [HttpGet("fingerprint")]
    public IActionResult GetSetupFingerprint()
    {
        var rejected = RejectNonLocalRequestNoToken();
        if (rejected != null) return rejected;

        if (IsConfigured())
            return NotFound();

        var fingerprint = ModularCA.API.Startup.SetupCertFingerprintHolder.GetFingerprint();
        if (string.IsNullOrWhiteSpace(fingerprint))
            return NotFound();

        return Ok(new { fingerprint, algorithm = "SHA-256" });
    }

    /// <summary>
    /// KC-11: Validates the one-time setup token provided in the <c>X-Setup-Token</c> header.
    /// The setup UI calls this endpoint to verify the operator's token before proceeding with
    /// the wizard. Returns 200 with <c>valid=true</c> on success, 403 if the token is missing,
    /// incorrect, or expired, and 404 if the system is already configured.
    /// <para>
    /// Hardening: comparison is constant-time (see <see cref="Startup.SetupTokenHolder.ValidateToken"/>),
    /// the token carries a 30-minute TTL enforced here, and this path is enrolled in
    /// <see cref="Middleware.LoginRateLimitMiddleware"/> so brute-force attempts are
    /// capped per IP. Both successful and failed validations are emitted to the audit
    /// log (the token value itself is never written).
    /// </para>
    /// </summary>
    [HttpGet("validate-token")]
    public IActionResult ValidateToken()
    {
        // Network check without token validation — we validate the token explicitly below
        var remoteIp = HttpContext.Connection.RemoteIpAddress;
        if (remoteIp != null
            && !IPAddress.IsLoopback(remoteIp)
            && !remoteIp.Equals(IPAddress.IPv6Loopback)
            && !(Startup.SetupNetworkMode.IsPrivateNetworkAllowed && IsRfc1918(remoteIp)))
        {
            var message = Startup.SetupNetworkMode.IsPrivateNetworkAllowed
                ? "Setup wizard is only accessible from localhost or private networks."
                : "Setup wizard is only accessible from localhost. Use --setup-local to allow private network access.";
            return StatusCode(403, new { error = message });
        }

        if (IsConfigured())
            return NotFound();

        var providedToken = HttpContext.Request.Headers["X-Setup-Token"].FirstOrDefault();
        var result = Startup.SetupTokenHolder.ValidateToken(providedToken);

        switch (result)
        {
            case Startup.SetupTokenHolder.ValidationResult.NotInSetupMode:
                Log.Information(
                    "Setup wizard: validate-token called from {CallerIp} — no token configured, allowing.",
                    remoteIp);
                return Ok(new { valid = true, message = "No setup token required." });

            case Startup.SetupTokenHolder.ValidationResult.Valid:
                Log.Information(
                    "Setup wizard: validate-token SUCCEEDED from {CallerIp}",
                    remoteIp);
                return Ok(new { valid = true });

            case Startup.SetupTokenHolder.ValidationResult.Expired:
                Log.Warning(
                    "Setup wizard: validate-token FAILED (expired) from {CallerIp}",
                    remoteIp);
                return StatusCode(403, new { valid = false, error = "Setup token has expired. Restart the server to generate a new token." });

            case Startup.SetupTokenHolder.ValidationResult.Missing:
                Log.Warning(
                    "Setup wizard: validate-token FAILED (missing) from {CallerIp}",
                    remoteIp);
                return StatusCode(403, new { valid = false, error = "Setup token is required." });

            case Startup.SetupTokenHolder.ValidationResult.Invalid:
            default:
                Log.Warning(
                    "Setup wizard: validate-token FAILED (invalid) from {CallerIp}",
                    remoteIp);
                return StatusCode(403, new { valid = false, error = "Invalid setup token." });
        }
    }

    /// <summary>
    /// Returns the current setup status. The body is intentionally
    /// minimal — we no longer leak <c>databaseConnected</c> / <c>needsDbConfig</c> to the
    /// unauthenticated caller because the presence or absence of those fields let an
    /// external scanner fingerprint a mid-setup install. The wizard's local SPA still needs
    /// to know whether to route the operator to the DB-creds step or the bootstrap step, so
    /// we surface a single coarse <c>step</c> enum value; everything else (host/port/user
    /// shape, error reason) is logged server-side via Serilog.
    /// When <c>staleDb=true</c>, the wizard should surface the recovery flow that calls
    /// <c>POST /api/v1/setup/database/drop</c>.
    /// </summary>
    [HttpGet("status")]
    public IActionResult GetStatus()
    {
        // Status is a read-only informational endpoint — no token required.
        // The setup UI calls this on mount before the operator enters the token.
        var rejected = RejectNonLocalRequestNoToken();
        if (rejected != null) return rejected;

        if (IsConfigured())
            return NotFound();

        var setupDbPath = Path.Combine(AppContext.BaseDirectory, "config", "setup-database.yaml");
        var hasSetupDbConfig = System.IO.File.Exists(setupDbPath);

        bool hasRootCreds = false;
        if (hasSetupDbConfig)
        {
            try
            {
                var setupDb = YamlSetupDatabaseLoader.Load(setupDbPath);
                hasRootCreds = setupDb != null && !string.IsNullOrWhiteSpace(setupDb.SqlRoot.Password);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Setup wizard GetStatus: setup-database.yaml failed to load");
            }
        }

        var staleDb = HasStaleDatabaseState();

        // Log the full probe detail to Serilog so the underlying state is
        // auditable server-side. The HTTP response keeps the backwards-compatible fields the
        // setup SPA reads, but the setup listener is loopback-only by default (Critical #2),
        // so the detail is only visible to a caller who is already on the host — a far
        // smaller asset-enumeration surface than the original 0.0.0.0 bind exposed.
        Log.Debug(
            "Setup status probe: hasRootCreds={HasRootCreds} staleDb={StaleDb} hasSetupDbConfig={HasSetupDbConfig}",
            hasRootCreds, staleDb, hasSetupDbConfig);

        string step = !hasRootCreds ? "database" : (staleDb ? "stale-db-recovery" : "bootstrap");
        return Ok(new
        {
            configured = false,
            databaseConnected = hasRootCreds,
            needsDbConfig = !hasRootCreds,
            staleDb,
            step,
        });
    }

    /// <summary>
    /// Drops the application database and audit database identified in
    /// <c>config/setup-database.yaml</c>, using the stored root credentials. Used by the
    /// setup wizard's stale-state recovery flow when the DB has CAs from a previous install
    /// but the on-disk config is fresh. Refuses to run once <c>config.yaml</c> exists.
    /// </summary>
    [HttpPost("database/drop")]
    public IActionResult DropDatabases()
    {
        var rejected = RejectNonLocalRequest();
        if (rejected != null) return rejected;

        if (IsConfigured())
            return NotFound();

        var setupDbPath = Path.Combine(AppContext.BaseDirectory, "config", "setup-database.yaml");
        if (!System.IO.File.Exists(setupDbPath))
            return BadRequest(new { error = "Root database credentials are not available. Provide them via /api/v1/setup/database/save first." });

        var setupDb = YamlSetupDatabaseLoader.Load(setupDbPath);
        if (setupDb == null || string.IsNullOrWhiteSpace(setupDb.SqlRoot.Password))
            return BadRequest(new { error = "Root database password is missing from setup-database.yaml." });

        try
        {
            var rootBuilder = new MySqlConnector.MySqlConnectionStringBuilder
            {
                Server = setupDb.SqlRoot.Host,
                Port = (uint)setupDb.SqlRoot.Port,
                UserID = setupDb.SqlRoot.Username,
                Password = setupDb.SqlRoot.Password
            };
            using var conn = new MySqlConnector.MySqlConnection(rootBuilder.ConnectionString);
            conn.Open();

            var dropped = new List<string>();
            foreach (var schema in new[] { setupDb.SqlApp.Database, setupDb.SqlAudit.Database })
            {
                if (string.IsNullOrWhiteSpace(schema))
                    continue;
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"DROP DATABASE IF EXISTS `{schema.Replace("`", "``")}`";
                cmd.ExecuteNonQuery();
                dropped.Add(schema);
            }

            // Force the SetupRedirectMiddleware cache to refresh on the next request so the
            // wizard transitions out of the stale-state banner without needing a restart.
            ModularCA.API.Middleware.SetupRedirectMiddleware.InvalidateCache();

            Log.Warning(
                "Setup wizard: database DROP executed from {CallerIp} — dropped schemas: {Schemas}",
                HttpContext.Connection.RemoteIpAddress, dropped);
            return Ok(new { dropped, message = $"Dropped {dropped.Count} database(s). You can now continue with setup." });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Setup wizard recovery: failed to drop databases");
            return StatusCode(500, new { error = "Failed to drop databases. See server logs for details." });
        }
    }

    /// <summary>
    /// Detects "stale DB" condition: the previous install left CertificateAuthorities rows behind
    /// but config.yaml is missing (fresh install on disk). Used by the wizard to surface the
    /// recovery flow without forcing the operator to drop to a CLI.
    /// </summary>
    /// <summary>
    /// Checks whether the database has CAs from a previous installation (stale state).
    /// Uses a raw MySqlConnection to avoid EF Core logging stack traces on connection failure.
    /// </summary>
    private bool HasStaleDatabaseState()
    {
        var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
        if (System.IO.File.Exists(configPath))
            return false;

        var connStr = db.Database.GetConnectionString() ?? "";
        if (connStr.Contains("setup-placeholder", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            using var conn = new MySqlConnector.MySqlConnection(connStr);
            conn.Open();

            using var tableCheck = conn.CreateCommand();
            tableCheck.CommandText = "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'CertificateAuthorities'";
            if (Convert.ToInt64(tableCheck.ExecuteScalar()) == 0)
                return false;

            using var caCheck = conn.CreateCommand();
            caCheck.CommandText = "SELECT EXISTS(SELECT 1 FROM CertificateAuthorities WHERE IsDeleted = 0 LIMIT 1)";
            return Convert.ToInt64(caCheck.ExecuteScalar()) > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Tests a database connection with the provided credentials.
    /// Returns whether the connection succeeded and if the database already exists.
    /// Gate behind <see cref="IsConfigured"/> so that once setup has
    /// completed, anonymous callers cannot use this endpoint as an SSRF / credential-stuffing
    /// oracle against arbitrary MySQL hosts. A middleware in the pipeline provides a
    /// second layer of defense against forgotten per-action checks.
    /// Connection string is now built via <see cref="MySqlConnector.MySqlConnectionStringBuilder"/>
    /// with typed property assignment, host/username/port are validated before use, and the
    /// exception message is never returned to the unauthenticated caller.
    /// </summary>
    [HttpPost("database/test")]
    public IActionResult TestDatabaseConnection([FromBody] SetupDatabase dbConfig)
    {
        var rejected = RejectNonLocalRequest();
        if (rejected != null) return rejected;

        if (IsConfigured())
            return NotFound();

        // Validate all operator-controlled fields before they touch
        // the connection string builder. The builder does its own escaping, but validating
        // shape here also blocks SSRF shenanigans via exotic hosts and keeps errors uniform.
        if (dbConfig == null)
            return BadRequest(new { connected = false, error = "connection failed" });

        if (!SetupInputValidation.IsValidHost(dbConfig.RootHost))
            return BadRequest(new { connected = false, error = "connection failed" });

        if (dbConfig.RootPort < 1 || dbConfig.RootPort > 65535)
            return BadRequest(new { connected = false, error = "connection failed" });

        if (!SetupInputValidation.IsValidUsername(dbConfig.RootUsername))
            return BadRequest(new { connected = false, error = "connection failed" });

        try
        {
            // Honor the operator-selected TLS mode when probing MySQL.
            // Unparseable values clamp back to Required so a typo can't silently disable TLS.
            var sslMode = Enum.TryParse<MySqlConnector.MySqlSslMode>(
                dbConfig.SslMode, ignoreCase: true, out var _ssl)
                ? _ssl : MySqlConnector.MySqlSslMode.Required;
            var builder = new MySqlConnector.MySqlConnectionStringBuilder
            {
                Server = dbConfig.RootHost,
                Port = (uint)dbConfig.RootPort,
                UserID = dbConfig.RootUsername,
                Password = dbConfig.RootPassword ?? string.Empty,
                SslMode = sslMode,
                ConnectionTimeout = 5,
            };

            using var conn = new MySqlConnector.MySqlConnection(builder.ConnectionString);
            conn.Open();

            // Check if the app database already exists
            using var cmd = new MySqlConnector.MySqlCommand(
                "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = @dbName", conn);
            cmd.Parameters.AddWithValue("@dbName", dbConfig.AppDatabase);
            var exists = cmd.ExecuteScalar() != null;

            Log.Warning(
                "Setup wizard: database connection test succeeded from {CallerIp} — host={Host} port={Port} user={User} appDb={AppDatabase} dbExists={DbExists}",
                HttpContext.Connection.RemoteIpAddress, dbConfig.RootHost, dbConfig.RootPort, dbConfig.RootUsername, dbConfig.AppDatabase, exists);

            return Ok(new { connected = true, databaseExists = exists });
        }
        catch (Exception ex)
        {
            // Never leak ex.Message to the unauthenticated caller — it may contain the
            // resolved host, the port, or driver internals. Log the full detail server-side.
            Log.Warning(ex,
                "Setup wizard: database connection test FAILED from {CallerIp} — host={Host} port={Port} user={User}",
                HttpContext.Connection.RemoteIpAddress, dbConfig.RootHost, dbConfig.RootPort, dbConfig.RootUsername);
            return Ok(new { connected = false, error = "connection failed" });
        }
    }

    /// <summary>
    /// Returns available algorithms, key sizes, and default values for the setup wizard UI.
    /// The default SAN list is pre-populated from the host's own DNS name
    /// plus the incoming <c>Host</c> header so the issued Web TLS certificate matches the
    /// address the operator used to reach the wizard. Defaults remain merge-only — any
    /// entry the operator removes in the SPA is honored by <see cref="Initialize"/>.
    /// </summary>
    [HttpGet("defaults")]
    public IActionResult GetDefaults()
    {
        var rejected = RejectNonLocalRequest();
        if (rejected != null) return rejected;

        if (IsConfigured())
            return NotFound();

        var webTlsDefaults = new SetupWebTlsCertificate();
        try
        {
            // Seed SAN defaults from the operator's actual hostnames.
            var sans = new List<string>(webTlsDefaults.Sans);

            var hostName = System.Net.Dns.GetHostName();
            if (!string.IsNullOrWhiteSpace(hostName))
            {
                var candidate = $"DNS:{hostName}";
                if (!sans.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                    sans.Add(candidate);
            }

            var requestHost = Request?.Host.Host;
            if (!string.IsNullOrWhiteSpace(requestHost))
            {
                // Distinguish IP literals from DNS names — wizard hostnames commonly arrive
                // as IP addresses when the operator navigated by IP. Put the IP under IP:,
                // the DNS name under DNS:.
                var prefix = System.Net.IPAddress.TryParse(requestHost, out _) ? "IP:" : "DNS:";
                var candidate = $"{prefix}{requestHost}";
                if (!sans.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                    sans.Add(candidate);
            }

            webTlsDefaults.Sans = sans;

            // Also pre-fill the CommonName from the primary DNS SAN if the default placeholder
            // is still "modularca.local" — matches what the operator is likely to pick anyway.
            if (string.Equals(webTlsDefaults.CommonName, "modularca.local", StringComparison.OrdinalIgnoreCase))
            {
                var firstDns = sans
                    .Where(s => s.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
                    .Select(s => s.Substring(4))
                    .FirstOrDefault(s => !string.Equals(s, "localhost", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(firstDns))
                    webTlsDefaults.CommonName = firstDns;
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Setup wizard GetDefaults: failed to populate SAN defaults from host");
        }

        var defaults = new SetupDefaultsResponse
        {
            Algorithms = new List<string> { "RSA", "ECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" },
            KeySizes = new List<string> { "2048", "3072", "4096", "7680", "8192", "P-256", "P-384", "P-521" },
            SignatureAlgorithms = new List<string>
            {
                "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
                "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1",
                "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA",
                "Ed25519", "Ed448",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F"
            },
            DefaultRootCa = new SetupRootCa
            {
                Algorithm = "RSA",
                KeySize = "4096",
                ValidityYears = 10
            },
            DefaultFeatures = new SetupFeatures(),
            DefaultWebTlsCertificate = webTlsDefaults
        };

        return Ok(defaults);
    }

    /// <summary>
    /// Saves database credentials to setup-database.yaml and restarts the application
    /// so the DI-registered DbContext picks up the correct connection string.
    /// The setup UI should call this first, wait for the app to come back, then call /initialize.
    /// Refuses to run if any CA already exists in the DB, even in the
    /// tiny window between a successful <see cref="Initialize"/> call and Kestrel closing
    /// the listener. Prevents an attacker from re-writing <c>setup-database.yaml</c> during
    /// graceful shutdown and triggering a second bootstrap against attacker-supplied root
    /// credentials.
    /// </summary>
    [HttpPost("database/save")]
    public IActionResult SaveDatabaseCredentials([FromBody] SetupDatabase dbConfig)
    {
        var rejected = RejectNonLocalRequest();
        if (rejected != null) return rejected;

        if (IsConfigured())
            return NotFound();

        // Defense-in-depth — also refuse if any CA row is present, since
        // IsConfigured() also checks the on-disk config.yaml which may still be missing during
        // a late-stage race after a successful Initialize. The DB is the authoritative state.
        try
        {
            if (db.Database.CanConnect() && db.CertificateAuthorities.Any())
                return NotFound();
        }
        catch
        {
            // DB unreachable — the normal setup-mode state, allow the save to proceed.
        }

        if (string.IsNullOrWhiteSpace(dbConfig.RootPassword))
            return BadRequest(new { error = "Root password is required." });

        var setupDbPath = Path.Combine(AppContext.BaseDirectory, "config", "setup-database.yaml");

        // Normalize the selected TLS mode before persisting so
        // downstream consumers never have to re-validate. Unparseable values clamp
        // back to Required so a typo can't silently disable TLS.
        var selectedSslMode = Enum.TryParse<MySqlConnector.MySqlSslMode>(
            dbConfig.SslMode, ignoreCase: true, out var _persistSsl)
            ? _persistSsl.ToString() : MySqlConnector.MySqlSslMode.Required.ToString();

        var config = new YamlSetupDatabaseLoader.SetupDatabaseConfig
        {
            SqlRoot = new YamlSetupDatabaseLoader.SqlConnectionConfig
            {
                Host = dbConfig.RootHost,
                Port = dbConfig.RootPort,
                Username = dbConfig.RootUsername,
                Password = dbConfig.RootPassword,
                Database = dbConfig.AppDatabase,
                SslMode = selectedSslMode
            },
            SqlApp = new YamlSetupDatabaseLoader.SqlConnectionConfig
            {
                Host = dbConfig.RootHost,
                Port = dbConfig.RootPort,
                Username = dbConfig.AppUsername,
                Database = dbConfig.AppDatabase,
                SslMode = selectedSslMode
            },
            SqlAudit = new YamlSetupDatabaseLoader.SqlConnectionConfig
            {
                Host = dbConfig.RootHost,
                Port = dbConfig.RootPort,
                Username = dbConfig.AuditUsername,
                Database = dbConfig.AuditDatabase,
                SslMode = selectedSslMode
            }
        };

        YamlSetupDatabaseLoader.Write(setupDbPath, config);

        // ICF-10: Attempt to tighten file permissions on the credentials file.
        // On Linux/macOS (.NET 7+), restrict to owner-only read/write. On Windows
        // the API is unavailable, so we catch and log a reminder instead.
        try
        {
#pragma warning disable CA1416 // Platform compatibility — guarded by PlatformNotSupportedException catch
            System.IO.File.SetUnixFileMode(setupDbPath,
                System.IO.UnixFileMode.UserRead | System.IO.UnixFileMode.UserWrite);
#pragma warning restore CA1416
        }
        catch (PlatformNotSupportedException)
        {
            Log.Warning(
                "ICF-10: setup-database.yaml contains database credentials. " +
                "On Windows, automatic file ACL tightening is not supported. " +
                "Please manually restrict access to: {Path}", setupDbPath);
        }
        catch (Exception permEx)
        {
            Log.Warning(permEx,
                "ICF-10: Failed to set restrictive file permissions on {Path}. " +
                "This file contains database credentials — ensure it is not world-readable.", setupDbPath);
        }

        Log.Warning(
            "Setup wizard: database credentials saved from {CallerIp} — host={Host} port={Port} rootUser={RootUser} appUser={AppUser} appDb={AppDatabase} auditUser={AuditUser} auditDb={AuditDatabase}. Application will restart.",
            HttpContext.Connection.RemoteIpAddress, dbConfig.RootHost, dbConfig.RootPort,
            dbConfig.RootUsername, dbConfig.AppUsername, dbConfig.AppDatabase,
            dbConfig.AuditUsername, dbConfig.AuditDatabase);

        // Stop Kestrel AFTER the response has flushed so the client
        // receives the JSON body, then the listener closes without the previous 500 ms
        // window where new unauthenticated setup requests could slip through.
        HttpContext.Response.OnCompleted(() =>
        {
            appLifetime.StopApplication();
            return Task.CompletedTask;
        });

        return Ok(new { message = "Database credentials saved. Application is restarting — retry setup after a few seconds.", restarting = true });
    }

    /// <summary>
    /// Accepts the full setup configuration, runs the bootstrap procedure, and returns
    /// the generated admin credentials. Invalidates the setup middleware cache on success.
    /// The method body is serialized behind a process-wide
    /// <see cref="SemaphoreSlim"/> and wraps the bootstrap in a MySQL <c>GET_LOCK</c>
    /// advisory lock so two concurrent callers (including multi-instance deployments
    /// behind a load balancer) cannot both race <c>BootstrapService.RunFromSetupRequest</c>.
    /// </summary>
    [HttpPost("initialize")]
    public IActionResult Initialize([FromBody] SetupRequest request)
    {
        var rejected = RejectNonLocalRequest();
        if (rejected != null) return rejected;

        // Fast path rejection: cache-level check so we don't block on the semaphore
        // once setup has completed. Re-check inside the critical section.
        if (IsConfigured())
            return NotFound();

        // Process-wide gate. 0 ms wait — the second caller must
        // return 409 immediately so impatient double-clicks on the wizard never both run.
        if (!_initializeLock.Wait(0))
            return Conflict(new { error = "Setup initialization is already in progress. Refresh the page in a few seconds." });

        try
        {
            // Re-check under the lock — a concurrent caller may have completed first.
            if (IsConfigured())
                return NotFound();

            // Validate required fields
            if (string.IsNullOrWhiteSpace(request.Organization.Name))
                return BadRequest(new { error = "Organization name is required." });
            if (string.IsNullOrWhiteSpace(request.RootCa.CommonName))
                return BadRequest(new { error = "Root CA Common Name is required." });

            // Refuse to issue a Web TLS cert that won't validate against the
            // address the operator is currently using to reach the wizard. Requires at least
            // one SAN matching the current Request.Host (case-insensitive).
            var requestHost = Request?.Host.Host;
            if (!string.IsNullOrWhiteSpace(requestHost) && request.WebTlsCertificate?.Sans is { Count: > 0 } sans)
            {
                bool matches = sans.Any(s =>
                {
                    var colon = s.IndexOf(':');
                    var value = colon >= 0 ? s[(colon + 1)..] : s;
                    return string.Equals(value, requestHost, StringComparison.OrdinalIgnoreCase);
                });
                if (!matches)
                {
                    return BadRequest(new { error = $"At least one SAN must match the current request host '{requestHost}'. Add 'DNS:{requestHost}' or 'IP:{requestHost}' and re-submit." });
                }
            }

            // If the wizard didn't collect DB creds (skipped because setup-database.yaml exists),
            // load ALL database config from the file. The frontend sends default names like
            // "modularca-app" even when the Database step was skipped, so we unconditionally
            // prefer the setup-database.yaml values — those are what the operator configured
            // and what the /database/test endpoint validated.
            if (string.IsNullOrWhiteSpace(request.Database.RootPassword))
            {
                var setupDbPath = Path.Combine(AppContext.BaseDirectory, "config", "setup-database.yaml");
                var setupDb = YamlSetupDatabaseLoader.Load(setupDbPath);
                if (setupDb != null)
                {
                    request.Database.RootHost = setupDb.SqlRoot.Host;
                    request.Database.RootPort = setupDb.SqlRoot.Port;
                    request.Database.RootUsername = setupDb.SqlRoot.Username;
                    request.Database.RootPassword = setupDb.SqlRoot.Password;
                    request.Database.AppDatabase = setupDb.SqlApp.Database;
                    request.Database.AppUsername = setupDb.SqlApp.Username;
                    request.Database.AuditDatabase = setupDb.SqlAudit.Database;
                    request.Database.AuditUsername = setupDb.SqlAudit.Username;
                }
                else
                {
                    return BadRequest(new { error = "Database root password is required. Provide it in the setup form or create config/setup-database.yaml." });
                }
            }

            // Defense-in-depth: take a MySQL named advisory lock so that
            // two API instances behind a load balancer with a shared DB cannot both run the
            // bootstrap concurrently. GET_LOCK returns 1 on acquire, 0 on timeout, NULL on error.
            // We try against the app DB using the operator-supplied root creds; if the DB does
            // not yet exist (first run), the lock acquisition is skipped (safe — the
            // _initializeLock semaphore still serializes within the current process).
            MySqlConnector.MySqlConnection? advisoryConn = null;
            try
            {
                try
                {
                    var advisoryBuilder = new MySqlConnector.MySqlConnectionStringBuilder
                    {
                        Server = request.Database.RootHost,
                        Port = (uint)request.Database.RootPort,
                        UserID = request.Database.RootUsername,
                        Password = request.Database.RootPassword ?? string.Empty,
                        ConnectionTimeout = 5,
                    };
                    advisoryConn = new MySqlConnector.MySqlConnection(advisoryBuilder.ConnectionString);
                    advisoryConn.Open();
                    using var lockCmd = new MySqlConnector.MySqlCommand(
                        "SELECT GET_LOCK('modularca_bootstrap', 0)", advisoryConn);
                    var lockResult = lockCmd.ExecuteScalar();
                    var lockAcquired = lockResult != null && lockResult != DBNull.Value && Convert.ToInt32(lockResult) == 1;
                    if (!lockAcquired)
                    {
                        return Conflict(new { error = "Another ModularCA instance is currently running bootstrap. Retry in a few seconds." });
                    }
                }
                catch (Exception lockEx)
                {
                    // GET_LOCK unavailable (MySQL unreachable pre-setup or insufficient privs).
                    // The in-process semaphore still blocks multi-caller races on this node.
                    Log.Warning(lockEx, "Setup initialize: MySQL advisory lock could not be acquired — falling back to in-process gate only");
                }

                var result = BootstrapService.RunFromSetupRequest(request, serviceProvider);

                if (!result.Success)
                {
                    // result.Message is already generic (correlation id only)
                    // — do not interpolate it into Log.Error, which would double-log. Log the
                    // bare message; full exception detail was already captured by BootstrapService.
                    Log.Error(
                        "Setup wizard: initialization FAILED from {CallerIp} — org={Organization} rootCaCN={RootCaCN} message={Message}",
                        HttpContext.Connection.RemoteIpAddress, request.Organization?.Name, request.RootCa?.CommonName, result.Message);
                    return StatusCode(500, new SetupResponse
                    {
                        Success = false,
                        // Never let internal message text escape to the unauthenticated SPA.
                        Message = result.Message,
                    });
                }

                Log.Warning(
                    "Setup wizard: initialization SUCCEEDED from {CallerIp} — org={Organization} rootCaCN={RootCaCN}. Application will restart into production mode.",
                    HttpContext.Connection.RemoteIpAddress, request.Organization?.Name, request.RootCa?.CommonName);

                // Flip the middleware cache on success so the unauthenticated
                // setup endpoints close immediately — do NOT wait for the StopApplication to
                // actually tear down the Kestrel listener (which can take several seconds).
                ModularCA.API.Middleware.SetupRedirectMiddleware.InvalidateCache();

                // Fire-and-forget shutdown after the response has flushed.
                // The previous code slept 1 second before StopApplication, keeping the setup
                // endpoints reachable during that window. Flush-and-stop closes the gap.
                HttpContext.Response.OnCompleted(() =>
                {
                    appLifetime.StopApplication();
                    return Task.CompletedTask;
                });

                // Don't return the admin password — the UI already has it
                result.AdminPassword = null;
                return Ok(result);
            }
            finally
            {
                if (advisoryConn != null)
                {
                    try
                    {
                        using var releaseCmd = new MySqlConnector.MySqlCommand(
                            "SELECT RELEASE_LOCK('modularca_bootstrap')", advisoryConn);
                        releaseCmd.ExecuteScalar();
                    }
                    catch { /* best-effort — the session-scoped lock drops on close anyway */ }
                    advisoryConn.Dispose();
                }
            }
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    /// <summary>
    /// Checks whether the system is already configured by querying the database for existing CAs.
    /// Returns false if the database is unreachable or the CertificateAuthorities table doesn't exist yet.
    /// Uses a raw information_schema probe first so EF Core doesn't log failed commands at ERR level
    /// on every setup-status poll before the schema has been created.
    ///
    /// Also returns false when <c>config/config.yaml</c> is missing — that on-disk state means
    /// we're in setup mode, so any leftover CertificateAuthorities rows are considered stale and
    /// the wizard's recovery flow should be reachable. The middleware applies the same rule.
    /// </summary>
    /// <summary>
    /// Checks whether the system has been fully configured (config.yaml exists and at
    /// least one CA is present). Uses a raw MySqlConnection to avoid EF Core logging
    /// full stack traces when the database is unreachable.
    /// </summary>
    private bool IsConfigured()
    {
        var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
        if (!System.IO.File.Exists(configPath))
            return false;

        var connStr = db.Database.GetConnectionString() ?? "";
        if (connStr.Contains("setup-placeholder", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            using var conn = new MySqlConnector.MySqlConnection(connStr);
            conn.Open();

            using var tableCheck = conn.CreateCommand();
            tableCheck.CommandText = "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'CertificateAuthorities'";
            if (Convert.ToInt64(tableCheck.ExecuteScalar()) == 0)
                return false;

            using var caCheck = conn.CreateCommand();
            caCheck.CommandText = "SELECT EXISTS(SELECT 1 FROM CertificateAuthorities WHERE IsDeleted = 0 LIMIT 1)";
            return Convert.ToInt64(caCheck.ExecuteScalar()) > 0;
        }
        catch (Exception ex)
        {
            // "Cannot tell" is not the same as "not configured".
            //
            // Every caller uses this to decide whether the unauthenticated setup wizard is still
            // reachable, and returning false re-opens endpoints including
            // POST /setup/database/drop and /setup/initialize. A database outage on a configured
            // system therefore used to hand a loopback caller — or any RFC1918 caller when the
            // server was started with --setup-local — the ability to drop the CA database, since
            // in non-setup mode no setup token is required either.
            //
            // config.yaml existing is by itself sufficient evidence that bootstrap has already
            // run; we only got here because that check passed. So an unreachable database means
            // deny, not open.
            Log.Warning(ex,
                "Setup wizard: could not verify configured state (config.yaml exists but the database "
                + "is unreachable). Treating the system as CONFIGURED so setup endpoints stay closed.");
            return true;
        }
    }
}

/// <summary>
/// Shape-validation helpers for the unauthenticated setup wizard.
/// These are deliberately restrictive: hosts must be valid DNS names or IP addresses,
/// usernames are constrained to <c>[A-Za-z0-9._-]{1,64}</c>, and all inputs are rejected
/// if they contain control characters. The typed <c>MySqlConnectionStringBuilder</c>
/// escapes reserved characters, but validating shape up-front blocks SSRF tricks and
/// produces uniform error responses that do not leak driver internals.
/// </summary>
internal static partial class SetupInputValidation
{
    // Hostname label per RFC 1123: up to 63 chars, starts/ends alphanumeric, internal hyphens allowed.
    // Whole-hostname cap is 253 chars.
    [GeneratedRegex(@"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$",
        RegexOptions.CultureInvariant)]
    private static partial Regex HostnameRegex();

    [GeneratedRegex(@"^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex UsernameRegex();

    /// <summary>
    /// Returns true when the supplied host is a valid DNS hostname or a parseable IP literal.
    /// Control characters and empty strings are rejected.
    /// </summary>
    public static bool IsValidHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        if (host.Length > 255) return false;
        foreach (var c in host)
        {
            if (char.IsControl(c)) return false;
        }
        // Accept IPv4, IPv6, or a DNS hostname.
        if (System.Net.IPAddress.TryParse(host, out _)) return true;
        return HostnameRegex().IsMatch(host);
    }

    /// <summary>
    /// Returns true when the supplied username matches <c>^[A-Za-z0-9._-]{1,64}$</c>.
    /// </summary>
    public static bool IsValidUsername(string? username)
    {
        if (string.IsNullOrEmpty(username)) return false;
        return UsernameRegex().IsMatch(username);
    }
}
