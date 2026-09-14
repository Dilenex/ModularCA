using FluentValidation;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ModularCA.API.Startup;
using ModularCA.API.Validation.SigningProfiles;
using ModularCA.Auth.Implementations;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Services;
using ModularCA.Bootstrap;
using ModularCA.Shared.Models.Config;
using ModularCA.Core.Implementations;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Acme;
using ModularCA.Core.Services.Cmp;
using ModularCA.Core.Services.Est;
using ModularCA.Core.Services.Ocsp;
using ModularCA.Core.Services.Scep;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.Hsm;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Microsoft.Extensions.Hosting.Systemd;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;
using ModularCA.Core.Logging;
using System.Text;
using ModularCA.Shared.Errors;

// ── Serilog bootstrap logger ─────────────────────────
// Initialized before CLI flag handling so that operator-triggered destructive
// operations (--reset, --bootstrap, --backup, --restore) leave evidence in the
// log sinks (console + file). Replaced by the full host-wired logger later on.
// Console rendering is chosen the same way here as for the host logger below, so the startup
// window is not a blind spot: under systemd these lines carry the <N> priority prefix and
// `journalctl -p err` surfaces a failed --restore or a refused boot. config.yaml is not loaded
// yet, so this resolves from the environment alone.
var bootstrapConsoleFormat = ConsoleLogFormatResolver.Resolve(
    configured: null,
    underSystemd: SystemdHelpers.IsSystemdService(),
    inContainer: string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase));

var bootstrapConfig = new LoggerConfiguration().MinimumLevel.Information();
switch (bootstrapConsoleFormat)
{
    case ConsoleLogFormat.Systemd:
        bootstrapConfig.WriteTo.Console(new SystemdTextFormatter());
        break;
    case ConsoleLogFormat.Json:
        bootstrapConfig.WriteTo.Console(new CompactJsonFormatter());
        break;
    default:
        bootstrapConfig.WriteTo.Console(outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");
        break;
}

Log.Logger = bootstrapConfig
    .WriteTo.File(new CompactJsonFormatter(),
        Path.Combine(AppContext.BaseDirectory, "logs", "modularca-bootstrap-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14)
    .CreateBootstrapLogger();

// === Handle CLI flags ===
if (args.Contains("--reset", StringComparer.OrdinalIgnoreCase))
{
    if (!args.Contains("--force", StringComparer.OrdinalIgnoreCase))
    {
        Console.WriteLine("ERROR: --reset requires --force to confirm destructive operation.");
        Console.WriteLine("Usage: dotnet run --reset --force --confirm-db-name <database-name>");
        Console.WriteLine("       dotnet run --reset --force --confirm-db-name <database-name> --ci-no-confirm");
        Console.WriteLine("WARNING: This will destroy ALL data (databases, keystores, config).");
        Console.WriteLine("         After reset, run normally to access the web setup wizard.");
        Console.WriteLine();
        Console.WriteLine("NOTE: The audit database is NOT dropped — by --reset or by the bootstrap that");
        Console.WriteLine("      follows it. Historical audit rows remain visible after the next install.");
        Console.WriteLine("      To discard them deliberately, add --wipe-audit to the bootstrap run.");
        Environment.Exit(1);
    }

    // Require the operator to explicitly type the target
    // database name when running --force. --expected-db is retained as a backwards-compat
    // alias for --confirm-db-name. The --ci-no-confirm flag waives this requirement for
    // non-interactive CI pipelines that genuinely need unattended resets.
    string? confirmDbName = args
        .SkipWhile(a => !a.Equals("--confirm-db-name", StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault();
    if (string.IsNullOrWhiteSpace(confirmDbName))
    {
        confirmDbName = args
            .SkipWhile(a => !a.Equals("--expected-db", StringComparison.OrdinalIgnoreCase))
            .Skip(1)
            .FirstOrDefault();
    }
    bool ciNoConfirm = args.Contains("--ci-no-confirm", StringComparer.OrdinalIgnoreCase);

    if (string.IsNullOrWhiteSpace(confirmDbName) && !ciNoConfirm)
    {
        Console.WriteLine("ERROR: --reset --force also requires --confirm-db-name <database-name>");
        Console.WriteLine("       so the caller proves they know which DB is about to be destroyed.");
        Console.WriteLine("       For non-interactive CI, add --ci-no-confirm to waive the gate.");
        Environment.Exit(1);
    }

    // Print the retention-by-design warning in the reset banner so
    // operators are not surprised when audit rows from the previous tenant reappear.
    Console.WriteLine("================================================================");
    Console.WriteLine("FACTORY RESET — Destroying all data...");
    Console.WriteLine();
    Console.WriteLine("  (i) Audit database is NOT dropped, by this reset or by the bootstrap that");
    Console.WriteLine("      follows. Historical audit rows persist into the next install.");
    Console.WriteLine("      Discard them deliberately with: --bootstrap --wipe-audit");
    Console.WriteLine("  (i) config/backup.key will be renamed to backup.key.pre-reset-<ts>");
    Console.WriteLine("      so backups taken before this reset remain decryptable.");
    Console.WriteLine("================================================================");
    Console.WriteLine();

    // Destructive operation — emit a structured Serilog event so
    // the reset leaves evidence on every configured sink before the data is gone.
    Log.Warning("Operator triggered factory reset (--reset --force) confirmDbName={ConfirmDbName} ciNoConfirm={CiNoConfirm}",
        confirmDbName ?? "(none supplied)", ciNoConfirm);
    var exitCode = BootstrapModularCA.FactoryReset(confirmDbName);
    if (exitCode == 0)
    {
        Console.WriteLine("\nFactory reset complete. Run the application normally to access the setup wizard.");
        Console.WriteLine("   dotnet run");
    }
    Environment.Exit(exitCode);
}
// Private networks are the default. --setup-loopback-only restores the stricter posture for a
// CA on a network the operator does not trust; the one-time setup token is required either way.
if (args.Contains("--setup-loopback-only", StringComparer.OrdinalIgnoreCase))
{
    Log.Information("Setup wizard restricted to loopback callers (--setup-loopback-only)");
    ModularCA.API.Startup.SetupNetworkMode.RestrictToLoopback();
}
else if (args.Contains("--setup-local", StringComparer.OrdinalIgnoreCase))
{
    // Kept because it appears in existing runbooks and scripts. It asked for what is now the
    // default, so it does nothing; saying so is better than silently accepting it forever.
    Log.Information("--setup-local is no longer needed: private-network access is the default. "
                  + "Pass --setup-loopback-only to restrict the wizard to this machine.");
}

if (args.Contains("--bootstrap", StringComparer.OrdinalIgnoreCase))
{
    Log.Information("Operator triggered CA bootstrap procedure (--bootstrap)");
    Console.WriteLine("Running CA bootstrap procedure...\n");

    // Audit history is preserved across a reinstall unless the operator asks otherwise.
    // The drop used to happen here unconditionally, which made the --reset banner's promise
    // that "historical audit rows will persist into the next install" false.
    var wipeAudit = args.Contains("--wipe-audit", StringComparer.OrdinalIgnoreCase);
    if (wipeAudit)
    {
        Log.Warning("Operator passed --wipe-audit; the audit database will be dropped and recreated");
        Console.WriteLine("⚠  --wipe-audit: existing audit history will be DESTROYED, not preserved.\n");
    }

    var exitCode = BootstrapModularCA.Run(wipeAudit);
    Environment.Exit(exitCode);
}
if (args.Contains("--backup", StringComparer.OrdinalIgnoreCase))
{
    var outputPath = args.SkipWhile(a => !a.Equals("--backup", StringComparison.OrdinalIgnoreCase)).Skip(1).FirstOrDefault();
    Log.Information("Operator triggered backup (--backup) outputPath={OutputPath}", outputPath ?? "(default)");
    var exitCode = await BackupRestore.Backup(outputPath);
    Environment.Exit(exitCode);
}
if (args.Contains("--restore", StringComparer.OrdinalIgnoreCase))
{
    var archivePath = args.SkipWhile(a => !a.Equals("--restore", StringComparison.OrdinalIgnoreCase)).Skip(1).FirstOrDefault();
    if (string.IsNullOrWhiteSpace(archivePath))
    {
        Console.WriteLine("Usage: --restore <backup-archive.enc> [--password <password>]");
        Environment.Exit(1);
    }

    // Optional --password <pwd> for disaster recovery when backup-password.key is missing
    // or doesn't match this archive's salt. If the flag isn't supplied but the archive is
    // a StoredPassword archive that needs a password, fall back to an interactive prompt.
    string? providedPassword = args
        .SkipWhile(a => !a.Equals("--password", StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault();

    try
    {
        var info = ModularCA.Bootstrap.Crypto.BackupKeyManager.PeekArchiveInfo(archivePath);
        if (info is { IsLegacyFormat: false, Mode: ModularCA.Bootstrap.Crypto.BackupEncryptionMode.StoredPassword }
            && string.IsNullOrEmpty(providedPassword))
        {
            // Check whether the local password file would decrypt this archive by comparing salts.
            // If the file is missing OR the salts don't match, prompt for the password interactively.
            // We use the default config-relative path here — the CLI --restore handler runs before
            // the full runtime config is loaded, and overriding the path is an edge case operators
            // can handle via `--password <pwd>` if they've moved the key file.
            var passwordKeyPath = Path.Combine(
                AppContext.BaseDirectory,
                "config",
                "backup-password.key");

            bool needPrompt = true;
            if (File.Exists(passwordKeyPath))
            {
                try
                {
                    var (kek, storedSalt, _, _, _) =
                        ModularCA.Bootstrap.Crypto.BackupKeyManager.ReadPasswordKeyFile(passwordKeyPath);
                    ModularCA.Bootstrap.Crypto.BackupKeyManager.ZeroKey(kek);
                    if (info.Salt != null && storedSalt.AsSpan().SequenceEqual(info.Salt))
                        needPrompt = false;
                }
                catch
                {
                    needPrompt = true;
                }
            }

            if (needPrompt)
            {
                Console.WriteLine();
                Console.WriteLine("This archive is encrypted in StoredPassword mode and cannot be restored with the");
                Console.WriteLine("current password key file. Enter the backup password to proceed (or Ctrl+C to abort):");
                Console.Write("Password: ");

                var entered = new StringBuilder();
                ConsoleKeyInfo keyInfo;
                while ((keyInfo = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
                {
                    if (keyInfo.Key == ConsoleKey.Backspace && entered.Length > 0)
                        entered.Remove(entered.Length - 1, 1);
                    else if (!char.IsControl(keyInfo.KeyChar))
                        entered.Append(keyInfo.KeyChar);
                }
                Console.WriteLine();
                providedPassword = entered.ToString();
                if (string.IsNullOrEmpty(providedPassword))
                {
                    Console.WriteLine("No password entered — aborting.");
                    Environment.Exit(1);
                }
            }
        }
    }
    catch (FileNotFoundException ex)
    {
        Console.WriteLine($"❌ {ex.Message}");
        Environment.Exit(1);
    }
    catch (InvalidDataException ex)
    {
        Console.WriteLine($"❌ Cannot read backup archive: {ex.Message}");
        Environment.Exit(1);
    }

    Log.Warning("Operator triggered restore (--restore) archive={ArchivePath}", archivePath);
    var exitCode = await BackupRestore.Restore(archivePath, skipSchemaCheck: false, providedPassword: providedPassword);
    Environment.Exit(exitCode);
}
if (args.Contains("--backfill-keystore-pins", StringComparer.OrdinalIgnoreCase))
{
    // Backfill Keystores.SigningCaSpkiSha256 for legacy rows whose pin was
    // never populated. This walks every Keystores row, reparses the file under the legacy
    // unpinned path, identifies which CA actually signed it, and writes the SPKI hex back
    // to the row. After a clean run the legacy fallback in KeystoreService.FindValidSigner
    // should never execute again and operators can treat a new fallback invocation as a
    // tamper signal. Read-only by default — pass --write to actually persist changes.
    var writeMode = args.Contains("--write", StringComparer.OrdinalIgnoreCase);
    Log.Warning("Operator triggered keystore pin backfill writeMode={WriteMode}", writeMode);

    var cfgPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
    if (!File.Exists(cfgPath))
    {
        Console.Error.WriteLine("❌ config.yaml not found — bootstrap must complete before backfill can run.");
        Environment.Exit(1);
    }
    var cfg = YamlConfigLoader.Load(cfgPath);
    var dbYamlPath2 = Path.Combine(AppContext.BaseDirectory, "config", "db.yaml");
    var dbYaml2 = YamlDbConfigLoader.Load(dbYamlPath2);
    if (dbYaml2 != null)
    {
        cfg.DB.App.Host = dbYaml2.App.Host;
        cfg.DB.App.Port = dbYaml2.App.Port;
        cfg.DB.App.Database = dbYaml2.App.Database;
        cfg.DB.App.Username = dbYaml2.App.Username;
        cfg.DB.App.Password = dbYaml2.App.Password;
        cfg.DB.App.SslMode = dbYaml2.App.SslMode;
    }

    // Honor the operator-selected TLS mode; clamp typos to Required.
    var backfillSslMode = Enum.TryParse<MySqlConnector.MySqlSslMode>(
        cfg.DB.App.SslMode, ignoreCase: true, out var _backfillSsl)
        ? _backfillSsl : MySqlConnector.MySqlSslMode.Required;
    var appCsb = new MySqlConnector.MySqlConnectionStringBuilder
    {
        Server = cfg.DB.App.Host,
        Port = (uint)cfg.DB.App.Port,
        Database = cfg.DB.App.Database,
        UserID = cfg.DB.App.Username,
        Password = cfg.DB.App.Password,
        SslMode = backfillSslMode,
    };
    var backfillConnStr = appCsb.ConnectionString;
    var dbOptions = new DbContextOptionsBuilder<ModularCADbContext>()
        .UseMySql(backfillConnStr, ServerVersion.AutoDetect(backfillConnStr))
        .Options;
    using var backfillDb = new ModularCADbContext(dbOptions);
    var keystoresDir = Path.Combine(AppContext.BaseDirectory, "keystores");
    // Supply the secondary passphrase so the backfill can authenticate the pin it writes.
    // Without it the pin goes in unprotected, which is the state the backfill exists to clear.
    var keystoreYamlPath = Path.Combine(AppContext.BaseDirectory, "config", "keystore.yaml");
    var report = ModularCA.Keystore.Services.KeystoreService.BackfillPinnedSpki(
        backfillDb, keystoresDir, persist: writeMode,
        secondaryPassphraseResolver: name =>
        {
            try { return ModularCA.Keystore.Config.KeystoreYamlLoader.LoadSecondaryPassphrase(keystoreYamlPath, name); }
            catch { return null; }
        });

    Console.WriteLine($"Backfill report ({(writeMode ? "persisted" : "dry-run — re-run with --write")}):");
    Console.WriteLine($"  Pinned  ({report.Backfilled.Count}):");
    foreach (var s in report.Backfilled) Console.WriteLine($"    + {s}");
    Console.WriteLine($"  Skipped ({report.Skipped.Count}):");
    foreach (var s in report.Skipped) Console.WriteLine($"    - {s}");
    Console.WriteLine($"  Failed  ({report.Failed.Count}):");
    foreach (var s in report.Failed) Console.WriteLine($"    ! {s}");

    // In dry-run mode BackfillPinnedSpki already walked the rows and populated them in-memory
    // via the EF change tracker. If the operator did not pass --write, we deliberately do NOT
    // call SaveChanges, but the helper may have called it internally — ensure dry-run is
    // idempotent by discarding the DbContext without SaveChanges.
    Environment.Exit(report.Failed.Count == 0 ? 0 : 1);
}

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSystemd();

// Load DB credentials from db.yaml (runtime app DB creds)
var dbYamlPath = Path.Combine(AppContext.BaseDirectory, "config", "db.yaml");
var dbYaml = YamlDbConfigLoader.Load(dbYamlPath);

// Load config.yaml for everything else (JWT, HTTPS, logging, scheduler, etc.)
var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
SystemConfig config;
bool isSetupMode = false;

if (File.Exists(configPath))
{
    config = YamlConfigLoader.Load(configPath);
}
else
{
    isSetupMode = true;
    config = new SystemConfig();
}

// Populate DB creds on the config object from db.yaml, falling back to setup-database.yaml.
// SslMode is propagated from whichever file is authoritative so that
// connection builders downstream (see config.DB.App.SslMode / config.DB.Audit.SslMode reads)
// honor the operator's wizard choice both pre- and post-bootstrap.
if (dbYaml != null)
{
    config.DB.App.Host = dbYaml.App.Host;
    config.DB.App.Port = dbYaml.App.Port;
    config.DB.App.Database = dbYaml.App.Database;
    config.DB.App.Username = dbYaml.App.Username;
    config.DB.App.Password = dbYaml.App.Password;
    config.DB.App.SslMode = dbYaml.App.SslMode;
    config.DB.Audit.Host = dbYaml.Audit.Host;
    config.DB.Audit.Port = dbYaml.Audit.Port;
    config.DB.Audit.Database = dbYaml.Audit.Database;
    config.DB.Audit.Username = dbYaml.Audit.Username;
    config.DB.Audit.Password = dbYaml.Audit.Password;
    config.DB.Audit.SslMode = dbYaml.Audit.SslMode;
}
else
{
    // No db.yaml — try setup-database.yaml for root creds (setup mode). This is the
    // window between SaveDatabaseCredentials and full bootstrap, during which
    // setup-database.yaml is the only source of truth for the operator's TLS choice.
    isSetupMode = true;
    var setupDbPath = Path.Combine(AppContext.BaseDirectory, "config", "setup-database.yaml");
    var setupDb = YamlSetupDatabaseLoader.Load(setupDbPath);
    if (setupDb != null)
    {
        var rootCfg = !string.IsNullOrWhiteSpace(setupDb.SqlRoot.Password) ? setupDb.SqlRoot : setupDb.SqlApp;
        config.DB.App.Host = rootCfg.Host;
        config.DB.App.Port = rootCfg.Port;
        config.DB.App.Database = setupDb.SqlApp.Database;
        config.DB.App.Username = rootCfg.Username;
        config.DB.App.Password = rootCfg.Password;
        // Prefer SqlApp.SslMode (matches runtime app connection); fall back to SqlRoot
        // if SqlApp wasn't populated. Empty/unset falls through to the SystemConfig default.
        var setupSslMode = !string.IsNullOrWhiteSpace(setupDb.SqlApp.SslMode)
            ? setupDb.SqlApp.SslMode
            : setupDb.SqlRoot.SslMode;
        if (!string.IsNullOrWhiteSpace(setupSslMode))
        {
            config.DB.App.SslMode = setupSslMode;
            // Audit connection uses the same mode during setup since db.yaml doesn't
            // exist yet and setup-database.yaml carries one choice per install.
            config.DB.Audit.SslMode = !string.IsNullOrWhiteSpace(setupDb.SqlAudit.SslMode)
                ? setupDb.SqlAudit.SslMode
                : setupSslMode;
        }
    }
}

// ICF-03/04/05: overlay environment variables for secret fields
var envOverlay = new ModularCA.Shared.Utils.EnvVarConfigOverlay();
envOverlay.Apply(config);

// CRYPTO-001: apply RSA signature padding mode from CertPolicy config to the
// central KeyAlgorithmPolicy. This must happen before any certificate or CRL
// signing code runs. Default is PSS for new deployments; operators can revert
// to PKCS#1 v1.5 by setting CertPolicy.RsaSignaturePadding = "v15".
KeyAlgorithmPolicy.UseRsaPss = config.CertPolicy?.RsaSignaturePadding?.Equals("PSS", StringComparison.OrdinalIgnoreCase) ?? true;

// AUTH-019: warn at startup when LDAP is enabled without TLS
if (config.LdapAuth.Enabled && !config.LdapAuth.UseSsl)
{
    Log.Warning("LDAP authentication is enabled without TLS (UseSsl=false). " +
        "Bind credentials will be transmitted in cleartext. " +
        "Set LdapAuth.UseSsl=true or use LDAPS (port 636) for production deployments.");
}

if (isSetupMode)
{
    Console.WriteLine("[WARNING] Running in setup mode.");
    Console.WriteLine("         Navigate to the web interface to complete initial setup.");

    // KC-11: generate a one-time setup token that the wizard must present on every request.
    // This prevents network-adjacent attackers from accessing the wizard even if they can
    // reach the port — the token is only visible on the server console.
    var setupToken = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    SetupTokenHolder.SetToken(setupToken);
    // Token is printed AFTER the Kestrel banner so it's the last thing on screen
    // and doesn't get buried by DB-query warnings.
}

// Validate every configured cron expression at startup. A typo in
// config.yaml previously silently disabled the associated job — now we fail fast with
// a clear error so operators see the problem before the scheduler starts skipping work.
if (!isSetupMode)
{
    var cronMap = new Dictionary<string, string?>(StringComparer.Ordinal)
    {
        ["Backup.Schedule"] = config.Backup.Schedule,
        ["CertExpiryNotification.Schedule"] = config.CertExpiryNotification.Schedule,
        ["ComplianceScan.Schedule"] = config.ComplianceScan.Schedule,
        ["AutoRenewal.Schedule"] = config.AutoRenewal.Schedule,
        ["Audit.Retention.Schedule"] = config.Audit.Retention.Schedule,
    };
    var cronErrors = ModularCA.Core.Services.SchedulerJobs.CronExpressionValidator.ValidateAll(cronMap);
    if (cronErrors.Count > 0)
    {
        Console.WriteLine("[FATAL] Invalid cron expression(s) in config.yaml:");
        foreach (var err in cronErrors)
            Console.WriteLine($"        {err}");
        Console.WriteLine("        Fix config.yaml and restart.");
        Environment.Exit(1);
    }
}

// === Serilog structured logging ===
// Quick feature flag lookup for logging sinks (before DI is available).
// emit a warning when the lookup fails so operators running on cached defaults can see it;
// emit a warning when the metrics flag is explicitly disabled so silent monitoring loss is
// visible in SIEM.
var sinkFlags = new Dictionary<string, bool>();
var sinkFlagsQueryFailed = false;
Exception? sinkFlagsQueryError = null;
// Skip the DB query entirely in setup mode — tables don't exist yet and the errors
// bury the setup token in the console output.
if (!isSetupMode)
{
    try
    {
        var flagConnBuilder = new MySqlConnector.MySqlConnectionStringBuilder
        {
            Server = config.DB.App.Host,
            Port = (uint)config.DB.App.Port,
            Database = config.DB.App.Database,
            UserID = config.DB.App.Username,
            Password = config.DB.App.Password
        };
        using var flagConn = new MySqlConnector.MySqlConnection(flagConnBuilder.ConnectionString);
        flagConn.Open();
        using var flagCmd = new MySqlConnector.MySqlCommand("SELECT Name, Enabled FROM FeatureFlags WHERE Name IN ('Syslog.Enabled','EventLog.Enabled','Metrics.Enabled')", flagConn);
        using var reader = flagCmd.ExecuteReader();
        while (reader.Read())
            sinkFlags[reader.GetString(0)] = reader.GetBoolean(1);
    }
    catch (Exception ex)
    {
        // DB may not exist yet (first run before bootstrap). Remember so we can log a
        // warning after the host logger is wired up.
        sinkFlagsQueryFailed = true;
        sinkFlagsQueryError = ex;
    }
}

var serilogMinLevel = config.Logging.MinLevel?.ToLowerInvariant() switch
{
    "debug" => LogEventLevel.Debug,
    "warning" => LogEventLevel.Warning,
    "error" => LogEventLevel.Error,
    _ => LogEventLevel.Information
};
// Use a LoggingLevelSwitch so the min level can be changed at runtime via the config API.
var loggingLevelSwitch = new Serilog.Core.LoggingLevelSwitch(serilogMinLevel);
builder.Services.AddSingleton(loggingLevelSwitch);

// Enforce per-sink minimum level caps. Setting MinLevel=Debug
// globally must not pump Debug into persistent/remote sinks; only the console sink
// inherits the switch level. File/syslog/eventlog stay at Information minimum so a
// single local-debug session cannot blow up SIEM storage or log credentialed material.
var persistentSinkMinLevel = serilogMinLevel < LogEventLevel.Information
    ? LogEventLevel.Information
    : serilogMinLevel;

// Wire Serilog SelfLog to stderr + a Prometheus counter so sink
// failures (disk full, permission error, queue overflow) are visible. Registered
// once — subsequent calls are no-ops.
Serilog.Debugging.SelfLog.Enable(msg =>
{
    try
    {
        MetricsService.LogSinkDropped.Inc();
    }
    catch { /* registry not ready yet — ignore */ }
    try { Console.Error.WriteLine("[Serilog SelfLog] " + msg); } catch { }
});

// Running under a container or systemd, switch the console to the
// CompactJsonFormatter so Loki/Datadog/Fluent Bit get structured events from stdout.
// Interactive `dotnet run` keeps the human-readable template.
var runningInContainer = string.Equals(
    Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase);
var runningUnderSystemd = SystemdHelpers.IsSystemdService();
var consoleLogFormat = ConsoleLogFormatResolver.Resolve(
    config.Logging.ConsoleFormat, runningUnderSystemd, runningInContainer);

// Resolve VerboseErrors: env var overrides config.yaml.
// When false (production default), EF Core and ASP.NET framework errors are clamped to
// Critical so only clean application-level messages appear. When true (dev/staging),
// full stack traces flow through for debugging.
var verboseErrors = config.Logging.VerboseErrors;
var verboseEnv = Environment.GetEnvironmentVariable("MODULARCA_VERBOSE_ERRORS");
if (!string.IsNullOrEmpty(verboseEnv))
    verboseErrors = string.Equals(verboseEnv, "true", StringComparison.OrdinalIgnoreCase)
                 || verboseEnv == "1";

// In setup mode, force verbose off — the placeholder DB generates useless errors.
if (isSetupMode)
    verboseErrors = false;

var efCoreLevel = verboseErrors ? LogEventLevel.Warning : LogEventLevel.Fatal;
var aspNetLevel = verboseErrors ? LogEventLevel.Warning : LogEventLevel.Warning; // always Warning minimum

builder.Host.UseSerilog((context, services, configuration) =>
{
    configuration
        .MinimumLevel.ControlledBy(loggingLevelSwitch)
        // Positive override so ModularCA.* logs are not clamped by the
        // Microsoft.AspNetCore warning override (which also affects MVC-sourced events).
        .MinimumLevel.Override("ModularCA", LogEventLevel.Information)
        .MinimumLevel.Override("Microsoft.AspNetCore", aspNetLevel)
        .MinimumLevel.Override("Microsoft.EntityFrameworkCore", efCoreLevel)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Application", "ModularCA");

    // Console sink — one line per event with a syslog priority prefix under systemd, CLEF
    // JSON for a container's log shipper, readable template for a terminal. See
    // ConsoleLogFormatResolver for why systemd and container are no longer the same case.
    switch (consoleLogFormat)
    {
        case ConsoleLogFormat.Systemd:
            configuration.WriteTo.Console(new SystemdTextFormatter());
            break;
        case ConsoleLogFormat.Json:
            configuration.WriteTo.Console(new CompactJsonFormatter());
            break;
        default:
            configuration.WriteTo.Console(outputTemplate:
                "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {SourceContext}{NewLine}  {Message:lj}{NewLine}{Exception}");
            break;
    }

    // File sink (always JSON) — capped at persistentSinkMinLevel so Debug does not
    // reach rolled files when toggled globally.
    // Resolve a relative path against the binary, not the process CWD. Serilog's file sink
    // resolves relative paths against Environment.CurrentDirectory, which under systemd is
    // whatever WorkingDirectory= says and under `dotnet run` is the project directory. The
    // bootstrap sink above already uses AppContext.BaseDirectory, so the two logs landed in
    // different places and an operator tailing the app directory saw only the bootstrap file
    // while every controller warning went somewhere else.
    // An empty FilePath would make Path.Combine return the base directory itself, so the sink
    // would target a directory instead of failing loudly. AdminConfigController accepts any
    // non-null value, empty string included, so fall back to the documented default.
    var configuredLogPath = string.IsNullOrWhiteSpace(config.Logging.FilePath)
        ? "logs/modularca-.log"
        : config.Logging.FilePath;
    var resolvedLogPath = Path.IsPathRooted(configuredLogPath)
        ? configuredLogPath
        : Path.Combine(AppContext.BaseDirectory, configuredLogPath);

    configuration.WriteTo.File(new CompactJsonFormatter(), resolvedLogPath,
        restrictedToMinimumLevel: persistentSinkMinLevel,
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: config.Logging.RetentionDays,
        fileSizeLimitBytes: (long)config.Logging.MaxFileSizeMb * 1024 * 1024,
        rollOnFileSizeLimit: true,
        shared: true,
        flushToDiskInterval: TimeSpan.FromSeconds(2));

    // Syslog sink (RFC 5424 — SecurityOnion, Splunk, rsyslog) — gated solely by the
    // Syslog.Enabled feature flag (admin UI toggle). YAML controls sink-specific
    // config (host, port, protocol, app name, facility) only; a valid Host is still
    // required before the sink is wired so an enabled-but-unconfigured flag is a
    // no-op. The Facility string is parsed against Serilog.Sinks.Syslog.Facility;
    // malformed/unknown values fall back to Local0 rather than crashing startup.
    var syslogFlagEnabled = sinkFlags.GetValueOrDefault("Syslog.Enabled", true);
    if (syslogFlagEnabled && !string.IsNullOrWhiteSpace(config.Logging.Syslog.Host))
    {
        var syslogFacility = Enum.TryParse<Serilog.Sinks.Syslog.Facility>(
            config.Logging.Syslog.Facility, ignoreCase: true, out var parsedFacility)
            ? parsedFacility
            : Serilog.Sinks.Syslog.Facility.Local0;
        if (config.Logging.Syslog.Protocol?.ToUpperInvariant() == "TCP")
            configuration.WriteTo.TcpSyslog(config.Logging.Syslog.Host, config.Logging.Syslog.Port,
                appName: config.Logging.Syslog.AppName,
                facility: syslogFacility);
        else
            configuration.WriteTo.UdpSyslog(config.Logging.Syslog.Host, config.Logging.Syslog.Port,
                appName: config.Logging.Syslog.AppName,
                facility: syslogFacility);
    }

    // Windows Event Log sink — gated solely by the EventLog.Enabled feature flag
    // (admin UI toggle). YAML controls Source/LogName only.
    var eventLogFlagEnabled = sinkFlags.GetValueOrDefault("EventLog.Enabled", true);
    if (eventLogFlagEnabled && OperatingSystem.IsWindows())
    {
        configuration.WriteTo.EventLog(
            config.Logging.EventLog.Source,
            logName: config.Logging.EventLog.LogName,
            restrictedToMinimumLevel: persistentSinkMinLevel);
    }

    // Network sink (TCP — SecurityOnion, Splunk HEC, custom collectors)
    // Uses syslog TCP for network forwarding. For dedicated TCP/UDP sinks,
    // configure Syslog with TCP protocol and the target SIEM endpoint.
    // Direct TCP sink support can be added when Serilog.Sinks.Network API stabilizes.
});

// Add services to the container.
// Enforce TLS on MySQL connections. Default is "Required"; operators
// can tighten to VerifyCA/VerifyFull or (non-compliant) downgrade via db.yaml / env var.
// Unparseable values clamp back to MySqlSslMode.Required so a typo cannot silently drop TLS.
var appSslMode = Enum.TryParse<MySqlConnector.MySqlSslMode>(config.DB.App.SslMode, ignoreCase: true, out var _appSsl)
    ? _appSsl : MySqlConnector.MySqlSslMode.Required;
var appConnBuilder = new MySqlConnector.MySqlConnectionStringBuilder
{
    Server = config.DB.App.Host,
    Port = (uint)config.DB.App.Port,
    Database = config.DB.App.Database,
    UserID = config.DB.App.Username,
    Password = config.DB.App.Password,
    SslMode = appSslMode
};
var appConnStr = appConnBuilder.ConnectionString;

// EF Core command interceptor measuring db query duration.
// Shared singleton instance — interceptor itself is stateless and thread-safe.
var dbDurationInterceptor = new ModularCA.Core.Services.DbCommandDurationInterceptor();

// Default CommandTimeout (30s) applied at registration. Heavy paths
// (CRL generation, compliance reports, compliance scan, cert list) may override to a
// higher value via `db.Database.SetCommandTimeout(...)` before executing long queries.
const int defaultCommandTimeoutSeconds = 30;

// In setup mode with no DB credentials, the prior code wired a dummy
// connection to `localhost:3306` as root with empty password — a footgun on developer
// machines with a local MySQL. Instead register a sentinel DbContextOptions that fails
// loudly on first query, forcing callers in setup mode to route through the setup wizard.
if (isSetupMode && string.IsNullOrWhiteSpace(config.DB.App.Username))
{
    builder.Services.AddDbContext<ModularCADbContext>(options =>
        options.UseMySql(
            // Syntactically-valid but unusable connection string: the hostname is an RFC
            // 2606 reserved name that will never resolve, and the credentials are empty.
            "Server=setup-placeholder.invalid;Database=modularca-setup;Uid=disabled;Pwd='';",
            new MySqlServerVersion(new System.Version(8, 0, 0)),
            mysql => mysql.CommandTimeout(defaultCommandTimeoutSeconds))
        .AddInterceptors(dbDurationInterceptor)
        .ConfigureWarnings(w => w.Ignore(
            Microsoft.EntityFrameworkCore.Diagnostics.CoreEventId
                .PossibleIncorrectRequiredNavigationWithQueryFilterInteractionWarning)));
}
else
{
    builder.Services.AddDbContext<ModularCADbContext>(options =>
        options.UseMySql(
            appConnStr,
            ServerVersion.AutoDetect(appConnStr),
            mysql => mysql.CommandTimeout(defaultCommandTimeoutSeconds)
        ).AddInterceptors(dbDurationInterceptor)
        .ConfigureWarnings(w => w.Ignore(
            Microsoft.EntityFrameworkCore.Diagnostics.CoreEventId
                .PossibleIncorrectRequiredNavigationWithQueryFilterInteractionWarning)));
}

builder.Services.AddSingleton(config);
builder.Services.AddSingleton(envOverlay);
builder.Services.AddSingleton<ModularCA.Core.Services.AuditHashChainService>();

// Entitlements are resolved once from a signed licence file and never change while the process
// runs, so this is a singleton: installing a licence is a file drop and a restart. A missing,
// malformed or unsigned licence degrades to the free edition and logs why — it is never a
// startup failure, because refusing to boot a certificate authority over a licence file would
// take issuance, CRL and OCSP down for a paperwork problem.
//
// Note this is deliberately NOT IFeatureFlagService. Flags live in a database table an
// administrator can edit; an entitlement stored where the operator can flip it is not an
// entitlement. The two compose: available = entitled && enabled.
builder.Services.AddSingleton<ModularCA.Shared.Interfaces.IEntitlementService>(sp =>
{
    var licensePath = Path.Combine(AppContext.BaseDirectory, "config", "license.lic");
    string? document = null;
    try
    {
        if (File.Exists(licensePath))
            document = File.ReadAllText(licensePath);
    }
    catch (Exception ex)
    {
        // An unreadable file is the free edition, same as an absent one. Logged via the service
        // below rather than here so there is a single place that reports licence state.
        Serilog.Log.Warning(ex, "Licence file at {Path} could not be read", licensePath);
    }

    return new ModularCA.Core.Services.EntitlementService(
        document,
        sp.GetService<Microsoft.Extensions.Logging.ILogger<ModularCA.Core.Services.EntitlementService>>());
});

// === Audit database (optional — only registered if configured) ===
if (!string.IsNullOrWhiteSpace(config.DB.Audit.Database))
{
    // Audit DB gets the same TLS-Required default as the app DB.
    var auditSslMode = Enum.TryParse<MySqlConnector.MySqlSslMode>(config.DB.Audit.SslMode, ignoreCase: true, out var _auditSsl)
        ? _auditSsl : MySqlConnector.MySqlSslMode.Required;
    var auditConnBuilder = new MySqlConnector.MySqlConnectionStringBuilder
    {
        Server = config.DB.Audit.Host,
        Port = (uint)config.DB.Audit.Port,
        Database = config.DB.Audit.Database,
        UserID = config.DB.Audit.Username,
        Password = config.DB.Audit.Password,
        SslMode = auditSslMode
    };
    var auditConnStr = auditConnBuilder.ConnectionString;
    builder.Services.AddDbContext<AuditDbContext>(options =>
        options.UseMySql(
            auditConnStr,
            ServerVersion.AutoDetect(auditConnStr),
            mysql => mysql.CommandTimeout(defaultCommandTimeoutSeconds)
        ).AddInterceptors(dbDurationInterceptor));
}

// Scoped tenant context feeds the global query filter in
// ModularCADbContext so every tenant-scoped read is fenced to the authenticated caller's
// accessible tenants. Populated by TenantResolutionMiddleware after the auth pipeline.
builder.Services.AddScoped<ModularCA.Shared.Interfaces.ITenantContext, ModularCA.API.Services.TenantContext>();

builder.Services.AddScoped<ISigningProfileService, SigningProfileService>();

builder.Services.AddScoped<IssuanceValidationService>();
builder.Services.AddScoped<CertificateBuilderService>();
builder.Services.AddSingleton<IPqcKeyGenerationService, PqcKeyGenerationService>();
builder.Services.AddScoped<ICertPolicyService, CertPolicyService>();
builder.Services.AddScoped<IQuotaService, QuotaService>();
builder.Services.AddScoped<ITenantPolicyChangeService, TenantPolicyChangeService>();
builder.Services.AddScoped<ModularCA.Auth.Authorization.IControlledUserCeremonyService, ModularCA.Auth.Authorization.ControlledUserCeremonyService>();
builder.Services.AddScoped<ICertificateIssuanceService, CertificateIssuanceService>();
builder.Services.AddScoped<ICertificateAccessService, CertificateAccessService>();
builder.Services.AddScoped<ICertificateAccessEvaluator, CertificateAccessEvaluator>();
builder.Services.AddScoped<ICertificateAccessAssignment, CertificateAccessAssignment>();
builder.Services.AddScoped<IUserManagementService, UserManagementService>();

builder.Services.AddScoped<ICsrService, CsrService>();
builder.Services.AddScoped<ICrlService, CrlService>();
builder.Services.AddScoped<ICaServiceUrlService, CaServiceUrlService>();

builder.Services.AddScoped<ICrlConfigurationService, CrlConfigurationService>();
builder.Services.AddScoped<LdapPublisherJob>();
builder.Services.AddScoped<ISchedulerJob, LdapPublisherJob>(sp => sp.GetRequiredService<LdapPublisherJob>());
builder.Services.AddScoped<CrlExportJob>();
builder.Services.AddScoped<ISchedulerJob, CrlExportJob>(sp => sp.GetRequiredService<CrlExportJob>());
// Singleton registry of system (singleton) scheduler jobs — backs the unified
// /api/v1/admin/scheduler endpoints (cron writeback, manual-run dispatch). Holds
// no per-request state so a single instance is safe; each manual run creates its
// own DI scope.
builder.Services.AddSingleton<ModularCA.Shared.Interfaces.ISchedulerJobRegistry, ModularCA.Core.Services.SchedulerJobRegistry>();

// SchedulerJobRunner — shared per-execution wrapper for timeout, metrics, audit, and
// SchedulerJobStates persistence. Required by SingletonCronJob and PerRowScheduledJob
// inheritors. The instanceId is sourced from SchedulerService.InstanceId so failure
// alerts attribute the right replica even when multiple instances race for the lease.
builder.Services.AddSingleton(sp => new ModularCA.Core.Services.SchedulerJobRunner(
    sp,
    sp.GetRequiredService<ILogger<ModularCA.Core.Services.SchedulerJobRunner>>(),
    sp.GetRequiredService<SystemConfig>(),
    ModularCA.Core.Services.SchedulerService.InstanceId));
if (!isSetupMode)
    builder.Services.AddHostedService<SchedulerService>();

// Bounded-channel drain for network audit rows. Replaces the
// per-request Task.Run/CreateScope pattern in RequestAuditMiddleware; batches
// AuditNetworkEntity inserts (100 rows or 1 s) so hot-path requests never pay
// a DB round-trip. Runs in both setup and runtime mode so the setup UI's
// self-traffic is still auditable.
builder.Services.AddHostedService<AuditNetworkDrainService>();

// Stage 2 TLS provisioning: if Mode=Pending, register the hosted service that issues
// the real web TLS cert via the standard pipeline on first startup.
if (!isSetupMode && string.Equals(config.Https.Mode?.Trim(), "Pending", StringComparison.OrdinalIgnoreCase))
    builder.Services.AddHostedService<ModularCA.Core.Services.WebTlsProvisioningService>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();

builder.Services.AddScoped<ICertificateRevocationService, CertificateRevocationService>();

// ACME Protocol Services
builder.Services.AddScoped<IAcmeNonceService, AcmeNonceService>();
builder.Services.AddScoped<IAcmeAccountService, AcmeAccountService>();
builder.Services.AddScoped<IAcmeJwsService, AcmeJwsService>();
builder.Services.AddScoped<IAcmeAuthorizationService, AcmeAuthorizationService>();
builder.Services.AddScoped<IAcmeChallengeService, AcmeChallengeService>();
builder.Services.AddScoped<IAcmeOrderService, AcmeOrderService>();
builder.Services.AddScoped<ICaaCheckService, CaaCheckService>();
// Per-account ACME rate limiter (new-order / finalize /
// failed-validation). Runs alongside the per-IP buckets in ProtocolRateLimitMiddleware.
builder.Services.AddSingleton<IAcmeAccountRateLimiter, AcmeAccountRateLimiter>();
builder.Services.AddScoped<AcmeCleanupJob>();
builder.Services.AddScoped<ISchedulerJob, AcmeCleanupJob>(sp => sp.GetRequiredService<AcmeCleanupJob>());
// The ACME http-01 validator must NOT auto-follow
// redirects to arbitrary hosts. We disable the default auto-redirect behavior
// here; AcmeChallengeService performs a single-hop, allow-listed redirect
// handoff manually per RFC 8555 §8.3.
builder.Services.AddHttpClient("AcmeChallenge")
    .ConfigurePrimaryHttpMessageHandler(() => new System.Net.Http.SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        MaxConnectionsPerServer = 4,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        PooledConnectionLifetime = TimeSpan.FromSeconds(30)
    })
    .ConfigureHttpClient(c =>
    {
        // Per-challenge timeout: matches the redirect-prevention remediation. The
        // per-request deadline is enforced by a CancellationTokenSource inside
        // the validator so individual address attempts are capped.
        c.Timeout = TimeSpan.FromSeconds(10);
    });
builder.Services.AddHttpClient("CtLog");

// OCSP Protocol Service
builder.Services.AddScoped<IOcspService, OcspResponderService>();

// EST Protocol Service
builder.Services.AddScoped<IEstService, EstService>();

// SCEP Protocol Service
builder.Services.AddScoped<IScepService, ScepService>();

// CMP Protocol Service
builder.Services.AddScoped<ICmpService, CmpService>();

// Centralized CA Resolver Service
builder.Services.AddScoped<ICaResolverService, CaResolverService>();

// cert-manager integration API key filter
builder.Services.AddScoped<ModularCA.API.Filters.CertManagerApiKeyFilter>();

// CA creation at runtime (root + intermediate)
builder.Services.AddScoped<CaCreationService>();

// Use the already-loaded config instance instead of building a temporary provider
var loadedConfig = config;

// In setup mode, generate a temporary JWT secret so auth middleware doesn't crash
// (no real auth is needed — setup endpoints are unauthenticated)
if (isSetupMode && string.IsNullOrWhiteSpace(loadedConfig.JWT.Secret))
{
    loadedConfig.JWT.Secret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(64));
}

// Validate JWT secret length (skip in setup mode where it's auto-generated)
if (!isSetupMode && Encoding.UTF8.GetByteCount(loadedConfig.JWT.Secret) < 64)
{
    Console.WriteLine("[FATAL] JWT secret is too short (minimum 64 bytes required).");
    Console.WriteLine("        Regenerate config.yaml or set a longer JWT.Secret value.");
    Environment.Exit(1);
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var key = Encoding.UTF8.GetBytes(loadedConfig.JWT.Secret);
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = loadedConfig.JWT.Issuer,
            ValidateAudience = true,
            ValidAudience = loadedConfig.JWT.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateLifetime = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            ClockSkew = TimeSpan.FromMinutes(1),
            // JwtTokenService emits the username under the custom claim name "username", not
            // "name" or "unique_name". Without this, ClaimsIdentity.Name is always null, and any
            // code reading User.Identity.Name silently sees an unauthenticated-looking caller —
            // which disabled the EST caller-to-CSR binding entirely and defeated the fallback in
            // JwtIpBindingMiddleware.
            NameClaimType = "username"
        };

    })
    // HTTP Basic for EST, per RFC 7030 section 3.2.3. Added as a NAMED scheme and never as the
    // default or a fallback: only EstController asks for it by name, so a Basic header presented
    // to any other endpoint still authenticates nothing. Making it a default would give every
    // authenticated route in the product a password-only, MFA-free entry path.
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions,
               ModularCA.API.Auth.EstBasicAuthenticationHandler>(
        ModularCA.API.Auth.EstBasicAuthenticationHandler.SchemeName, _ => { });

// Shared credential verification for protocols that carry no session. Extracted from
// AuthController.Login so EST's Basic path gets the same lockout counters, account-state gating
// and audit records rather than a weaker parallel implementation.
builder.Services.AddScoped<ModularCA.Auth.Services.IProtocolCredentialService,
                           ModularCA.Auth.Services.ProtocolCredentialService>();

builder.Services.AddScoped<ModularCA.Auth.Authorization.ICaGroupAuthorizationService, ModularCA.Auth.Authorization.CaGroupAuthorizationService>();
builder.Services.AddScoped<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, ModularCA.Auth.Authorization.CaGroupAuthorizationHandler>();

builder.Services.AddAuthorization(options =>
{
    // System-level policies (system group membership required)
    options.AddPolicy("SystemAdmin", policy => policy.Requirements.Add(new ModularCA.Auth.Authorization.CaGroupRequirement(ModularCA.Shared.Authorization.Capabilities.SystemManage, isSystemOnly: true)));
    options.AddPolicy("SystemOperator", policy => policy.Requirements.Add(new ModularCA.Auth.Authorization.CaGroupRequirement(ModularCA.Shared.Authorization.Capabilities.CaManage, isSystemOnly: true)));
    options.AddPolicy("SystemAuditor", policy => policy.Requirements.Add(new ModularCA.Auth.Authorization.CaGroupRequirement(ModularCA.Shared.Authorization.Capabilities.AuditView, isSystemOnly: true)));
    // CA-scoped policies (system, tenant, or CA group membership)
    options.AddPolicy("CaAdmin", policy => policy.Requirements.Add(new ModularCA.Auth.Authorization.CaGroupRequirement(ModularCA.Shared.Authorization.Capabilities.CaManage)));
    options.AddPolicy("CaOperator", policy => policy.Requirements.Add(new ModularCA.Auth.Authorization.CaGroupRequirement(ModularCA.Shared.Authorization.Capabilities.CertRevoke)));
    options.AddPolicy("CaAuditor", policy => policy.Requirements.Add(new ModularCA.Auth.Authorization.CaGroupRequirement(ModularCA.Shared.Authorization.Capabilities.CertView)));
    options.AddPolicy("CaUser", policy => policy.Requirements.Add(new ModularCA.Auth.Authorization.CaGroupRequirement(ModularCA.Shared.Authorization.Capabilities.CertRequest)));

    // Fail closed. Any controller/action without an
    // explicit [Authorize] attribute now requires authentication by default. Genuinely
    // public endpoints (setup wizard, public CA cert, CRL, OCSP, ACME, EST, SCEP, CMP, TSA)
    // are explicitly marked [AllowAnonymous] and remain exempt.
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// FIDO2/WebAuthn second-factor authentication.
//
// rpId and origin are canonicalized on Https.PublicDomain / Https.PublicPort —
// there is no separate WebAuthn.RelyingPartyId or WebAuthn.Origin. The three
// values (TLS server-cert SAN, rpId, and origin) MUST agree or the browser
// rejects the assertion, so they share a single source of truth. When
// PublicDomain is unset (e.g., very first boot before setup completes) we
// fall back to "localhost" / "https://localhost:{port}" so Fido2 can still
// initialize; setup will overwrite PublicDomain before WebAuthn is actually
// used in anger.
if (config.WebAuthn.Enabled)
{
    var rpId = !string.IsNullOrWhiteSpace(config.Https.PublicDomain)
        ? config.Https.PublicDomain
        : "localhost";
    var origin = !string.IsNullOrWhiteSpace(config.Https.PublicDomain)
        ? config.Https.GetPublicHttpsBaseUrl()
        : $"https://localhost:{config.Https.Port}";

    builder.Services.AddFido2(options =>
    {
        options.ServerDomain = rpId;
        options.ServerName = config.WebAuthn.RelyingPartyName;
        options.Origins = new HashSet<string> { origin };
    });
}

// ICF-07: Distributed cache — Redis when configured, in-process memory otherwise.
// MFA step-up tokens, WebAuthn challenges, and token revocation all flow through IDistributedCache.
if (config.Redis.Enabled && !string.IsNullOrWhiteSpace(config.Redis.ConnectionString))
{
    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = config.Redis.ConnectionString;
        options.InstanceName = config.Redis.InstanceName ?? "ModularCA:";
    });
    // The connection string carries the password ("host:6379,password=..."), and this line
    // lands in journald and whatever ships logs onward. That Redis holds the Data Protection
    // keyring, which decrypts every TOTP secret. Print the endpoints only.
    string redisDescription;
    try
    {
        redisDescription = StackExchange.Redis.ConfigurationOptions.Parse(config.Redis.ConnectionString)
            .ToString(includePassword: false);
    }
    catch
    {
        redisDescription = "(configured; not shown)";
    }
    Console.WriteLine("[Cache] Using Redis distributed cache at {0}", redisDescription);
}
else
{
    builder.Services.AddDistributedMemoryCache();
    var cacheRunsInContainer = string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase);
    var cacheIsProduction = builder.Environment.IsProduction();
    if (cacheRunsInContainer || cacheIsProduction)
    {
        Console.WriteLine("[Cache] WARNING: using in-process DistributedMemoryCache for MFA step-up, WebAuthn, and token revocation.");
        Console.WriteLine("[Cache] Multi-node deployments MUST use sticky sessions or these flows will silently drop state.");
        Console.WriteLine("[Cache] Set Redis.Enabled=true and Redis.ConnectionString for horizontal scaling.");
    }
}

// Data Protection API — encrypts TOTP secrets at rest.
//
// SINGLE-NODE LIMITATION. The Data Protection keyring is
// persisted to the local filesystem at config/dp-keys with no shared backend.
// In a multi-node deployment each instance generates its own keyring and the
// nodes will be unable to decrypt each other's TOTP secrets — TOTP login on
// node A will silently fail on node B. Until this is migrated to a shared
// store (Redis with ProtectKeysWithCertificate, a database-backed XML
// repository, or a cloud KMS like Azure Key Vault) operators MUST run a
// single instance OR pin sticky sessions to a single backend per user.
//
// The on-disk dp-keys directory has its ACLs tightened to the service account
// via FileSecurityUtil.SetOwnerOnly below — disk read still equals TOTP
// plaintext recovery, so backups MUST exclude config/dp-keys (or encrypt the
// backup with a key not co-located on the same host).
var dpKeysDir = Path.Combine(AppContext.BaseDirectory, "config", "dp-keys");
Directory.CreateDirectory(dpKeysDir);
// Tighten ACLs on every keyring file inside dp-keys so disk
// read of a backup or a forgotten copy doesn't trivially recover the file key
// that decrypts every TOTP secret. FileSecurityUtil.SetOwnerOnly is a no-op
// on directories on Windows, so iterate the existing key xml files. New keys
// landed by AddDataProtection at runtime will inherit the tightened parent
// directory ACL on POSIX; on Windows the data-protection runtime writes new
// files atomically and we'd need a FileSystemWatcher hook to harden them on
// each rotation — accepted limitation for the single-node case (see comment
// block above).
try
{
    foreach (var dpFile in Directory.EnumerateFiles(dpKeysDir, "key-*.xml"))
    {
        ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly(dpFile);
    }
}
catch (Exception dpAclEx)
{
    Console.WriteLine($"[DataProtection] WARNING: failed to tighten ACL on {dpKeysDir}: {dpAclEx.Message}");
}
// ICF-08: Data Protection keyring — Redis when available, filesystem otherwise.
var dpBuilder = builder.Services.AddDataProtection()
    .SetApplicationName("ModularCA");

if (config.Redis.Enabled && !string.IsNullOrWhiteSpace(config.Redis.ConnectionString))
{
    // When Redis is available, persist Data Protection keys there for multi-node support
    var redis = StackExchange.Redis.ConnectionMultiplexer.Connect(config.Redis.ConnectionString);
    dpBuilder.PersistKeysToStackExchangeRedis(redis, "ModularCA:DataProtection-Keys");
    Console.WriteLine("[DataProtection] Keyring persisted to Redis");
}
else
{
    dpBuilder.PersistKeysToFileSystem(new DirectoryInfo(dpKeysDir));
}

builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();
// DPoP proof-of-possession validation for refresh-token binding (theft defense without IP pinning).
builder.Services.AddScoped<ModularCA.Auth.Services.IDpopProofService, ModularCA.Auth.Services.DpopProofService>();
builder.Services.AddScoped<IPasswordPolicyService, PasswordPolicyService>();

// Configure dependency injection — skip keystore loading in setup mode (files don't exist yet)
List<Org.BouncyCastle.X509.X509Certificate> trustedCAs;
List<CertificateAuthorityIdentity> fullCAs;

if (isSetupMode)
{
    trustedCAs = new();
    fullCAs = new();
}
else
{
    try
    {
        var loaded = StartupKeystoreLoader.LoadAll(
            yamlPath: Path.Combine(AppContext.BaseDirectory, "config", "keystore.yaml"),
            keystorePath: Path.Combine(AppContext.BaseDirectory, "keystores"),
            dbConnStr: appConnStr
        );
        trustedCAs = loaded.TrustedCAs;
        fullCAs = loaded.FullCAs
            .Select(x => new CertificateAuthorityIdentity(x.Cert, new ModularCA.Keystore.Adapters.SoftwarePrivateKeyHandle(x.PrivateKey)))
            .ToList();
    }
    catch (Exception ex) when (IsKeystoreIntegrityFailure(ex))
    {
        // Fail closed. A keystore that is present but does not verify means the CA private key
        // material cannot be trusted, and continuing would serve a CA whose integrity checks were
        // performed, failed, and then ignored.
        //
        // This whole block used to be a single `catch (Exception ex)` that swallowed the
        // SecurityException from a failed file signature, the SPKI pin-MAC mismatch, and per-entry
        // signature failures, along with the AES-GCM tag mismatch — then booted with an empty CA
        // registry while printing "This is expected during initial setup" on a path where
        // isSetupMode was already handled above, so it never is setup. Flipping one byte of
        // ca-certs.keystore fired the entire integrity apparatus correctly and discarded it.
        Console.Error.WriteLine();
        Console.Error.WriteLine("[FATAL] Keystore integrity verification failed. Refusing to start.");
        Console.Error.WriteLine($"        {ex.GetType().Name}: {ex.Message}");
        Console.Error.WriteLine();
        Console.Error.WriteLine("        The keystore did not verify. This means the file, its signature, or the");
        Console.Error.WriteLine("        pinned signing identity has been altered. Restore from a known-good");
        Console.Error.WriteLine("        backup; do not delete the keystore to get past this message.");
        Console.Error.WriteLine();
        Environment.Exit(1);
        throw; // Unreachable. Present so the compiler sees this path terminate.
    }
    catch (Exception ex)
    {
        // Everything else — the keystore files not written yet, the database not reachable to
        // read the pinned signer, a malformed keystore.yaml. These are recoverable states that
        // the setup and migration paths below already tolerate, so starting with an empty CA
        // registry is preserved deliberately rather than made fatal here.
        //
        // The old wording claimed this was "expected during initial setup", which was never true
        // on this branch. Say what actually happened instead.
        Console.WriteLine($"[WARNING] Could not load keystores: {ex.GetType().Name}: {ex.Message}");
        Console.WriteLine("          Starting with an empty CA registry. No certificate can be issued");
        Console.WriteLine("          until this is resolved.");
        trustedCAs = new();
        fullCAs = new();
    }
}

// Distinguishes "this keystore failed its integrity checks" from "this keystore could not be
// read at all". Only the former is fatal — see the catch blocks above. SecurityException covers
// the file and per-entry signatures and the SPKI pin MAC; CryptographicException covers the
// AES-GCM authentication tag; InvalidDataException covers a malformed or truncated file. The
// inner-exception walk matters because the loader wraps failures as it unwinds.
static bool IsKeystoreIntegrityFailure(Exception? ex)
{
    for (; ex != null; ex = ex.InnerException)
    {
        if (ex is System.Security.SecurityException
            or System.Security.Cryptography.CryptographicException
            or InvalidDataException)
            return true;
    }
    return false;
}

// Load HSM-backed CA signers if PKCS#11 is configured and enabled
Pkcs11SessionManager? hsmSession = null;
if (config.Hsm?.Enabled == true && !string.IsNullOrEmpty(config.Hsm.ModulePath))
{
    try
    {
        hsmSession = new Pkcs11SessionManager(config.Hsm.ModulePath, config.Hsm.SlotId, config.Hsm.Pin);
        var hsmSigners = StartupKeystoreLoader.LoadHsmSigners(hsmSession, appConnStr);

        foreach (var (cert, keyHandle) in hsmSigners)
        {
            var identity = new CertificateAuthorityIdentity(cert, keyHandle);
            fullCAs.Add(identity);
            trustedCAs.Add(cert);
            Console.WriteLine($"[HSM] CA loaded: {cert.SubjectDN}");
        }

        // Register the session manager as a singleton so runtime services can access the HSM
        builder.Services.AddSingleton(hsmSession);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[HSM] Initialization failed: {ex.Message}");
        Console.WriteLine("[HSM] Continuing with software-only keystore.");
        hsmSession = null;
    }
}

var registry = new MultiCARegistry(fullCAs, trustedCAs);

builder.Services.AddSingleton<MultiCARegistry>(registry);
builder.Services.AddSingleton<IKeystoreCertificates>(registry);

// Key wrapping passphrase provider for HKDF-based non-RSA private key encryption
var kwYamlPath = Path.Combine(AppContext.BaseDirectory, "config", "keystore.yaml");
if (!isSetupMode && File.Exists(kwYamlPath))
{
    builder.Services.AddSingleton<IKeyWrappingPassphraseProvider>(
        new KeystoreKeyWrappingPassphraseProvider(kwYamlPath));
}
else
{
    // Setup mode or keystore.yaml doesn't exist yet (post-reset) — provide no-op provider
    builder.Services.AddSingleton<IKeyWrappingPassphraseProvider>(
        new SetupModeKeyWrappingPassphraseProvider());
}


var Config = builder.Configuration.GetSection("CA");

builder.Services.AddScoped<ICsrService, CsrService>();

// Global JsonStringEnumConverter so request-body enums bind from their string names
// (e.g. "Superseded") instead of requiring integer codes. Without this, ASP.NET's
// default System.Text.Json options reject string enum values at model binding with
// "The JSON value could not be converted to <Enum>". Adding it once here removes the
// need for per-property [JsonConverter] attributes on every request DTO.
builder.Services.AddControllers().AddJsonOptions(opts =>
{
    opts.JsonSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
    // Emit every DateTime as ISO-8601 UTC with a trailing 'Z'. EF (MySQL datetime) and NCrontab
    // hand us DateTimeKind.Unspecified values, which System.Text.Json would otherwise serialize
    // without a zone — causing browsers to parse UTC instants as local time. See the converter.
    opts.JsonSerializerOptions.Converters.Add(new ModularCA.API.Json.UtcDateTimeJsonConverter());
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.OpenApiInfo
    {
        Title = "ModularCA API",
        Version = "0.1.0-rc1",
        Description = "Enterprise Certificate Authority — REST API for certificate lifecycle management, PKI protocols, and administration.",
        Contact = new Microsoft.OpenApi.OpenApiContact { Name = "ModularCA" }
    });

    // JWT Bearer auth in Swagger UI
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer {token}'",
        Name = "Authorization",
        In = Microsoft.OpenApi.ParameterLocation.Header,
        Type = Microsoft.OpenApi.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    // Security requirement applied globally — Swagger UI shows the lock icon on all endpoints

    // Include XML comments from the API project
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
        c.IncludeXmlComments(xmlPath);
});

builder.Services.AddScoped<ICertProfileService, CertProfileService>();
builder.Services.AddScoped<IProfileResolutionService, ProfileResolutionService>();
// Pre-flight for the validity ceiling: same three limits issuance applies, answered before the
// operator submits so the clamp never fires for someone who could have avoided it.
builder.Services.AddScoped<IValidityCeilingService, ValidityCeilingService>();

builder.Services.AddScoped<ICertificateStore, CertificateStore>();

builder.Services.AddSingleton<ITrustStoreProvider, InMemoryTrustStore>();
builder.Services.AddSingleton<ModularCA.Shared.Interfaces.IWhitelistService, ModularCA.Core.Services.WhitelistService>();

builder.Services.AddScoped<IFeatureFlagService, FeatureFlagService>();
builder.Services.AddScoped<ISecurityPolicyService, SecurityPolicyService>();
builder.Services.AddScoped<ILdapPublisherPolicyService, LdapPublisherPolicyService>();
// Encrypts LDAP publisher bind passwords at rest on the same Data Protection keyring that
// protects TOTP secrets. Registered here rather than in Core so Core keeps no dependency on
// ASP.NET Core Data Protection.
builder.Services.AddScoped<ModularCA.Shared.Interfaces.ILdapSecretProtector,
    ModularCA.API.Services.DataProtectionLdapSecretProtector>();
builder.Services.AddScoped<IProtocolRateLimitService, ProtocolRateLimitService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IProtocolAuditService, ProtocolAuditService>();
// Drains logs/bootstrap-audit-*.jsonl on first successful startup.
builder.Services.AddScoped<ModularCA.Core.Services.BootstrapAuditReplayService>();
builder.Services.AddSingleton<SiemLogFormatter>();
builder.Services.AddScoped<IEnrollmentTokenService, EnrollmentTokenService>();
builder.Services.AddScoped<IEnrollmentAuthorizationService, EnrollmentAuthorizationService>();
builder.Services.AddHostedService<ModularCA.API.Services.WhitelistRewarmService>();
builder.Services.AddScoped<ModularCA.Shared.Interfaces.IEnrollmentPrincipalAuthorizer, ModularCA.Auth.Authorization.EnrollmentPrincipalAuthorizer>();
builder.Services.AddScoped<ModularCA.Auth.Services.ILdapAuthService, ModularCA.Auth.Services.LdapAuthService>();
builder.Services.AddScoped<ICtSubmissionService, CtSubmissionService>();
builder.Services.AddScoped<ICertificateExportService, CertificateExportService>();
builder.Services.AddScoped<ITimestampService, TimestampService>();
builder.Services.AddScoped<ISshCaService, SshCaService>();
builder.Services.AddScoped<ILdapGroupProvider>(sp => sp.GetRequiredService<ModularCA.Auth.Services.ILdapAuthService>() as ILdapGroupProvider
    ?? throw new InvalidOperationException("LdapAuthService must implement ILdapGroupProvider"));
builder.Services.AddScoped<ILdapGroupSyncService, LdapGroupSyncService>();
builder.Services.AddScoped<LdapGroupSyncJob>();
builder.Services.AddScoped<ISchedulerJob, LdapGroupSyncJob>(sp => sp.GetRequiredService<LdapGroupSyncJob>());
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddSingleton<IWebhookService, WebhookService>();
builder.Services.AddHttpClient("Webhook")
    .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddScoped<INotificationService, NotificationService>();
builder.Services.AddScoped<ISecurityAlertService, SecurityAlertService>();
builder.Services.AddScoped<IKeyCeremonyService, KeyCeremonyService>();
builder.Services.AddScoped<CertExpiryNotificationJob>();
builder.Services.AddScoped<ISchedulerJob, CertExpiryNotificationJob>(sp => sp.GetRequiredService<CertExpiryNotificationJob>());
builder.Services.AddScoped<ComplianceScanJob>();
builder.Services.AddScoped<ISchedulerJob, ComplianceScanJob>(sp => sp.GetRequiredService<ComplianceScanJob>());
builder.Services.AddScoped<AutoRenewalJob>();
builder.Services.AddScoped<ISchedulerJob, AutoRenewalJob>(sp => sp.GetRequiredService<AutoRenewalJob>());
builder.Services.AddScoped<CertExpireJob>();
builder.Services.AddScoped<ISchedulerJob, CertExpireJob>(sp => sp.GetRequiredService<CertExpireJob>());
builder.Services.AddSingleton<ModularCA.Shared.Interfaces.IBackupArchiver, ModularCA.Bootstrap.BackupArchiver>();
builder.Services.AddScoped<BackupCreationJob>();
builder.Services.AddScoped<ISchedulerJob, BackupCreationJob>(sp => sp.GetRequiredService<BackupCreationJob>());
builder.Services.AddScoped<BackupVerificationJob>();
builder.Services.AddScoped<ISchedulerJob, BackupVerificationJob>(sp => sp.GetRequiredService<BackupVerificationJob>());
// Scheduled audit-retention job (chunked DELETE + optional gzip
// archive) across AuditLogs/AuditEst/AuditScep/AuditCmp/AuditAcme/AuditNetwork.
builder.Services.AddScoped<AuditRetentionJob>();
builder.Services.AddScoped<ISchedulerJob, AuditRetentionJob>(sp => sp.GetRequiredService<AuditRetentionJob>());
builder.Services.AddScoped<ICertHealthScoreService, CertHealthScoreService>();
builder.Services.AddScoped<IComplianceReportService, ComplianceReportService>();

builder.Services.AddHealthChecks()
    .AddCheck<ModularCA.API.HealthChecks.ModularCAHealthCheck>("modularca");

builder.Services.AddValidatorsFromAssemblyContaining<CreateSigningProfileValidator>();

builder.Services.AddScoped<ICsrParserService, CsrParserService>();

builder.Services.AddScoped<RequestProfileService>();
builder.Services.AddScoped<RequestProfileValidationService>();
builder.Services.AddScoped<IPolicySyncService, PolicySyncService>();

builder.Services.AddScoped<CertificateTemplateService>();

builder.Services.AddScoped<TrustAnchorService>();

// Validate CORS origins at
// startup. Reject wildcard, reject non-HTTPS origins that aren't explicit
// localhost, and fail startup loudly if anything slips through — credentials
// + wildcard CORS is a classic own-goal. The policy also adds method and
// header restrictions and gates registration on
// Http.EnableCors so a misset ASPNETCORE_ENVIRONMENT=Development cannot
// enable broad cross-origin access in production.
var corsOrigins = config.Http.CorsOrigins.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
foreach (var origin in corsOrigins)
{
    if (origin == "*")
        throw new InvalidOperationException("[CORS] Wildcard origin '*' is not allowed. Specify exact origins in Http.CorsOrigins.");
    if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
        throw new InvalidOperationException($"[CORS] Invalid origin '{origin}' in Http.CorsOrigins — must be an absolute URL.");
    var isLocal = string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                  || uri.Host == "127.0.0.1" || uri.Host == "::1";
    if (!isLocal && !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException($"[CORS] Non-local origin '{origin}' must use https:// in Http.CorsOrigins.");
}

// Wire UseHsts to the same Http.Hsts config that
// SecurityHeadersMiddleware reads. Both middlewares agree on max-age /
// includeSubDomains / preload so the browser sees a single, consistent
// HSTS declaration.
builder.Services.AddHsts(options =>
{
    var hsts = config.Http.Hsts ?? new HstsConfig();
    options.MaxAge = TimeSpan.FromSeconds(Math.Max(0, hsts.MaxAgeSeconds));
    options.IncludeSubDomains = hsts.IncludeSubDomains;
    options.Preload = hsts.Preload;
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", corsPolicy =>
    {
        // DO NOT add AllowCredentials — the SPA uses Bearer tokens, not cookies,
        // for API calls. Adding credentials would require narrowing the origin
        // allow-list further and opens the door to CSRF on credentialed endpoints.
        corsPolicy.WithOrigins(corsOrigins)
                  .WithMethods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
                  .WithHeaders(
                      "Authorization",
                      "Content-Type",
                      "X-Requested-With",
                      "X-MFA-Token",
                      "X-CSRF-Token",
                      "X-Correlation-Id",
                      "DPoP");
    });
});


// === Kestrel HTTPS configuration with hot-reload support (Web TLS certificate) ===
// The ApiCertificateProvider service class name is retained for binary compatibility,
// but it now holds the Web TLS certificate used by the management UI / API listener.
var apiCertProvider = new ApiCertificateProvider();
builder.Services.AddSingleton(apiCertProvider);
builder.Services.AddScoped<TlsRenewalJob>();
builder.Services.AddScoped<ISchedulerJob, TlsRenewalJob>(sp => sp.GetRequiredService<TlsRenewalJob>());

if (isSetupMode)
{
    // In setup mode, generate a temporary self-signed Web TLS cert so the setup wizard is encrypted.
    // Browsers will show a certificate warning, but the connection is secure against passive MITM
    // only if the operator verifies the fingerprint out-of-band.
    var setupCert = GenerateSetupTlsCert();
    apiCertProvider.SetCertificate(setupCert);

    // The setup wizard is defense-in-depth'd by
    // (1) cert fingerprint verification printed to console, (2) a process-wide semaphore
    // + MySQL advisory lock preventing racing callers, (3) MySqlConnectionStringBuilder
    // + strict input validation on /api/v1/setup/database/test, and (4) the
    // IpWhitelistMiddleware RFC1918+loopback fallback gate. ModularCA is a headless server
    // product, so the Kestrel listener defaults to IPAddress.Any — operators reach the
    // wizard from the local network without SSH port-forwarding. The middleware still
    // rejects non-RFC1918 sources before they reach the SetupController. Operators can
    // override with --setup-bind <address>. A loud warning is only emitted when the bind
    // ends up on a non-RFC1918 interface IP, since RFC1918 is the expected enterprise case.
    string? setupBindArg = args
        .SkipWhile(a => !a.Equals("--setup-bind", StringComparison.OrdinalIgnoreCase))
        .Skip(1)
        .FirstOrDefault();

    System.Net.IPAddress setupBindAddress = System.Net.IPAddress.Any;
    if (!string.IsNullOrWhiteSpace(setupBindArg))
    {
        if (System.Net.IPAddress.TryParse(setupBindArg, out var parsed))
        {
            setupBindAddress = parsed;
        }
        else
        {
            Console.WriteLine($"[SETUP MODE] Invalid --setup-bind value '{setupBindArg}' — falling back to 0.0.0.0");
        }
    }

    // Classify the resolved bind for banner output. Any-bind (0.0.0.0/::) is treated as
    // "normal" because the middleware whitelist still restricts reachable requests to
    // RFC1918+loopback. A specific non-RFC1918 interface IP warrants the loud warning.
    bool setupBindIsLoopback = System.Net.IPAddress.IsLoopback(setupBindAddress);
    bool setupBindIsWildcard =
        setupBindAddress.Equals(System.Net.IPAddress.Any) ||
        setupBindAddress.Equals(System.Net.IPAddress.IPv6Any);
    // Shared with SetupController so the banner and the access check can never disagree about
    // what "private" means.
    bool setupBindIsRfc1918 =
        !setupBindIsLoopback && !setupBindIsWildcard &&
        ModularCA.Shared.Utils.PrivateNetwork.IsPrivate(setupBindAddress);
    bool setupBindIsPublicInterface =
        !setupBindIsLoopback && !setupBindIsWildcard && !setupBindIsRfc1918;

    // Print the setup-cert SHA-256 fingerprint to the console so the
    // operator has a value they can compare to what the SPA displays. Stash it in a static
    // slot the /api/v1/setup/fingerprint endpoint reads at request time.
    var setupCertFingerprint = ComputeSetupCertFingerprint(setupCert);
    SetupCertFingerprintHolder.SetFingerprint(setupCertFingerprint);

    builder.WebHost.ConfigureKestrel(options =>
    {
        options.Limits.MaxRequestBodySize = 10 * 1024 * 1024;
        // Anti-slowloris: bound idle connections and slow request/response
        // streams so a single client cannot pin a thread-pool slot or socket indefinitely.
        options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
        options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
        options.Limits.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: 240, gracePeriod: TimeSpan.FromSeconds(5));
        options.Limits.MinResponseDataRate = new MinDataRate(bytesPerSecond: 240, gracePeriod: TimeSpan.FromSeconds(5));
        var desiredPort = config.Https.Port > 0 ? config.Https.Port : 8443;
        // Setup mode keeps the rolling-port behaviour so the
        // wizard can always come up even if the operator's preferred port is in
        // use. Non-setup listeners use fail-fast mode instead.
        var port = FindAvailablePort(desiredPort, failFast: false);
        if (port != desiredPort)
            Console.WriteLine($"[SETUP MODE] Port {desiredPort} in use — using {port} instead");

        options.Listen(setupBindAddress, port, listenOptions =>
        {
            listenOptions.UseHttps(httpsOptions =>
            {
                httpsOptions.ServerCertificateSelector = (context, name) => apiCertProvider.GetCertificate();
            });
        });

        Console.WriteLine();
        Console.WriteLine("================================================================");
        Console.WriteLine($"[SETUP MODE] Listening on https://{setupBindAddress}:{port}");
        Console.WriteLine("             (temporary self-signed Web TLS cert)");
        Console.WriteLine($"             VERIFY FINGERPRINT BEFORE TRUSTING:");
        Console.WriteLine($"             SHA-256 = {setupCertFingerprint}");
        Console.WriteLine("             Compare this to the value shown in the browser wizard.");
        if (setupBindIsPublicInterface)
        {
            Console.WriteLine();
            Console.WriteLine("  !! WARNING: --setup-bind points at a non-RFC1918 interface.");
            Console.WriteLine("     The wizard is reachable from the public internet.");
            Console.WriteLine();
            Console.WriteLine("     IpWhitelistMiddleware rejects non-RFC1918 sources ONLY when it can");
            Console.WriteLine("     see the real client address. Behind a reverse proxy it sees the");
            Console.WriteLine("     proxy's address instead — usually RFC1918, which satisfies every");
            Console.WriteLine("     internal-only rule — unless Http.TrustedProxyCidrs names that proxy.");
            Console.WriteLine("     Do not treat the whitelist as the control keeping this private.");
            Console.WriteLine();
            Console.WriteLine("     Narrow the bind to a specific LAN interface, or use SSH");
            Console.WriteLine("     port-forwarding instead. Verify the fingerprint out-of-band");
            Console.WriteLine("     before entering any credentials.");
        }
        else if (setupBindIsLoopback)
        {
            Console.WriteLine();
            Console.WriteLine("  (i) Setup listener is bound to loopback only. For remote access");
            Console.WriteLine($"      use an SSH port-forward: ssh -L {port}:127.0.0.1:{port} <host>");
            Console.WriteLine("      Or re-launch with: --setup-bind <address>");
        }
        else if (!ModularCA.API.Startup.SetupNetworkMode.IsPrivateNetworkAllowed)
        {
            // The listener is open but the access check is not: say so plainly, because the
            // symptom otherwise is a 403 from an address the banner appeared to bless.
            Console.WriteLine();
            Console.WriteLine("  (i) Setup listener is bound broadly, but access is restricted to");
            Console.WriteLine("      this machine (--setup-loopback-only). Callers from the LAN");
            Console.WriteLine($"      will receive 403. For remote access use an SSH port-forward:");
            Console.WriteLine($"      ssh -L {port}:127.0.0.1:{port} <host>");
            Console.WriteLine("      Or restart without --setup-loopback-only.");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("  (i) Setup wizard accepts this machine and private networks");
            Console.WriteLine("      (RFC 1918, link-local, IPv6 unique-local). Every caller must");
            Console.WriteLine("      still present the one-time token printed below, so reaching");
            Console.WriteLine("      the port is not enough to use the wizard.");
            Console.WriteLine("      Restrict to this machine with: --setup-loopback-only");
            Console.WriteLine("      Verify the fingerprint above matches the browser cert warning");
            Console.WriteLine("      before entering any credentials.");
        }
        Console.WriteLine("================================================================");
        Console.WriteLine();
        Console.WriteLine($"[SETUP] One-time setup token: {SetupTokenHolder.GetToken()}");
        Console.WriteLine("[SETUP] The setup wizard will require this token to proceed.");
        Console.WriteLine();
    });
}
else
{
    var httpsMode = config.Https.Mode?.Trim();
    // On-disk filename "api-tls.pfx" is kept unchanged for backwards compatibility,
    // though the cert it stores is the Web TLS certificate for the management UI / API listener.
    var selfIssuedPath = Path.Combine(AppContext.BaseDirectory, "config", "api-tls.pfx");

    bool pendingTlsProvisioning = false;
    string? pfxPath = null;
    if (string.Equals(httpsMode, "Pending", StringComparison.OrdinalIgnoreCase))
    {
        // Stage 2: bootstrap completed but the web TLS cert hasn't been issued yet.
        // Start on a temporary self-signed cert; WebTlsProvisioningService will issue
        // the real cert via the standard pipeline once the DI container is ready.
        Console.WriteLine("[STARTUP] TLS mode is Pending — starting on temporary certificate.");
        Console.WriteLine("         The Web TLS certificate will be issued automatically via the standard pipeline.");
        apiCertProvider.SetCertificate(GenerateSetupTlsCert());
        pendingTlsProvisioning = true;
    }
    else if (string.Equals(httpsMode, "SelfIssued", StringComparison.OrdinalIgnoreCase))
    {
        pfxPath = selfIssuedPath;
    }
    else if (string.Equals(httpsMode, "Custom", StringComparison.OrdinalIgnoreCase)
             && !string.IsNullOrWhiteSpace(config.Https.CertificatePath))
    {
        pfxPath = Path.IsPathRooted(config.Https.CertificatePath)
            ? config.Https.CertificatePath
            : Path.Combine(AppContext.BaseDirectory, config.Https.CertificatePath);
    }

    if (pfxPath != null && File.Exists(pfxPath))
    {
        // Load initial cert into the provider
        apiCertProvider.SetCertificate(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(
            pfxPath, config.Https.CertificatePassword,
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet));
    }
    else if (!pendingTlsProvisioning)
    {
        // Web TLS cert missing (post-reset or misconfigured) — generate temp self-signed cert
        // so the setup wizard or login page is still served over HTTPS
        Console.WriteLine("[WARNING] Web TLS certificate not found — using temporary self-signed certificate.");
        Console.WriteLine("         Complete the setup wizard or re-run --bootstrap to generate a proper Web TLS cert.");
        apiCertProvider.SetCertificate(GenerateSetupTlsCert());
    }

    {

        builder.WebHost.ConfigureKestrel(options =>
        {
            // Enforce a 10 MB maximum request body size to protect against oversized payloads.
            // Kestrel automatically returns HTTP 413 (Payload Too Large) when exceeded.
            options.Limits.MaxRequestBodySize = 10 * 1024 * 1024; // 10MB default

            // Anti-slowloris: bound idle connections and slow request/response
            // streams so a single client cannot pin a thread-pool slot or socket indefinitely.
            // Applies to both the HTTPS (SNI-gated mTLS) listener and the plain-HTTP
            // CRL/OCSP/AIA listener configured on this server instance below.
            options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
            options.Limits.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: 240, gracePeriod: TimeSpan.FromSeconds(5));
            options.Limits.MinResponseDataRate = new MinDataRate(bytesPerSecond: 240, gracePeriod: TimeSpan.FromSeconds(5));

            // HTTPS endpoint with SNI-based client-cert gating.
            //
            // A single listener on the configured HTTPS port handles both the
            // public/admin surface (no cert prompt) and the mTLS login
            // subdomain (cert picker). Per-connection, Kestrel calls the
            // TlsHandshakeCallbackOptions.OnConnection callback with the raw
            // TLS ClientHello — including the SNI hostname — BEFORE deciding
            // whether to emit a CertificateRequest. When SNI matches
            // Mtls.AuthSubdomain, the connection is configured to require a
            // client cert; every other SNI (the main hostname) gets a plain
            // server-auth handshake with no cert prompt.
            //
            // Pre-load the configured trusted mTLS CA certs
            // once at startup (outside the hot path). The per-connection
            // validation callback walks a custom-trust chain against them
            // when a cert is presented; additional per-credential validation
            // (thumbprint, bind to enrolled SigningCaId) still happens in the
            // mTLS login controllers.
            //
            // Every load failure is collected rather than swallowed. A config
            // that lists three CA paths of which none resolve used to leave an
            // empty anchor set behind a one-line console notice — and an empty
            // anchor set is indistinguishable, at handshake time, from "mTLS was
            // never configured". The failures are reported to the operator and
            // then folded into the fail-fast check below, so a typo'd or
            // unreadable anchor path stops the server instead of quietly
            // degrading the transport gate.
            var mtlsTrustedCas = new List<System.Security.Cryptography.X509Certificates.X509Certificate2>();
            var mtlsAnchorLoadFailures = new List<string>();
            foreach (var path in config.Mtls.TrustedCaCertPaths ?? new List<string>())
            {
                if (string.IsNullOrWhiteSpace(path))
                    continue;

                // Relative anchor paths resolve against the application base directory
                // (same convention as Https.CertificatePath above) rather than the
                // process working directory, which differs between a console run, a
                // systemd unit, and a Windows service.
                var anchorPath = Path.IsPathRooted(path)
                    ? path
                    : Path.Combine(AppContext.BaseDirectory, path);

                try
                {
                    if (!File.Exists(anchorPath))
                    {
                        mtlsAnchorLoadFailures.Add($"{path} — file not found (resolved to {anchorPath})");
                        continue;
                    }
                    mtlsTrustedCas.Add(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(anchorPath));
                }
                catch (Exception ex)
                {
                    mtlsAnchorLoadFailures.Add($"{path} — {ex.GetType().Name}: {ex.Message}");
                }
            }

            if (mtlsAnchorLoadFailures.Count > 0)
            {
                Console.WriteLine("[mTLS WARNING] One or more Mtls.TrustedCaCertPaths entries could not be loaded:");
                foreach (var failure in mtlsAnchorLoadFailures)
                    Console.WriteLine($"               {failure}");
                Log.Warning("[SECURITY] {Count} configured mTLS trust anchor(s) failed to load: {Failures}",
                    mtlsAnchorLoadFailures.Count, string.Join(" | ", mtlsAnchorLoadFailures));
            }

            // Fall back to the enrolled mTLS signing CAs recorded in the database when
            // config.yaml names no anchor paths.
            //
            // Every mTLS client certificate this system will ever see was issued by one of
            // its own CAs: MtlsController signs them with the CA named by the requesting
            // user's group (CaGroups.MtlsSigningCaId), and MtlsCredential.SigningCaId
            // records which one. The database therefore already holds the exact and complete
            // anchor set, and requiring the operator to hand-export those same certificates
            // to PEM files and list their paths is busywork that the setup wizard does not
            // do — it writes Mtls.Enabled from the operator's checkbox but hardcodes
            // TrustedCaCertPaths to empty (BootstrapDatabaseSetup.cs), so the wizard's own
            // happy path could never satisfy a config-only anchor requirement.
            //
            // Config wins when present. An operator who lists explicit paths is asserting a
            // narrower or external trust set (e.g. fronting with a proxy that forwards certs
            // from a CA this instance does not run), and silently widening that back out to
            // "every CA in the database" would defeat the point.
            //
            // Setup mode is skipped: the schema may not exist yet, and the fail-fast below
            // is itself setup-exempt, so there is nothing to feed.
            if (mtlsTrustedCas.Count == 0 && !isSetupMode && config.Mtls.Enabled)
            {
                try
                {
                    var anchorDbOptions = new DbContextOptionsBuilder<ModularCADbContext>()
                        .UseMySql(appConnStr, ServerVersion.AutoDetect(appConnStr))
                        .Options;
                    using var anchorDb = new ModularCADbContext(anchorDbOptions);

                    // Resolved in three steps rather than one joined query: the FK columns are
                    // Guid? (a group may have no mTLS CA, an SSH-only CA has no X.509 cert) and
                    // threading nullable keys through Join is both harder to read and easy to get
                    // subtly wrong. Three small round-trips at startup cost nothing.
                    var mtlsCaIds = anchorDb.CaGroups
                        .AsNoTracking()
                        .Where(g => g.MtlsSigningCaId != null)
                        .Select(g => g.MtlsSigningCaId!.Value)
                        .Distinct()
                        .ToList();

                    var caCertIds = anchorDb.CertificateAuthorities
                        .AsNoTracking()
                        .Where(ca => mtlsCaIds.Contains(ca.Id) && ca.CertificateId != null)
                        .Select(ca => ca.CertificateId!.Value)
                        .Distinct()
                        .ToList();

                    var seededAnchors = anchorDb.Certificates
                        .AsNoTracking()
                        .Where(c => caCertIds.Contains(c.CertificateId))
                        .Select(c => c.RawCertificate)
                        .ToList();

                    foreach (var raw in seededAnchors)
                    {
                        if (raw == null || raw.Length == 0)
                            continue;
                        try
                        {
                            mtlsTrustedCas.Add(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(raw));
                        }
                        catch (Exception ex)
                        {
                            mtlsAnchorLoadFailures.Add($"database-seeded anchor — {ex.GetType().Name}: {ex.Message}");
                        }
                    }

                    if (mtlsTrustedCas.Count > 0)
                        Console.WriteLine($"[mTLS] Seeded {mtlsTrustedCas.Count} trust anchor(s) from enrolled mTLS signing CAs (Mtls.TrustedCaCertPaths is empty).");
                }
                catch (Exception ex)
                {
                    // A read failure here is not the same as "no anchors exist" — say so, so the
                    // fatal below does not send the operator hunting for a config problem when
                    // the real cause was an unreachable database at boot.
                    mtlsAnchorLoadFailures.Add($"database anchor lookup failed — {ex.GetType().Name}: {ex.Message}");
                    Log.Warning(ex, "[SECURITY] Could not read enrolled mTLS signing CAs for trust-anchor seeding.");
                }
            }

            // Enforce TLS 1.2 floor + TLS 1.3.
            var sslProtocols =
                System.Security.Authentication.SslProtocols.Tls12 |
                System.Security.Authentication.SslProtocols.Tls13;

            // Pre-compute the effective mTLS auth subdomain FQDN so the
            // per-connection callback does a case-insensitive string compare
            // with zero allocations per request.
            var authSubdomainFqdn = ModularCA.Shared.Utils.SubdomainUtil.ResolveFqdn(
                config.Mtls.AuthSubdomain, config.Https.PublicDomain);

            // EST enrollment gets its own SNI hostname, on the same listener and port. It is not the
            // mTLS login subdomain and must not be pointed at the same name: that hostname REQUIRES
            // a client certificate and validates against the CAs that issue human login
            // credentials, while EST must only REQUEST one (RFC 7030 section 4.1 makes /cacerts the
            // unauthenticated bootstrap step, and a device holds no certificate until after it
            // enrolls) and must validate against the CAs that issued the devices.
            var estSubdomainFqdn = ModularCA.Shared.Utils.SubdomainUtil.ResolveFqdn(
                config.Est.AuthSubdomain, config.Https.PublicDomain);

            // EST client-certificate trust anchors. Deliberately a separate, refreshable set rather
            // than a reuse of mtlsTrustedCas: those are the CAs that sign human login certificates
            // (CaGroups.MtlsSigningCaId), whereas an EST client authenticates with the certificate
            // this CA previously issued to the device (RFC 7030 section 4.2.2). Sharing one set
            // would let a login certificate enroll as a device and stop devices re-enrolling at all.
            ModularCA.Core.Services.Est.EstTrustAnchorCache? estTrustAnchors = null;
            if (!isSetupMode && !string.IsNullOrEmpty(estSubdomainFqdn))
            {
                var estDbOptions = new DbContextOptionsBuilder<ModularCADbContext>()
                    .UseMySql(appConnStr, ServerVersion.AutoDetect(appConnStr))
                    .Options;

                estTrustAnchors = new ModularCA.Core.Services.Est.EstTrustAnchorCache(
                    () => new ModularCADbContext(estDbOptions),
                    TimeSpan.FromSeconds(config.Est.TrustAnchorRefreshSeconds),
                    message => Log.Warning("[EST] Trust-anchor load problem: {Message}", message));

                var estAnchorCount = estTrustAnchors.LoadNow();
                if (estAnchorCount == 0)
                {
                    // Not fatal, unlike the mTLS equivalent. EST can be authenticated by HTTP Basic
                    // instead, /cacerts must answer regardless, and a CA may have EST enabled only
                    // moments from now — the cache will pick it up. But say so, because the
                    // alternative is a client-certificate handshake that rejects everything with no
                    // explanation anywhere.
                    Console.WriteLine($"[EST] Subdomain '{estSubdomainFqdn}' is gated, but no CA currently has EST enabled —");
                    Console.WriteLine("      client certificates presented there will be rejected until one does.");
                    Console.WriteLine($"      Anchors re-read every {config.Est.TrustAnchorRefreshSeconds}s; no restart needed.");
                }
                else
                {
                    Console.WriteLine($"[EST] Client-cert requested (not required) on SNI '{estSubdomainFqdn}'; {estAnchorCount} EST-enabled CA anchor(s) loaded.");
                }
            }

            // Two SNI gates on one listener must not name one hostname. The mTLS branch is
            // evaluated first and REQUIRES a client certificate, so a shared name silently turns
            // EST's unauthenticated /cacerts bootstrap into a handshake failure — and the operator
            // sees devices that cannot fetch the CA chain, with both settings looking correct.
            if (!isSetupMode
                && !string.IsNullOrEmpty(estSubdomainFqdn)
                && !string.IsNullOrEmpty(authSubdomainFqdn)
                && string.Equals(estSubdomainFqdn, authSubdomainFqdn, StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine($"[FATAL] Est.AuthSubdomain and Mtls.AuthSubdomain both resolve to '{estSubdomainFqdn}'.");
                Console.Error.WriteLine("        These hostnames have incompatible handshake policies: the mTLS login name");
                Console.Error.WriteLine("        requires a client certificate and validates it against the login-signing CAs,");
                Console.Error.WriteLine("        while EST requests one without requiring it and validates against the");
                Console.Error.WriteLine("        EST-enabled CAs. Sharing a name breaks EST's unauthenticated /cacerts step.");
                Console.Error.WriteLine("        Give them separate names (for example 'mtls' and 'est').");
                Log.Warning("[SECURITY] Startup aborted: Est.AuthSubdomain and Mtls.AuthSubdomain collide on {Fqdn}.", estSubdomainFqdn);
                Environment.Exit(1);
            }

            // The listener serves one certificate for every SNI name. A gated hostname missing from
            // its SANs fails in the browser or client as a name mismatch, before any of the
            // client-certificate logic above is reached — so the operator debugging "mTLS login
            // doesn't work" or "EST can't connect" is looking at the wrong layer entirely. Warn
            // rather than refuse: the certificate is replaceable at runtime, and a CA that cannot
            // start cannot issue the certificate that would fix this.
            if (!isSetupMode)
            {
                var serverCert = apiCertProvider.GetCertificate();
                foreach (var (setting, fqdn) in new[]
                         {
                             ("Mtls.AuthSubdomain", authSubdomainFqdn),
                             ("Est.AuthSubdomain", estSubdomainFqdn),
                         })
                {
                    if (string.IsNullOrEmpty(fqdn) || serverCert == null)
                        continue;

                    if (ModularCA.Shared.Utils.CertificateSanUtil.CoversHostname(serverCert, fqdn))
                        continue;

                    Console.WriteLine($"[TLS WARNING] {setting} is '{fqdn}', but the HTTPS server certificate does not");
                    Console.WriteLine($"              list that name (subject: {serverCert.Subject}). Clients will fail with a");
                    Console.WriteLine("              hostname mismatch before any client-certificate exchange happens.");
                    Console.WriteLine("              Reissue the web TLS certificate with that name in its SANs.");
                    Log.Warning("[TLS] {Setting} hostname {Fqdn} is not covered by the HTTPS server certificate SANs.", setting, fqdn);
                }
            }

            // CMP without a dedicated signer answers PBMAC clients fine and signature-protected
            // clients not at all: responses are signed with the CA certificate, which carries no
            // digitalSignature key usage, and OpenSSL refuses it as a message signer. The gap is
            // invisible from the server side, so say so at boot for every CA it applies to.
            if (!isSetupMode)
            {
                try
                {
                    var cmpDbOptions = new DbContextOptionsBuilder<ModularCADbContext>()
                        .UseMySql(appConnStr, ServerVersion.AutoDetect(appConnStr))
                        .Options;
                    using var cmpDb = new ModularCADbContext(cmpDbOptions);
                    var unsignedCmpCas = (from cfg in cmpDb.CaProtocolConfigs.AsNoTracking()
                                          join ca in cmpDb.CertificateAuthorities.AsNoTracking() on cfg.CaId equals ca.Id
                                          where cfg.Protocol == "CMP" && cfg.IsEnabled && ca.IsEnabled && !ca.IsDeleted
                                                && ca.CmpSigningCertificateId == null
                                          select ca.Label ?? ca.Name).ToList();
                    foreach (var label in unsignedCmpCas)
                    {
                        Console.WriteLine($"[CMP WARNING] CA '{label}' has CMP enabled but no CMP signing certificate.");
                        Console.WriteLine("              Signature-protected responses will be signed with the CA certificate, which");
                        Console.WriteLine("              OpenSSL-based clients reject. Issue one from the CA's detail page (Infrastructure");
                        Console.WriteLine("              Certificates -> CMP signer). PBMAC clients are unaffected.");
                        Log.Warning("[CMP] CA {CaLabel} has CMP enabled with no CMP signing certificate.", label);
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[CMP] Could not check CAs for a CMP signing certificate at startup.");
                }
            }

            // Fail-fast: mTLS gating without trust anchors is not a working configuration.
            //
            // The handshake callback below rejects every client certificate when the
            // anchor set is empty (nothing can be validated against zero anchors), so an
            // instance that reaches this point with no anchors from EITHER source —
            // Mtls.TrustedCaCertPaths or the enrolled-signing-CA fallback seeded above —
            // would prompt for a certificate on the auth subdomain and then refuse every
            // one of them, with no explanation anywhere except a TLS alert in the browser.
            // Refuse to start instead, and name every remedy.
            //
            // Scope of the check, deliberately narrow:
            //   * Setup mode is exempt. A fresh install has no config.yaml at all, so
            //     Mtls.Enabled is the SystemConfig default (false) and this can't fire —
            //     but the second setup-mode trigger (config.yaml present, db.yaml not yet
            //     written) CAN see an operator-authored Mtls block. The wizard must be
            //     able to boot so the operator can finish bootstrap and fix the config
            //     from the UI, so the check follows the same !isSetupMode convention as
            //     the JWT-secret and cron-expression fail-fasts above.
            //   * An empty AuthSubdomain is exempt. Without a gated SNI hostname the
            //     listener never sets ClientCertificateRequired, so no client cert is
            //     ever requested and there is no fail-open to close. That case is already
            //     covered by the [mTLS WARNING] block further down, which explains why
            //     mTLS login won't work.
            if (!isSetupMode && config.Mtls.Enabled && !string.IsNullOrEmpty(authSubdomainFqdn) && mtlsTrustedCas.Count == 0)
            {
                Console.Error.WriteLine("[FATAL] Mtls.Enabled=true but no usable client-certificate trust anchors are available.");
                Console.Error.WriteLine($"        Mtls.TrustedCaCertPaths yielded 0 loadable certificates ({config.Mtls.TrustedCaCertPaths?.Count ?? 0} path(s) configured, {mtlsAnchorLoadFailures.Count} failure(s) recorded).");
                Console.Error.WriteLine("        The database fallback also produced none: no CA group has an mTLS signing CA");
                Console.Error.WriteLine("        assigned (CaGroups.MtlsSigningCaId), or the database could not be read.");
                if (mtlsAnchorLoadFailures.Count > 0)
                {
                    Console.Error.WriteLine("        Recorded failures:");
                    foreach (var failure in mtlsAnchorLoadFailures)
                        Console.Error.WriteLine($"          - {failure}");
                }
                Console.Error.WriteLine("        The TLS handshake on the mTLS auth subdomain would request a client");
                Console.Error.WriteLine("        certificate and have nothing to validate it against. Refusing to start");
                Console.Error.WriteLine("        rather than run with an unvalidated client-certificate transport gate.");
                Console.Error.WriteLine("        Fix by any of:");
                Console.Error.WriteLine("          - assigning an mTLS signing CA to at least one group in the admin UI");
                Console.Error.WriteLine("            (Groups -> group -> mTLS signing CA), which seeds anchors automatically, or");
                Console.Error.WriteLine("          - setting Mtls.TrustedCaCertPaths in config.yaml to the PEM/DER file(s) of");
                Console.Error.WriteLine("            the CA(s) that issue mTLS client certificates, or");
                Console.Error.WriteLine("          - setting Mtls.Enabled: false to turn the mTLS login flow off.");
                Log.Warning("[SECURITY] Startup aborted: Mtls.Enabled=true with an empty effective trust-anchor set (subdomain {Subdomain}).", authSubdomainFqdn);
                Environment.Exit(1);
            }

            Action<Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions> configureHttps = listenOptions =>
            {
                listenOptions.UseHttps(new Microsoft.AspNetCore.Server.Kestrel.Https.TlsHandshakeCallbackOptions
                {
                    OnConnection = ctx =>
                    {
                        var sni = ctx.ClientHelloInfo.ServerName;
                        var isMtlsSubdomain = ModularCA.Shared.Utils.SubdomainUtil.MatchesSni(sni, authSubdomainFqdn);

                        // EST is gated separately and never falls back to the mTLS branch: if both
                        // settings somehow name the same hostname, mTLS wins and EST's /cacerts
                        // bootstrap would break, so the startup check below refuses that pairing.
                        var isEstSubdomain = !isMtlsSubdomain
                            && estTrustAnchors != null
                            && ModularCA.Shared.Utils.SubdomainUtil.MatchesSni(sni, estSubdomainFqdn);

                        var options = new System.Net.Security.SslServerAuthenticationOptions
                        {
                            ServerCertificate = apiCertProvider.GetCertificate(),
                            EnabledSslProtocols = sslProtocols,

                            // True on the EST subdomain as well, but it means something different
                            // there: this flag is what puts a CertificateRequest on the wire, and
                            // the EST validation callback below accepts a client that answers it
                            // with nothing. Without the flag no certificate is ever offered and
                            // EstRequireClientCert can never be satisfied — the defect this
                            // subdomain exists to fix.
                            ClientCertificateRequired = isMtlsSubdomain || isEstSubdomain,
                        };

                        if (isEstSubdomain)
                        {
                            options.RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                            {
                                // Anonymous is allowed here, and must be. RFC 7030 section 4.1 makes
                                // /cacerts the unauthenticated bootstrap step: a device fetches the
                                // CA chain before it has any certificate of its own, so failing the
                                // handshake on an empty client Certificate would break enrollment
                                // at its first step. Whether anonymity is acceptable for the
                                // request that follows is EnrollmentAuthorizationService's call,
                                // per CA, where EstRequireClientCert and EstHttpAuthEnabled live.
                                if (cert == null)
                                    return true;

                                // A certificate that IS presented must be real. EstService reads
                                // this certificate's CN and SANs and binds the CSR to them, but
                                // never checks who issued it — it trusts this callback to have
                                // done so. Waving an unvalidated certificate through here means a
                                // self-signed CN=root-admin enrolls as CN=root-admin, with every
                                // downstream binding check confirming the forgery against itself.
                                var anchors = estTrustAnchors!.Current;
                                var accepted = ModularCA.Core.Services.Est.EstClientCertValidator.IsIssuedByEstCa(
                                    cert as System.Security.Cryptography.X509Certificates.X509Certificate2,
                                    anchors.EstCaCerts,
                                    anchors.ChainCerts);

                                if (!accepted)
                                {
                                    // Logged because the client sees only a TLS alert. Without this
                                    // line the operator has a device that "cannot connect" and no
                                    // way to tell a wrong-CA certificate from a network fault.
                                    Log.Warning(
                                        "[EST] Client certificate rejected at handshake on {Sni}: subject {Subject}, issuer {Issuer}. "
                                        + "{AnchorCount} EST-enabled CA anchor(s) in effect.",
                                        sni,
                                        (cert as System.Security.Cryptography.X509Certificates.X509Certificate2)?.Subject ?? "?",
                                        (cert as System.Security.Cryptography.X509Certificates.X509Certificate2)?.Issuer ?? "?",
                                        anchors.EstCaCerts.Count);
                                }

                                return accepted;
                            };
                        }

                        if (isMtlsSubdomain)
                        {
                            // Only gate cert validation when a cert was actually requested —
                            // otherwise the callback never fires.
                            options.RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                            {
                                if (cert is not System.Security.Cryptography.X509Certificates.X509Certificate2 x509)
                                    return false;

                                // Fail CLOSED on an empty trust store. Nothing presented here
                                // can have been validated against zero anchors, so returning
                                // true would mean "any self-signed certificate completes the
                                // mTLS handshake" — the transport gate would be decorative and
                                // the whole burden would silently fall on the login controllers.
                                // Startup already refuses to come up in this state (see the
                                // fail-fast above); this is the belt to that suspenders, for the
                                // case where the anchor list is somehow emptied at runtime.
                                if (mtlsTrustedCas.Count == 0)
                                    return false;

                                using var buildChain = new System.Security.Cryptography.X509Certificates.X509Chain();
                                buildChain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                                foreach (var ca in mtlsTrustedCas)
                                    buildChain.ChainPolicy.CustomTrustStore.Add(ca);

                                // Only certificates usable for client authentication. The login
                                // CAs may also issue other kinds; a TLS server certificate must
                                // not double as a login credential. Absence of the EKU extension
                                // still passes (RFC 5280 section 4.2.1.12: absent means
                                // unrestricted), so existing login certificates are unaffected.
                                buildChain.ChainPolicy.ApplicationPolicy.Add(
                                    new System.Security.Cryptography.Oid(
                                        ModularCA.Core.Services.Est.EstClientCertValidator.ClientAuthEkuOid));

                                // Revocation: Offline, matching MtlsMiddleware's chain policy.
                                // A revoked client certificate must not survive the handshake
                                // just because the authoritative revocation decision happens a
                                // layer up (MtlsController.Verify → MtlsChainValidator, which
                                // does an Online check when SecurityPolicy.RequireMtlsOcspCheck
                                // is set). Offline consults the locally cached/published CRL
                                // only — no OCSP or CDP fetch on the connection path — so this
                                // costs no network round trip inside the 10s handshake budget.
                                //
                                // The Ignore*RevocationUnknown flags are deliberate: with a cold
                                // CRL cache Offline mode reports RevocationStatusUnknown and
                                // Build() would fail every handshake, taking mTLS login down for
                                // a reason that has nothing to do with the client's standing. So
                                // an explicit Revoked status is fatal here, while "can't tell"
                                // defers to the application layer, which is the tier that can
                                // fetch OCSP and is policy-configurable about failing closed.
                                buildChain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline;
                                buildChain.ChainPolicy.RevocationFlag = System.Security.Cryptography.X509Certificates.X509RevocationFlag.ExcludeRoot;
                                buildChain.ChainPolicy.VerificationFlags =
                                    System.Security.Cryptography.X509Certificates.X509VerificationFlags.IgnoreEndRevocationUnknown
                                    | System.Security.Cryptography.X509Certificates.X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                                    | System.Security.Cryptography.X509Certificates.X509VerificationFlags.IgnoreRootRevocationUnknown;

                                return buildChain.Build(x509);
                            };
                        }

                        return new ValueTask<System.Net.Security.SslServerAuthenticationOptions>(options);
                    },
                    HandshakeTimeout = TimeSpan.FromSeconds(10),
                });
            };

            var addresses = (config.Https.ListenAddress ?? "0.0.0.0")
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            // Non-setup runs fail-fast on port-bind conflict
            // instead of silently rolling. An operator who configured Https.Port
            // and finds the app listening on port+1 has no idea that something
            // else stole the port. FindAvailablePort still rolls in setup mode
            // so the wizard can always come up.
            var httpsPort = FindAvailablePort(config.Https.Port, failFast: true);
            if (httpsPort != config.Https.Port)
                Console.WriteLine($"[HTTPS] Port {config.Https.Port} in use — using {httpsPort} instead");

            foreach (var addr in addresses)
            {
                if (addr is "0.0.0.0" or "[::]" or "*")
                    options.ListenAnyIP(httpsPort, configureHttps);
                else
                    options.Listen(System.Net.IPAddress.Parse(addr), httpsPort, configureHttps);
            }

            // mTLS login is served from the same HTTPS listener on the same
            // port, SNI-gated. Connections with ClientHello.ServerName ==
            // Mtls.AuthSubdomain get a ClientCertificateRequired handshake;
            // everything else (the public hostname) gets a plain server-auth
            // handshake with no cert prompt. No dedicated port is used.
            if (config.Mtls.Enabled)
            {
                if (string.IsNullOrEmpty(authSubdomainFqdn))
                {
                    Console.WriteLine("[mTLS WARNING] Mtls.Enabled=true but Mtls.AuthSubdomain is empty —");
                    Console.WriteLine("               mTLS login flow has no gated SNI. The main HTTPS listener");
                    Console.WriteLine("               does NOT request client certificates at TLS handshake");
                    Console.WriteLine("               (by design, so the public portal doesn't prompt for a");
                    Console.WriteLine("               cert on every visit). Set Mtls.AuthSubdomain (e.g.");
                    Console.WriteLine("               'mtls.ca.example.com' or the short 'mtls' which is");
                    Console.WriteLine("               prepended to Https.PublicDomain) for mTLS login to work.");
                }
                else
                {
                    Console.WriteLine($"[mTLS] Client-cert picker gated to SNI '{authSubdomainFqdn}'. Main HTTPS listener issues no CertificateRequest for any other hostname.");
                }
            }

            // Plain HTTP listener for CRL, OCSP, and AIA endpoints.
            // RFC 5280 requires these to be reachable without TLS (clients validating a cert
            // cannot use HTTPS to fetch the CRL/OCSP that validates that same cert).
            if (config.Http.Port > 0)
            {
                var httpPort = FindAvailablePort(config.Http.Port, failFast: true);
                if (httpPort != config.Http.Port)
                    Console.WriteLine($"[HTTP] Port {config.Http.Port} in use — using {httpPort} instead");

                // Tight per-listener body cap is enforced by
                // PlainHttpBodyLimitMiddleware (below) — we can't set a
                // per-listener limit at Kestrel bind time without dropping into
                // ConnectionDelegate plumbing, so the middleware compares
                // Connection.LocalPort == config.Http.Port and resizes the
                // IHttpMaxRequestBodySizeFeature at request-entry time.
                foreach (var addr in addresses)
                {
                    if (addr is "0.0.0.0" or "[::]" or "*")
                        options.ListenAnyIP(httpPort);
                    else
                        options.Listen(System.Net.IPAddress.Parse(addr), httpPort);
                }
                Console.WriteLine($"[HTTP] Listening on port {httpPort} (plain HTTP for CRL/OCSP/AIA, 256 KB body cap)");
            }
        });
    }
} // end else (non-setup HTTPS config)

// In non-setup mode, Https.PublicDomain MUST be set and
// MUST be a valid hostname or IP — the HTTPS enforcement middleware builds
// redirect targets from this value (not the attacker-controllable Host
// header), and ACME JWS URL binding relies on it. Setup mode is exempt
// because the config file doesn't exist yet and the wizard writes it.
if (!isSetupMode)
{
    var domain = config.Https.PublicDomain?.Trim() ?? string.Empty;
    if (string.IsNullOrWhiteSpace(domain))
    {
        Console.Error.WriteLine("[FATAL] Https.PublicDomain is not set in config.yaml.");
        Console.Error.WriteLine("        The management UI uses this value for redirects and ACME URL binding.");
        Console.Error.WriteLine("        Set it to your public hostname, e.g. ca.example.com");
        Environment.Exit(1);
    }
    if (domain.Contains("://") || domain.Contains('/'))
    {
        Console.Error.WriteLine($"[FATAL] Https.PublicDomain ('{domain}') must be a bare hostname or IP — no scheme, no path.");
        Console.Error.WriteLine("        Example: ca.example.com");
        Environment.Exit(1);
    }
    var hostNameType = Uri.CheckHostName(domain);
    if (hostNameType != UriHostNameType.Dns && hostNameType != UriHostNameType.IPv4 && hostNameType != UriHostNameType.IPv6)
    {
        Console.Error.WriteLine($"[FATAL] Https.PublicDomain ('{domain}') is not a valid hostname or IP address.");
        Environment.Exit(1);
    }
}
else if (string.IsNullOrWhiteSpace(config.Https.PublicDomain))
{
    Console.WriteLine("[WARNING] Https.PublicDomain is not set — setup mode will populate it.");
}

var app = builder.Build();

// SECURITY (MFA bypass fix): fail-closed sanity check — IDistributedCache MUST resolve
// from DI. The login flow in AuthController routes users with enrolled TOTP/WebAuthn
// through an MFA step-up branch that persists a short-lived token in this cache. If
// IDistributedCache is unregistered the MFA branch historically fell through to full
// JWT issuance, silently bypassing MFA. AddDistributedMemoryCache() is now registered
// unconditionally as a fallback above (see ICF-07), and this check refuses to boot if
// the service still can't be resolved — never fail-open.
try
{
    using var scope = app.Services.CreateScope();
    var resolvedCache = scope.ServiceProvider.GetService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();
    if (resolvedCache == null)
    {
        throw new InvalidOperationException(
            "IDistributedCache is not registered. This is a fatal security configuration error: " +
            "the MFA step-up flow requires a distributed cache to issue short-lived MFA tokens. " +
            "Without it, users with enrolled TOTP/WebAuthn would silently bypass MFA. " +
            "Ensure AddDistributedMemoryCache() or AddStackExchangeRedisCache() is registered in StartModularCA.cs.");
    }
    Console.WriteLine("[Cache] Startup sanity check passed — IDistributedCache resolved ({0}).", resolvedCache.GetType().FullName);
}
catch (InvalidOperationException)
{
    throw;
}
catch (Exception ex)
{
    throw new InvalidOperationException(
        "IDistributedCache sanity check failed during startup. Refusing to boot — fail-closed on MFA-critical dependency.",
        ex);
}

// Refuse to start in Development environment unless the
// operator has explicitly opted in via --allow-dev-mode or the
// MODULARCA_ALLOW_DEV_MODE=1 env var. The ASP.NET Core developer exception
// page in Development mode leaks stack traces, source paths, and SQL — a
// disaster for a CA service if the box is accidentally shipped with
// ASPNETCORE_ENVIRONMENT=Development.
if (app.Environment.IsDevelopment())
{
    var devAllowed =
        args.Contains("--allow-dev-mode", StringComparer.OrdinalIgnoreCase) ||
        string.Equals(
            Environment.GetEnvironmentVariable("MODULARCA_ALLOW_DEV_MODE"),
            "1",
            StringComparison.Ordinal);
    if (!devAllowed)
    {
        Console.Error.WriteLine("[FATAL] ASPNETCORE_ENVIRONMENT=Development is set but Development mode is not allowed.");
        Console.Error.WriteLine("        The developer exception page leaks stack traces, file paths, and SQL — unacceptable for a CA service.");
        Console.Error.WriteLine("        To explicitly opt in, relaunch with --allow-dev-mode or set MODULARCA_ALLOW_DEV_MODE=1.");
        Console.Error.WriteLine("        Otherwise, unset ASPNETCORE_ENVIRONMENT (or set it to Staging / Production).");
        Environment.Exit(1);
    }
    Console.WriteLine("[WARNING] Development environment is active (--allow-dev-mode opt-in). Stack traces and SQL may leak on error.");
}

// Ensure the HSM PKCS#11 session is cleanly closed when the application shuts down
if (hsmSession != null)
{
    app.Lifetime.ApplicationStopping.Register(() => hsmSession.Dispose());
}

//var trustStore = app.Services.GetRequiredService<ITrustStoreProvider>();
//trustStore.LoadFromFile("ca-trust.keystore"); // adjust path if needed


// Apply pending EF Core migrations for the main database on startup
// In setup mode, skip migrations entirely — the setup wizard handles schema creation
// via BootstrapService.Initialize() which calls Migrate() with root credentials.
if (!isSetupMode)
{
    try
    {
        using var scope = app.Services.CreateScope();
        var mainDb = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var pendingMigrations = await mainDb.Database.GetPendingMigrationsAsync();
        if (pendingMigrations.Any())
        {
            var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
            logger.LogInformation("Applying {Count} pending migration(s): {Migrations}",
                pendingMigrations.Count(), string.Join(", ", pendingMigrations));
            try
            {
                await mainDb.Database.MigrateAsync();
                logger.LogInformation("Database migrations applied successfully.");
            }
            catch (Exception migrateEx)
            {
                // This used to "recover" by calling EnsureDeletedAsync() — an unconditional DROP
                // of the live application schema — and then retrying. The catch was unqualified,
                // so a lock-wait timeout, a GRANT the app user lacks for one DDL statement, or a
                // connection drop mid-migration was indistinguishable from the dirty-schema case
                // it was written for. A second catch then swallowed the rebuild failure and let
                // the process continue booting on an empty database, so the first sign of trouble
                // was an operational CA with no certificates, no revocations, and no users.
                //
                // Startup never destroys data. A failed migration leaves the existing schema
                // untouched and is surfaced loudly; recovering from a genuinely dirty schema is a
                // deliberate operator action (`--reset --force`), not something a service does to
                // itself at 3am because a lock timed out.
                logger.LogError(migrateEx,
                    "Database migration failed. The existing schema has been left untouched. " +
                    "If this is a transient fault (lock timeout, connection drop) retry the start. " +
                    "If the schema predates migrations, run the bootstrap reset deliberately — " +
                    "the service will not drop the database on its own.");
            }
        }
    }
    catch (Exception ex)
    {
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
        logger.LogWarning(ex, "Failed to check/apply migrations — the database may not exist yet. Setup wizard will handle initialization.");
    }
}

// Warm the IWhitelistService snapshot after migrations are applied so the
// singleton has a populated in-memory view before any request hits the pipeline.
// Skipped entirely in setup mode: the DbContext is wired with placeholder credentials
// (root@localhost with no real password) until db.yaml/config.yaml are written by
// the wizard, so any DB read from the service would log EF command/connection errors.
// The middleware's pre-bootstrap fallback handles /setup/* via WhitelistDefaults
// while the service stays cold. The post-bootstrap reload in BootstrapService flips
// IsWarm = true once real credentials exist.
if (!isSetupMode)
{
    try
    {
        using var warmupScope = app.Services.CreateScope();
        var whitelistService = warmupScope.ServiceProvider.GetRequiredService<ModularCA.Shared.Interfaces.IWhitelistService>();
        await whitelistService.ReloadAsync();
        if (whitelistService.IsWarm)
            Console.WriteLine("[STARTUP] IWhitelistService snapshot loaded.");
        else
            Console.WriteLine("[STARTUP] IWhitelistService warmup completed but snapshot is cold (IsWarm=false) — middleware will use the hardcoded fallback for /setup paths until the next successful reload.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[STARTUP] IWhitelistService warmup failed: {ex.Message} — middleware will use the hardcoded fallback for /setup paths until the next successful reload.");
    }
}
else
{
    Console.WriteLine("[STARTUP] IWhitelistService warmup skipped (setup mode) — middleware will use the hardcoded fallback for /setup paths.");
}

// Apply pending audit database migrations on startup (skip in setup mode)
if (!isSetupMode)
{
    try
    {
        using var scope = app.Services.CreateScope();
        var auditDb = scope.ServiceProvider.GetService<AuditDbContext>();
        if (auditDb != null)
        {
            var pendingAudit = await auditDb.Database.GetPendingMigrationsAsync();
            if (pendingAudit.Any())
            {
                var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
                logger.LogInformation("Applying {Count} pending audit migration(s): {Migrations}",
                    pendingAudit.Count(), string.Join(", ", pendingAudit));
                await auditDb.Database.MigrateAsync();
                logger.LogInformation("Audit database migrations applied successfully.");
            }
        }
    }
    catch (Exception ex)
    {
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
        logger.LogWarning(ex, "Failed to apply audit migrations — the database may not exist yet.");
    }
}

// Determine if the system needs setup (no CAs exist)
bool needsSetup = isSetupMode;
if (!isSetupMode)
{
    try
    {
        using var checkScope = app.Services.CreateScope();
        var checkDb = checkScope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        needsSetup = !checkDb.Database.CanConnect() || !checkDb.CertificateAuthorities.Any();
    }
    catch { needsSetup = true; }
}

// A configured instance that has no CAs is a recovery situation (an empty restore, a wrong
// schema in db.yaml, every CA soft-deleted). The setup endpoints are the recovery tool, and
// they must not be reachable on a credential-free basis just because the state is odd: mint a
// token exactly as setup mode does, so recovery needs the console. Without a token the setup
// controller refuses.
if (!isSetupMode && needsSetup)
{
    var recoveryToken = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    SetupTokenHolder.SetToken(recoveryToken);
    Console.WriteLine("[SETUP] This instance is configured but has no certificate authorities.");
    Console.WriteLine("[SETUP] The setup wizard is available for recovery. It requires this one-time token,");
    Console.WriteLine($"[SETUP] valid for {SetupTokenHolder.DefaultTokenTtl.TotalMinutes:0} minutes: {recoveryToken}");
}

// Startup state logging
if (isSetupMode)
    Console.WriteLine("[STARTUP] Mode: SETUP — no config.yaml, serving setup wizard");
else if (needsSetup)
    Console.WriteLine("[STARTUP] Mode: NEEDS SETUP — config.yaml exists but no CAs found, redirecting to setup wizard");
else
{
    try
    {
        using var stateScope = app.Services.CreateScope();
        var stateDb = stateScope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var caCount = stateDb.CertificateAuthorities.Count();
        var certCount = stateDb.Certificates.Count();
        Console.WriteLine($"[STARTUP] Mode: RUNTIME — {caCount} CA(s), {certCount} certificate(s) in database");
    }
    catch { Console.WriteLine("[STARTUP] Mode: RUNTIME"); }
}

// System-group tier consistency check. The bootstrap seeds CaGroups with
// IsSystemTierSuper=true on the system-super row only; runtime authz reads that
// flag (NOT the literal name) to distinguish super tier from system-admin tier.
// Detect a partial rename or out-of-band UPDATE that desyncs name from flag and
// fail fast — silent drift would produce a tier-bypass exploit.
if (!needsSetup)
{
    try
    {
        using var tierScope = app.Services.CreateScope();
        var tierDb = tierScope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var inconsistentSuper = tierDb.CaGroups.Any(g => g.Name == "system-super" && !g.IsSystemTierSuper);
        var rogueSuper = tierDb.CaGroups.Any(g => g.Name != "system-super" && g.IsSystemTierSuper);
        if (inconsistentSuper || rogueSuper)
        {
            Console.Error.WriteLine("[FATAL] System-group tier consistency check failed:");
            if (inconsistentSuper)
                Console.Error.WriteLine("        A row named 'system-super' exists but IsSystemTierSuper=false.");
            if (rogueSuper)
                Console.Error.WriteLine("        A row with IsSystemTierSuper=true is named something other than 'system-super'.");
            Console.Error.WriteLine("        Either condition desyncs runtime authz from bootstrap intent;");
            Console.Error.WriteLine("        repair the CaGroups row before restarting (refer to the");
            Console.Error.WriteLine("        AddIsSystemTierSuperToCaGroup migration's data step for the canonical state).");
            Environment.Exit(1);
        }
    }
    catch (Exception ex) when (ex is not InvalidOperationException)
    {
        Console.WriteLine($"[STARTUP] System-group consistency check skipped: {ex.Message}");
    }
}

// Load imported trust anchors from DB into the runtime registry (skip if needs setup)
if (!needsSetup)
{
    using var scope = app.Services.CreateScope();
    try
    {
        var trustDb = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        var trustAnchors = trustDb.TrustAnchors.Where(t => t.IsEnabled).ToList();
        foreach (var ta in trustAnchors)
        {
            var cert = new Org.BouncyCastle.X509.X509Certificate(ta.RawCertificate);
            registry.RegisterTrustedCert(cert);
        }
        if (trustAnchors.Count > 0)
            Console.WriteLine($"[TrustAnchors] Loaded {trustAnchors.Count} trust anchor(s) into runtime registry.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[TrustAnchors] Failed to load trust anchors: {ex.Message}");
    }
}

// Configure the HTTP request pipeline.

// Global exception handler — writes a sanitized
// application/problem+json response with the correlation ID populated by
// CorrelationIdMiddleware. No stack traces or SQL ever leak to
// clients, even when the environment is Development. Runs first in the
// pipeline so it sees every exception thrown by downstream middleware.
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var featureEx = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>();
        var correlationId = context.Items.TryGetValue("CorrelationId", out var cid) && cid is string s && !string.IsNullOrEmpty(s)
            ? s
            : (System.Diagnostics.Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("N"));

        try
        {
            Serilog.Log.Error(featureEx?.Error, "Unhandled exception in request pipeline correlationId={CorrelationId} path={Path}",
                correlationId, context.Request.Path.Value ?? string.Empty);
        }
        catch { /* logger must not rethrow */ }

        if (context.Response.HasStarted) return;
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/problem+json";
        context.Response.Headers["X-Correlation-Id"] = correlationId;
        var body = System.Text.Json.JsonSerializer.Serialize(new
        {
            type = "about:blank",
            title = "Internal Server Error",
            status = 500,
            detail = "An unexpected error occurred. Contact your administrator with the correlation id below.",
            correlationId
        });
        await context.Response.WriteAsync(body);
    });
});

// Participate in ASP.NET Core's built-in HSTS
// middleware so the host-level hardening applies when TLS is active. The
// custom SecurityHeadersMiddleware still enforces HSTS for the admin UI
// headers, but UseHsts also sets header-propagation for non-direct-reply
// paths. UseHsts is a no-op in Development.
app.UseHsts();

if (app.Environment.IsDevelopment() || config.Http.SwaggerEnabled)
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// HTTPS redirection is intentionally NOT applied. The app binds three listeners:
//   • 8443 — HTTPS management UI
//   • 8444 — HTTPS mTLS auth port
//   • 8080 — plain HTTP for CRL / OCSP / AIA (RFC 5280 §4.2.1.13 recommends HTTP
//            for CDP to avoid chicken-and-egg trust during certificate validation;
//            most crypto clients also don't follow redirects on CRL fetches).
// HttpsRedirectionMiddleware can't pick between 8443/8444 and would redirect the
// plain-HTTP PKI endpoints to HTTPS, breaking revocation consumers. HSTS set by
// SecurityHeadersMiddleware already handles the "prefer HTTPS" signal for browsers
// hitting the management UI.

var forwardedOptions = new Microsoft.AspNetCore.Builder.ForwardedHeadersOptions
{
    ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
                       Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto |
                       Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedHost,
    // Configurable because a CDN in front of a reverse proxy is two hops, and walking back only
    // one yields the CDN's edge address and treats it as the client. See
    // HttpConfig.ForwardedHeaderHopLimit. Clamped to at least 1: zero disables the walk entirely
    // while still looking like a configured value.
    ForwardLimit = Math.Max(1, config.Http.ForwardedHeaderHopLimit)
};
// Default trusted-proxy set is loopback only. Operators who
// deploy ModularCA behind a reverse proxy (nginx, Traefik, HAProxy, ALB, etc.)
// MUST enumerate their proxy subnets in Http.TrustedProxyCidrs. The previous
// default trusted every RFC1918 range, which was an IP-whitelist-bypass risk in
// shared-tenancy / flat-network environments because a malicious neighbour on
// 10.0.0.0/8 could forge X-Forwarded-For to land inside the whitelist.
forwardedOptions.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.Loopback, 32));
forwardedOptions.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.IPv6Loopback, 128));

if (!string.IsNullOrWhiteSpace(config.Http.TrustedProxyCidrs))
{
    foreach (var cidr in config.Http.TrustedProxyCidrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        var slashIdx = cidr.IndexOf('/');
        if (slashIdx <= 0) { Console.WriteLine($"[WARNING] TrustedProxyCidrs entry '{cidr}' is not in CIDR form, skipping."); continue; }
        if (!System.Net.IPAddress.TryParse(cidr[..slashIdx], out var addr)) { Console.WriteLine($"[WARNING] TrustedProxyCidrs entry '{cidr}' has an invalid address, skipping."); continue; }
        if (!int.TryParse(cidr[(slashIdx + 1)..], out var prefixLen)) { Console.WriteLine($"[WARNING] TrustedProxyCidrs entry '{cidr}' has an invalid prefix length, skipping."); continue; }
        try
        {
            forwardedOptions.KnownIPNetworks.Add(new System.Net.IPNetwork(addr, prefixLen));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARNING] TrustedProxyCidrs entry '{cidr}' rejected: {ex.Message}");
        }
    }
}
// A deployment that says it is behind a proxy but names no trusted proxy falls back to
// loopback-only, which means X-Forwarded-For is ignored and every request is attributed to the
// proxy's own address. That address is usually RFC1918, so it satisfies every internal-only IP
// whitelist rule and the whitelist silently permits the entire internet — failing open, with no
// symptom until someone checks. Nothing said a word about this before; it cost an afternoon of
// probing two live deployments to find.
if (config.Security.BehindReverseProxy && string.IsNullOrWhiteSpace(config.Http.TrustedProxyCidrs))
{
    Console.WriteLine();
    Console.WriteLine("  !! WARNING: Security.BehindReverseProxy is true but Http.TrustedProxyCidrs is empty.");
    Console.WriteLine("     Forwarded headers are therefore trusted from loopback only, so X-Forwarded-For");
    Console.WriteLine("     from your proxy is IGNORED and every request is recorded as coming from the");
    Console.WriteLine("     proxy itself. If that address is RFC1918 it satisfies the internal-only IP");
    Console.WriteLine("     whitelist rules, and the whitelist will permit callers from anywhere.");
    Console.WriteLine("     The audit trail and per-IP login rate limiting are degraded the same way.");
    Console.WriteLine("     Set Http.TrustedProxyCidrs to your proxy's address, e.g. \"10.0.1.5/32\".");
    Console.WriteLine();
}

app.UseForwardedHeaders(forwardedOptions);

// Standard error response format: { "error": "message" }
// ACME endpoints use RFC 8555 format: { "type": "urn:...", "detail": "message", "status": 400 }
// Step-up MFA errors add: { "requiresStepUp": true }

app.UseMiddleware<ModularCA.API.Middleware.SecurityHeadersMiddleware>();
app.UseMiddleware<ModularCA.API.Middleware.PlainHttpBodyLimitMiddleware>(); // 256 KB body cap on plain-HTTP listener
app.UseMiddleware<ModularCA.API.Middleware.AuditFailClosedMiddleware>(); // Translate AuditWriteFailedException → 503
app.UseMiddleware<ModularCA.API.Middleware.ConcurrencyConflictMiddleware>(); // Translate DbUpdateConcurrencyException → 409
app.UseMiddleware<ModularCA.API.Middleware.RequestValidationMiddleware>();   // Translate RequestValidationException → 400
app.UseMiddleware<ModularCA.API.Middleware.HttpSchemeEnforcementMiddleware>(); // HTTP→HTTPS for non-PKI paths on the plain-HTTP listener
// Honour inbound traceparent / X-Correlation-Id headers and echo
// them back on the response so multi-hop requests can be followed end-to-end.
// Must run before RequestAuditMiddleware and UseSerilogRequestLogging so both see the id.
app.UseMiddleware<ModularCA.API.Middleware.CorrelationIdMiddleware>();
app.UseMiddleware<ModularCA.API.Middleware.RequestAuditMiddleware>();    // first — logs all requests
app.UseMiddleware<ModularCA.API.Middleware.MtlsMiddleware>();            // mTLS — require client certs on admin paths
app.UseMiddleware<ModularCA.API.Middleware.IpWhitelistMiddleware>();     // blocks unauthorized IPs
app.UseMiddleware<ModularCA.API.Middleware.LoginRateLimitMiddleware>();
app.UseMiddleware<ModularCA.API.Middleware.ProtocolRateLimitMiddleware>();
app.UseSerilogRequestLogging(opts =>
{
    // Stamp the resolved CorrelationId (set by CorrelationIdMiddleware)
    // onto the request-completed log event so it appears in every sink including syslog.
    opts.EnrichDiagnosticContext = (diag, ctx) =>
    {
        if (ctx.Items.TryGetValue("CorrelationId", out var cid) && cid is string s && !string.IsNullOrEmpty(s))
        {
            diag.Set("CorrelationId", s);
        }
    };
});

// CORS is gated on an explicit Http.EnableCors
// flag, not on ASPNETCORE_ENVIRONMENT. A misset env var no longer flips on
// cross-origin access in production.
if (config.Http.EnableCors && corsOrigins.Length > 0)
{
    app.UseCors("AllowFrontend");
    Console.WriteLine($"[CORS] Restricted CORS policy active for origins: {string.Join(", ", corsOrigins)}");
}

// Serve static files from wwwroot relative to ContentRoot
var webRoot = Path.Combine(app.Environment.ContentRootPath, "wwwroot");
if (Directory.Exists(webRoot))
{
    app.Environment.WebRootPath = webRoot;
}

// Refuse to start if the configured backup output directory resolves under wwwroot.
// Backups contain encrypted CA private key material — if they are reachable via static-files
// they become anonymously downloadable by a date-range guess. Hard-fail at boot is the only
// safe behaviour here.
if (Directory.Exists(webRoot) && config.Backup != null && !string.IsNullOrEmpty(config.Backup.OutputPath))
{
    var resolvedBackupPath = Path.IsPathRooted(config.Backup.OutputPath)
        ? Path.GetFullPath(config.Backup.OutputPath)
        : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, config.Backup.OutputPath));
    var fullWebRoot = Path.GetFullPath(webRoot);
    var withSep = fullWebRoot.EndsWith(Path.DirectorySeparatorChar) ? fullWebRoot : fullWebRoot + Path.DirectorySeparatorChar;
    if (resolvedBackupPath.Equals(fullWebRoot, StringComparison.Ordinal) ||
        resolvedBackupPath.StartsWith(withSep, StringComparison.Ordinal))
    {
        Console.Error.WriteLine(
            $"❌ STARTUP REFUSED: Backup.OutputPath ('{resolvedBackupPath}') resolves under the static-files wwwroot ('{fullWebRoot}'). " +
            "Backups contain CA private key material and must NOT be served as static files. Move backups outside wwwroot before restarting.");
        Environment.Exit(1);
    }
}

app.UseMiddleware<ModularCA.API.Middleware.CsrfProtectionMiddleware>();

// Cache the fingerprinted bundles forever; never cache the documents that point at them.
//
// Vite emits every chunk under assets/ with a content hash in its filename, so those files are
// immutable by construction and can be cached indefinitely. index.html is the opposite: it is
// the only mutable file, it names which hashed bundles to load, and a stale copy pins a browser
// to a build that is no longer deployed. With no directives at all the browser applies heuristic
// caching to both, which is the wrong answer for each.
//
// This was not theoretical. A staging deployment served a superseded bundle to a browser holding
// a cached index.html, and hours went into debugging source that was not the source running.
// Pairs with install.sh, which now clears wwwroot on upgrade so a superseded chunk is not left
// on disk to be served even if something does ask for it.
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        var headers = ctx.Context.Response.Headers;

        if (ctx.File.Name.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
        {
            headers.CacheControl = "no-cache, must-revalidate";
        }
        else if (ctx.Context.Request.Path.Value?.Contains("/assets/", StringComparison.OrdinalIgnoreCase) == true)
        {
            headers.CacheControl = "public, max-age=31536000, immutable";
        }
        else
        {
            // Favicons, vite.svg, root-level assets: mutable but rarely changed. Revalidate
            // cheaply rather than pinning them or forcing a re-download every navigation.
            headers.CacheControl = "no-cache";
        }
    }
});

app.UseMiddleware<ModularCA.API.Middleware.SetupRedirectMiddleware>();

app.UseRouting();
app.UseAuthentication();
app.UseMiddleware<ModularCA.API.Middleware.TokenRevocationMiddleware>();
app.UseMiddleware<ModularCA.API.Middleware.TenantResolutionMiddleware>();
app.UseAuthorization();
app.UseMiddleware<ModularCA.API.Middleware.ReservedCaLabelGuardMiddleware>(); // Reject reserved system CA labels on any /{caLabel}/ protocol route
app.UseMiddleware<ModularCA.API.Middleware.ProtocolFeatureGateMiddleware>(); // Gate protocol endpoints by feature flag
app.UseMiddleware<ModularCA.API.Middleware.JwtIpBindingMiddleware>();
app.UseMiddleware<ModularCA.API.Middleware.MfaEnrollmentMiddleware>();
app.UseMiddleware<ModularCA.API.Middleware.DocsAuthMiddleware>();

// Root path: permanently redirect to the public landing UI.
app.MapGet("/", () => Microsoft.AspNetCore.Http.Results.Redirect("/public/", permanent: true)).AllowAnonymous();

app.MapControllers();

// Split /health into a minimal anonymous liveness probe
// and an authenticated readiness probe. The old combined endpoint leaked MySQL
// hostnames, raw exception messages, CA subject DNs, expiring-cert metadata, and
// host disk capacity to any anonymous caller on the Internet.
//
// /health/live  — anonymous, returns { "status": "..." } only. Safe for LB probes.
// /health/ready — requires SystemAuditor, returns the full structured payload.
//                 HTTP 503 on Degraded/Unhealthy so LBs and SIEMs see the failure.
app.MapHealthChecks("/health/live", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    AllowCachingResponses = false,
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var statusStr = report.Status switch
        {
            Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy => "healthy",
            Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Degraded => "degraded",
            _ => "unhealthy"
        };
        // Deliberately minimal — no checks, no exception messages, no hostnames.
        await context.Response.WriteAsJsonAsync(new { status = statusStr });
    }
}).AllowAnonymous();

// Capture process start for the uptime field. Process.StartTime is the true OS
// process start regardless of when it's read; fall back to now if the platform
// denies the lookup so the readiness endpoint never throws over a stat.
DateTime appStartUtc;
try { appStartUtc = System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime(); }
catch { appStartUtc = DateTime.UtcNow; }

app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    AllowCachingResponses = false,
    // Degraded maps to 503 so load balancers do not keep sending
    // traffic to a node whose audit DB is down or whose TLS cert has expired.
    ResultStatusCodes = new Dictionary<Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus, int>
    {
        [Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy] = StatusCodes.Status200OK,
        [Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Degraded] = StatusCodes.Status503ServiceUnavailable,
        [Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable
    },
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var statusStr = report.Status switch
        {
            Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy => "healthy",
            Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Degraded => "degraded",
            _ => "unhealthy"
        };
        var checks = new Dictionary<string, object>();
        foreach (var entry in report.Entries)
        {
            foreach (var kv in entry.Value.Data)
            {
                checks[kv.Key] = kv.Value;
            }
        }
        var result = new
        {
            status = statusStr,
            checks,
            totalDurationMs = report.TotalDuration.TotalMilliseconds,
            uptimeSeconds = (DateTime.UtcNow - appStartUtc).TotalSeconds,
            timestamp = DateTime.UtcNow.ToString("o")
        };
        await context.Response.WriteAsJsonAsync(result);
    }
}).RequireAuthorization("SystemAuditor");

// Legacy /health compatibility shim — redirects callers to the split endpoints.
// Anonymous GET returns the minimal liveness payload so existing probes do not break.
app.MapGet("/health", async context =>
{
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsJsonAsync(new
    {
        status = "healthy",
        detail = "Use /health/live (anonymous, minimal) or /health/ready (authorized, full)."
    });
}).AllowAnonymous();

// Prometheus metrics endpoint. Always registered so
// Prometheus scrape jobs see a deterministic 503 (not a hard 404) when the
// feature flag is toggled off. Startup emits a Log.Warning so SIEM sees the
// silent-monitoring-loss condition the moment it happens. Gated solely by the
// Metrics.Enabled feature flag (admin UI toggle); YAML controls sink-specific
// config (Path) only.
var metricsFlagEnabled = sinkFlags.GetValueOrDefault("Metrics.Enabled", true);
var metricsEndpointActive = metricsFlagEnabled;
if (!metricsEndpointActive)
{
    Log.Warning("Prometheus metrics endpoint disabled by feature flag (Metrics.Enabled={FeatureFlag}). Scrapers will receive 503.",
        metricsFlagEnabled);
}
app.MapGet(config.Metrics.Path, async context =>
{
    if (!metricsEndpointActive)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.RetryAfter = "60";
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync("# ModularCA metrics endpoint is disabled by configuration.\n");
        return;
    }
    context.Response.ContentType = "text/plain; version=0.0.4; charset=utf-8";
    await Prometheus.Metrics.DefaultRegistry.CollectAndExportAsTextAsync(context.Response.Body);
}).RequireAuthorization("SystemAuditor");

// Surface feature-flag lookup failures. Running on default
// sink/metrics flags when the DB is unreachable is operationally valid (first-run
// bootstrap) but operators need to know. Skip in setup mode — tables don't exist yet.
if (sinkFlagsQueryFailed && !isSetupMode)
{
    Log.Warning(sinkFlagsQueryError,
        "FeatureFlags lookup failed at startup — running on defaults (Syslog/EventLog/Metrics enabled). Once the DB is reachable, restart to pick up operator overrides.");
}

// SPA fallback routes — serve index.html for client-side routing.
// AllowAnonymous is required because FallbackPolicy=RequireAuthenticatedUser
// would otherwise 401 the SPA HTML shell before the browser can even load the login page.
// Auth for admin/user pages happens client-side (AuthContext redirects to login) and
// server-side (API endpoints enforce their own [Authorize] policies).
app.MapFallback(context =>
{
    var path = context.Request.Path.Value ?? "";

    // Root redirect: / -> /public/
    if (path == "/" || path == "")
    {
        context.Response.Redirect("/public/");
        return Task.CompletedTask;
    }

    if (path.StartsWith("/api/") || path.StartsWith("/metrics")
        || path.StartsWith("/ca/") || path.StartsWith("/crl/")
        || path.StartsWith("/ocsp") || path.StartsWith("/tsa")
        || path.StartsWith("/est/") || path.StartsWith("/scep/")
        || path.StartsWith("/cmp/") || path.StartsWith("/acme/"))
    {
        context.Response.StatusCode = 404;
        return Task.CompletedTask;
    }

    string indexPath;
    if (path.StartsWith("/admin"))
        indexPath = Path.Combine(webRoot, "admin", "index.html");
    else if (path.StartsWith("/user"))
        indexPath = Path.Combine(webRoot, "user", "index.html");
    else if (path.StartsWith("/public"))
        indexPath = Path.Combine(webRoot, "public", "index.html");
    else if (path.StartsWith("/setup"))
        indexPath = Path.Combine(webRoot, "setup", "index.html");
    else if (path.StartsWith("/docs"))
    {
        // Require authentication for docs SPA — if a Bearer token was sent and validated, allow access.
        // Browser page loads without a Bearer header are allowed through so the SPA can boot and
        // perform its own client-side auth check (redirecting to /admin/login if no token in localStorage).
        var authHeader = context.Request.Headers.Authorization.ToString();
        var hasBearerHeader = !string.IsNullOrEmpty(authHeader) &&
                              authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
        if (hasBearerHeader && context.User?.Identity?.IsAuthenticated != true)
        {
            context.Response.Redirect($"/admin/login?returnUrl={Uri.EscapeDataString(path)}");
            return Task.CompletedTask;
        }
        indexPath = Path.Combine(webRoot, "docs", "index.html");
    }
    else
        indexPath = ""; // No fallback for other paths

    if (!string.IsNullOrEmpty(indexPath) && File.Exists(indexPath))
    {
        context.Response.ContentType = "text/html";
        return context.Response.SendFileAsync(indexPath);
    }
    context.Response.StatusCode = 404;
    return Task.CompletedTask;
}).AllowAnonymous();

// Scan every enabled CA that exposes OCSP and loudly
// warn (per-CA) if no delegated responder is provisioned. The responder
// service itself refuses to sign such requests when the DB-backed
// SecurityPolicy.AllowCaDirectSigning=false; the startup warning surfaces
// the configuration gap before the first client request does.
// Skip in setup mode — tables don't exist yet.
if (!isSetupMode)
try
{
    using var ocspStartupScope = app.Services.CreateScope();
    var ocspStartupDb = ocspStartupScope.ServiceProvider.GetRequiredService<ModularCA.Database.ModularCADbContext>();
    var ocspStartupLogger = ocspStartupScope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    var secPolicyRow = ocspStartupDb.SecurityPolicies.AsNoTracking().FirstOrDefault();
    var allowCaDirect = secPolicyRow?.AllowCaDirectSigning ?? false;
    var missingResponder = ocspStartupDb.CertificateAuthorities
        .IgnoreQueryFilters()
        .Where(ca => ca.IsEnabled && !ca.IsDeleted && !ca.IsSshCa && ca.OcspResponderCertificateId == null)
        .Select(ca => new { ca.Label, ca.Name })
        .ToList();
    foreach (var ca in missingResponder)
    {
        if (allowCaDirect)
        {
            ocspStartupLogger.LogWarning(
                "OCSP: CA '{Label}' has no delegated responder configured. SecurityPolicy.AllowCaDirectSigning=true — the CA private key will sign every OCSP response. Provision a delegated responder ASAP.",
                ca.Label ?? ca.Name);
        }
        else
        {
            ocspStartupLogger.LogWarning(
                "OCSP: CA '{Label}' has no delegated responder configured and SecurityPolicy.AllowCaDirectSigning=false. OCSP requests for this CA will return Unauthorized until a responder is provisioned.",
                ca.Label ?? ca.Name);
        }
    }
}
catch (Exception ex)
{
    // Best-effort — a broken scan must not block startup.
    var fallbackLogger = app.Services.GetRequiredService<ILogger<Program>>();
    fallbackLogger.LogWarning(ex, "OCSP: failed to scan for CAs missing a delegated responder at startup");
}

// GitOps policy sync on startup (if enabled)
if (config.PolicySync.Enabled && config.PolicySync.SyncOnStartup)
{
    using var startupScope = app.Services.CreateScope();
    var policySyncService = startupScope.ServiceProvider.GetRequiredService<IPolicySyncService>();
    var policySyncLogger = startupScope.ServiceProvider.GetRequiredService<ILogger<PolicySyncService>>();
    var policyDir = config.PolicySync.PolicyDirectory;
    if (!Path.IsPathRooted(policyDir))
        policyDir = Path.Combine(AppContext.BaseDirectory, policyDir);
    try
    {
        var syncResult = policySyncService.SyncFromDirectoryAsync(policyDir).GetAwaiter().GetResult();
        policySyncLogger.LogInformation("Policy sync on startup: Created={Created}, Updated={Updated}, Unchanged={Unchanged}, Errors={Errors}",
            syncResult.Created, syncResult.Updated, syncResult.Unchanged, syncResult.Errors.Count);
    }
    catch (Exception ex)
    {
        policySyncLogger.LogError(ex, "Policy sync on startup failed");
    }
}

// Drain any logs/bootstrap-audit-*.jsonl files left behind by
// bootstrap (where audit writes must be deferred because the audit DB is not yet
// reachable) and replay each entry into the real audit DB. Wrapped in try/catch
// so a replay failure never blocks startup.
if (!isSetupMode)
{
    try
    {
        using var replayScope = app.Services.CreateScope();
        var replayService = replayScope.ServiceProvider
            .GetRequiredService<ModularCA.Core.Services.BootstrapAuditReplayService>();
        await replayService.ReplayPendingAsync();
    }
    catch (Exception ex)
    {
        var replayLogger = app.Services.GetRequiredService<ILogger<Program>>();
        replayLogger.LogWarning(ex, "Bootstrap audit replay failed at startup; will retry on next boot");
    }
}

app.Run();

// Compute the SHA-256 fingerprint of the setup-mode self-signed cert.
// Format is colon-separated uppercase hex pairs so it visually matches the fingerprint a
// browser shows ("A1:B2:C3:...") — operators can compare the console banner to the wizard's
// first-page display and to the browser's cert-details dialog without mental conversion.
static string ComputeSetupCertFingerprint(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
{
    var rawBytes = cert.RawData;
    var hash = System.Security.Cryptography.SHA256.HashData(rawBytes);
    var sb = new System.Text.StringBuilder(hash.Length * 3);
    for (int i = 0; i < hash.Length; i++)
    {
        if (i > 0) sb.Append(':');
        sb.Append(hash[i].ToString("X2"));
    }
    return sb.ToString();
}

// Generates a temporary self-signed TLS certificate for the setup wizard.
// Valid for 7 days with SANs for localhost and common local addresses.
// Subject follows CA/Browser Forum BR §7.1.4.2 for DV-grade issuance: no O / OU
// (organization fields require OV/EV-level validation that a self-signed bootstrap
// cert can't satisfy). L / ST / C are BR-permitted if validated but omitted here
// because there's no validated location info for a temporary self-signed bootstrap
// cert. Validation happens via the SAN extension + operator fingerprint verification
// banner at startup.
static System.Security.Cryptography.X509Certificates.X509Certificate2 GenerateSetupTlsCert()
{
    using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

    var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
        "CN=modularca-setup",
        ecdsa,
        System.Security.Cryptography.HashAlgorithmName.SHA256);

    // Add SANs for common local access
    var sanBuilder = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
    sanBuilder.AddDnsName("localhost");
    sanBuilder.AddDnsName(Environment.MachineName);
    sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
    sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
    req.CertificateExtensions.Add(sanBuilder.Build());

    // Server authentication EKU
    req.CertificateExtensions.Add(
        new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
            new System.Security.Cryptography.OidCollection
            {
                new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1") // TLS Web Server Authentication
            }, false));

    var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(7));

    // Export and re-import so the private key is available to Kestrel
    var pfxBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "");
    return System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(pfxBytes, "");
}

// Probes whether the given TCP port is bindable on the loopback interface.
// When failFast is true (the default for the production HTTP/HTTPS/mTLS
// listeners), the process exits with a clear error message if the configured
// port is already in use — an operator who wrote Https.Port: 443 must not
// silently end up on 444 because something else holds 443.
// When failFast is false, the historical rolling behaviour is preserved so
// the setup wizard can always come up.
static int FindAvailablePort(int startPort, bool failFast = true)
{
    // First try the configured port.
    if (TryBind(startPort))
        return startPort;

    if (failFast)
    {
        Console.Error.WriteLine($"[FATAL] Port {startPort} is already in use. Refusing to silently roll to a different port.");
        Console.Error.WriteLine($"        A production CA service must listen on the port the operator configured.");
        Console.Error.WriteLine($"        If another process holds the port, identify and stop it, or change the config and restart.");
        Log.Warning("Port {Port} is in use — FindAvailablePort fail-fast triggered (non-setup mode).", startPort);
        Environment.Exit(1);
    }

    // Rolling-port behaviour (setup wizard only).
    for (int port = startPort + 1; port < startPort + 100; port++)
    {
        if (TryBind(port))
        {
            Log.Warning("[SECURITY] Configured port {Configured} in use — rolled to {Actual}. Verify no conflicting process is spoofing the configured port.", startPort, port);
            return port;
        }
    }
    Console.WriteLine($"[WARNING] Could not find an available port starting from {startPort}");
    return startPort;

    static bool TryBind(int port)
    {
        try
        {
            using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch (System.Net.Sockets.SocketException)
        {
            return false;
        }
    }
}
