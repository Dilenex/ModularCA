using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using Microsoft.Extensions.Hosting.Systemd;
using ModularCA.Core.Logging;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.Hsm;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Identity;
using ModularCA.Signer.Server;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;

namespace ModularCA.API.Startup;

/// <summary>
/// The process that holds the keys and nothing else. <c>--role signer</c> unlocks the keystore
/// exactly as the node did in stage 1, serves <see cref="ISigningService"/> over gRPC behind
/// mutual TLS on <c>Signer.Listen</c>, admits the one client whose SPKI is
/// <c>Signer.PinnedClientSpki</c>, and writes every decision to the signer audit before it
/// answers: a decision it cannot record is refused. No controller, console, scheduler or
/// protocol endpoint is hosted; the database is opened for classification, ceremony
/// verification and the audit, and for nothing else. With <c>--signer-dir</c> every file it
/// reads comes from that directory (<see cref="SignerPaths"/>) and its logs go there too.
/// </summary>
public static class SignerRole
{
    /// <summary>
    /// Runs the signer role to completion and returns the process exit code. Setup mode has
    /// no keystore to serve and is refused. The signer applies no migrations: before it listens
    /// it checks the application database, which its audit sink writes to, through
    /// <see cref="SchemaStartup.EnforceAllAsync"/>. It waits, extending the systemd start
    /// timeout, while the control role migrates or the database is unreachable, and refuses a
    /// schema this build does not match. In the shared layout it warns that the node can rewrite
    /// what it reads; in its own directory it writes its file logs and keystore audit there and
    /// warns about a directory or file others can write.
    /// </summary>
    /// <param name="config">The loaded configuration, database credentials already applied.</param>
    /// <param name="appConnStr">The application database connection string.</param>
    /// <param name="isSetupMode">Whether the configuration file or <c>db.yaml</c> is absent.</param>
    /// <param name="paths">Where the signer's files are: the shared layout or its own directory.</param>
    public static async Task<int> RunAsync(SystemConfig config, string appConnStr, bool isSetupMode, SignerPaths paths)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(paths);
        if (isSetupMode)
        {
            if (paths.IsDedicated)
            {
                Console.Error.WriteLine($"[FATAL] The signer role reads {paths.ConfigPath} and {paths.DbYamlPath}, and one is missing or unreadable.");
                Console.Error.WriteLine($"        Fill {paths.SignerDirectory} as README-DEPLOY.md, \"Two units\", describes; nothing under config/ is read in its place.");
                return 1;
            }
            Console.Error.WriteLine("[FATAL] The signer role needs a configured install: config.yaml, db.yaml and the keystores.");
            Console.Error.WriteLine("        Complete the setup wizard as a single process first, then split the roles.");
            return 1;
        }

        if (paths.IsDedicated)
        {
            await UseOwnLogsAsync(config.Logging, paths);
            ModularCA.Keystore.Services.KeystoreService.AuditLogDirectory = paths.LogsDirectory;
            WarnIfOthersCanWrite(paths, config.Signer);
            Log.Information("Signer configuration from {Directory}; logs and keystore audit in {Logs}", paths.SignerDirectory, paths.LogsDirectory);
        }
        else
        {
            Log.Warning("The signer reads {Config}, {Db} and {KeystoreYaml} from the node's configuration directory. "
                + "On one host the node owns that directory: it can change what the signer loads at its next start "
                + "(Hsm.ModulePath, Signer.PinnedClientSpki, Signer.Listen) and replace these files. Give the signer "
                + "its own directory with {Flag}; README-DEPLOY.md, \"Two units\", says how.",
                paths.ConfigPath, paths.DbYamlPath, paths.KeystoreYamlPath, SignerPaths.Flag);
        }

        var schemaExit = await SchemaStartup.EnforceAllAsync(
            [new SchemaTarget("application", DatabaseKind.Application, config.DB.App)],
            appliesMigrations: false,
            config.Schema,
            new Microsoft.Extensions.Hosting.Systemd.SystemdNotifier());
        if (schemaExit is int code)
            return code;

        var signerConfig = config.Signer;
        SignerServerOptions options;
        try
        {
            var (address, port) = SignerServerOptions.ParseListen(signerConfig.Listen);
            var serverCertificate = Pkcs12Files.Load(
                paths.ResolveFile(signerConfig.ServerCertificate),
                signerConfig.ServerCertificatePassword);
            options = new SignerServerOptions(address, port, serverCertificate, signerConfig.PinnedClientSpki);
        }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or System.Security.Cryptography.CryptographicException)
        {
            Console.Error.WriteLine($"[FATAL] The signer role cannot listen: {ex.Message}");
            var role = paths.IsDedicated ? $"--role signer {SignerPaths.Flag} {paths.SignerDirectory}" : "--role signer";
            Console.Error.WriteLine($"        Run {role} --init-identity to create the identity CA and the server certificate,");
            Console.Error.WriteLine($"        then {role} --issue-node-identity <dir> and set Signer.PinnedClientSpki in {paths.ConfigPath} from its output.");
            return 1;
        }

        var keystoresDirectory = paths.KeystoresDirectory;
        var keystoreYamlPath = paths.KeystoreYamlPath;

        // The startup unlock, as the node performs it: a keystore that does not verify is
        // fatal, a keystore that cannot be read leaves the signer locked and saying so.
        SignerBootstrap bootstrap;
        try
        {
            bootstrap = SignerBootstrap.Unlock(keystoreYamlPath, keystoresDirectory, appConnStr);
        }
        catch (Exception ex) when (IsKeystoreIntegrityFailure(ex))
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("[FATAL] Keystore integrity verification failed. The signer refuses to start.");
            Console.Error.WriteLine($"        {ex.GetType().Name}: {ex.Message}");
            Console.Error.WriteLine("        The keystore did not verify. Restore from a known-good backup; do not delete the keystore to get past this message.");
            return 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARNING] Could not load keystores: {ex.GetType().Name}: {ex.Message}");
            Console.WriteLine("          The signer starts locked. Nothing can be signed until this is resolved.");
            bootstrap = SignerBootstrap.Locked();
        }

        Pkcs11SessionManager? hsm = null;
        if (config.Hsm?.Enabled == true && !string.IsNullOrEmpty(config.Hsm.ModulePath))
        {
            try
            {
                hsm = new Pkcs11SessionManager(config.Hsm.ModulePath, config.Hsm.SlotId, config.Hsm.Pin);
                foreach (var cert in bootstrap.AddHsmSigners(hsm, appConnStr))
                    Console.WriteLine($"[HSM] CA loaded: {cert.SubjectDN}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HSM] Initialization failed: {ex.Message}");
                Console.WriteLine("[HSM] Continuing with software-only keystore.");
                hsm = null;
            }
        }

        WebApplication app;
        try
        {
            app = SignerServerHost.Build(options, builder =>
            {
                builder.Host.UseSystemd();
                builder.Host.UseSerilog();

                builder.Services.AddDbContext<ModularCADbContext>(o => o
                    .UseNpgsql(appConnStr, npgsql => npgsql.CommandTimeout(30))
                    .ConfigureWarnings(w => w.Ignore(
                        Microsoft.EntityFrameworkCore.Diagnostics.CoreEventId
                            .PossibleIncorrectRequiredNavigationWithQueryFilterInteractionWarning)));
                builder.Services.AddSingleton(config);
                if (hsm != null)
                    builder.Services.AddSingleton(hsm);

                // The signer role holds the keystore passwords; the node no longer needs them.
                builder.Services.AddSingleton<IKeyWrappingPassphraseProvider>(
                    File.Exists(keystoreYamlPath)
                        ? new KeystoreKeyWrappingPassphraseProvider(keystoreYamlPath)
                        : new SetupModeKeyWrappingPassphraseProvider());
                builder.Services.AddSingleton<ISignerAuditSink>(sp =>
                    new DatabaseSignerAuditSink(sp.GetRequiredService<IServiceScopeFactory>()));
                builder.Services.AddSingleton<ISigningService>(sp => bootstrap.CreateSigner(
                    keystoresDirectory,
                    keystoreYamlPath,
                    sp.GetRequiredService<IServiceScopeFactory>(),
                    sp.GetRequiredService<ISignerAuditSink>(),
                    sp.GetRequiredService<ILogger<InProcessSigningService>>(),
                    sp.GetRequiredService<IKeyWrappingPassphraseProvider>(),
                    failClosedOnAuditFailure: true));
            });
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"[FATAL] The signer role cannot listen: {ex.Message}");
            return 1;
        }

        Console.WriteLine($"[SIGNER] Listening on {options.ListenAddress}:{options.ListenPort} (gRPC over mutual TLS, HTTP/2 only)");
        Console.WriteLine($"[SIGNER] Server SPKI pin: {SpkiPin.Compute(options.ServerCertificate)}");
        Console.WriteLine($"[SIGNER] Admitting the client with SPKI pin: {SpkiPin.Normalize(options.PinnedClientSpki)}");
        Console.WriteLine(bootstrap.Unlocked
            ? "[SIGNER] Keystore unlocked; decisions are refused when the audit cannot record them."
            : "[SIGNER] Keystore LOCKED; every signature is refused until it is.");

        try
        {
            await app.RunAsync();
            return 0;
        }
        finally
        {
            hsm?.Dispose();
        }
    }

    /// <summary>
    /// Replaces the startup logger with the signer's own: the console as the node renders it,
    /// and the file sink at <c>Logging.FilePath</c> resolved against the signer's directory
    /// (<c>logs/modularca-.log</c> there by default), capped at Information like the node's.
    /// The startup logger is closed first so the two never hold the same file.
    /// </summary>
    private static async Task UseOwnLogsAsync(LoggingConfig logging, SignerPaths paths)
    {
        var level = logging.MinLevel?.ToLowerInvariant() switch
        {
            "debug" => LogEventLevel.Debug,
            "warning" => LogEventLevel.Warning,
            "error" => LogEventLevel.Error,
            _ => LogEventLevel.Information,
        };
        var persistentLevel = level < LogEventLevel.Information ? LogEventLevel.Information : level;
        var filePath = paths.ResolveFile(string.IsNullOrWhiteSpace(logging.FilePath) ? "logs/modularca-.log" : logging.FilePath);
        var format = ConsoleLogFormatResolver.Resolve(
            logging.ConsoleFormat,
            SystemdHelpers.IsSystemdService(),
            string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase));

        var configuration = new LoggerConfiguration()
            .MinimumLevel.Is(level)
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "ModularCA.Signer");
        switch (format)
        {
            case ConsoleLogFormat.Systemd:
                configuration.WriteTo.Console(new SystemdTextFormatter());
                break;
            case ConsoleLogFormat.Json:
                configuration.WriteTo.Console(new CompactJsonFormatter());
                break;
            default:
                configuration.WriteTo.Console(outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");
                break;
        }
        configuration.WriteTo.File(new CompactJsonFormatter(), filePath,
            restrictedToMinimumLevel: persistentLevel,
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: logging.RetentionDays,
            fileSizeLimitBytes: (long)logging.MaxFileSizeMb * 1024 * 1024,
            rollOnFileSizeLimit: true,
            shared: true,
            flushToDiskInterval: TimeSpan.FromSeconds(2));

        await Log.CloseAndFlushAsync();
        Log.Logger = configuration.CreateLogger();
    }

    /// <summary>
    /// Warns about the signer's directory, or a settings file in it, that its group or others can
    /// write: the point of the directory is that only the signer's account can. Unix only; the
    /// owner itself is the installer's to check.
    /// </summary>
    private static void WarnIfOthersCanWrite(SignerPaths paths, SignerConfig signer)
    {
        if (OperatingSystem.IsWindows() || paths.SignerDirectory is not { } dir)
            return;
        foreach (var path in paths.SettingsFiles(signer).Where(File.Exists).Prepend(dir))
        {
            try
            {
                var mode = File.GetUnixFileMode(path);
                if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
                    Log.Warning("{Path} can be written by accounts other than its owner; the signer's directory and its files should be owner-only", path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log.Warning("Could not read the mode of {Path}: {Message}", path, ex.Message);
            }
        }
    }

    /// <summary>
    /// Distinguishes a keystore that failed its integrity checks from one that could not be
    /// read, walking the inner exceptions as the loader wraps failures on the way up.
    /// </summary>
    private static bool IsKeystoreIntegrityFailure(Exception? ex)
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
}
