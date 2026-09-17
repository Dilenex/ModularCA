using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Keystore.Config;
using ModularCA.Keystore.Hsm;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Identity;
using ModularCA.Signer.Server;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// The process that holds the keys and nothing else. <c>--role signer</c> unlocks the keystore
/// exactly as the node did in stage 1, serves <see cref="ISigningService"/> over gRPC behind
/// mutual TLS on <c>Signer.Listen</c>, admits the one client whose SPKI is
/// <c>Signer.PinnedClientSpki</c>, and writes every decision to the signer audit before it
/// answers: a decision it cannot record is refused. No controller, console, scheduler or
/// protocol endpoint is hosted; the database is opened for classification, ceremony
/// verification and the audit, and for nothing else.
/// </summary>
public static class SignerRole
{
    /// <summary>
    /// Runs the signer role to completion and returns the process exit code. Setup mode has
    /// no keystore to serve and is refused.
    /// </summary>
    /// <param name="config">The loaded configuration, database credentials already applied.</param>
    /// <param name="appConnStr">The application database connection string.</param>
    /// <param name="isSetupMode">Whether <c>config.yaml</c> is absent.</param>
    public static async Task<int> RunAsync(SystemConfig config, string appConnStr, bool isSetupMode)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (isSetupMode)
        {
            Console.Error.WriteLine("[FATAL] The signer role needs a configured install: config.yaml, db.yaml and the keystores.");
            Console.Error.WriteLine("        Complete the setup wizard as a single process first, then split the roles.");
            return 1;
        }

        var baseDirectory = AppContext.BaseDirectory;
        var signerConfig = config.Signer;
        SignerServerOptions options;
        try
        {
            var (address, port) = SignerServerOptions.ParseListen(signerConfig.Listen);
            var serverCertificate = Pkcs12Files.Load(
                SignerConfig.ResolvePath(signerConfig.ServerCertificate, baseDirectory),
                signerConfig.ServerCertificatePassword);
            options = new SignerServerOptions(address, port, serverCertificate, signerConfig.PinnedClientSpki);
        }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or System.Security.Cryptography.CryptographicException)
        {
            Console.Error.WriteLine($"[FATAL] The signer role cannot listen: {ex.Message}");
            Console.Error.WriteLine("        Run --role signer --init-identity to create the identity CA and the server certificate,");
            Console.Error.WriteLine("        then --role signer --issue-node-identity <dir> and set Signer.PinnedClientSpki from its output.");
            return 1;
        }

        var keystoresDirectory = Path.Combine(baseDirectory, "keystores");
        var keystoreYamlPath = Path.Combine(baseDirectory, "config", "keystore.yaml");

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
                    .UseMySql(appConnStr, ServerVersion.AutoDetect(appConnStr), mysql => mysql.CommandTimeout(30))
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
