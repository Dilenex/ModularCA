using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Models;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// A signer for the command-line backup and restore paths, which run before the node's own
/// container exists. It holds no key and never unlocks: the two operations a backup and a
/// restore need, exporting and importing whole keystore files, are the ones a locked signer
/// performs, and every decision it takes is written to the signer audit in the database it is
/// pointed at, like the node's signer would.
/// </summary>
public static class MaintenanceSigner
{
    /// <summary>
    /// Creates a locked in-process signer over the keystore directory and configuration file,
    /// auditing to the application database <paramref name="appConnectionString"/> names.
    /// </summary>
    /// <param name="keystoresDirectory">The directory holding the keystore files.</param>
    /// <param name="yamlPath">The keystore configuration file the secondary passphrases are read from.</param>
    /// <param name="appConnectionString">The application database, for the pinned signer and the audit.</param>
    public static ISigningService Create(string keystoresDirectory, string yamlPath, string appConnectionString)
    {
        ArgumentNullException.ThrowIfNull(keystoresDirectory);
        ArgumentNullException.ThrowIfNull(yamlPath);
        ArgumentNullException.ThrowIfNull(appConnectionString);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(appConnectionString));
        var provider = services.BuildServiceProvider();
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();
        var registry = new LockedRegistry();
        return new InProcessSigningService(
            registry,
            scopes,
            new DatabaseSignerAuditSink(scopes),
            new FileKeystorePersistence(keystoresDirectory, yamlPath, scopes, registry),
            provider.GetRequiredService<ILogger<InProcessSigningService>>(),
            unlocked: false);
    }

    /// <summary>
    /// Creates an unlocked in-process signer for the command-line backup, which has to wrap the
    /// configuration secrets it carries: the keystores are unlocked as the node unlocks them at
    /// startup, with the passphrases <paramref name="yamlPath"/> and the database supply. Throws
    /// what <see cref="SignerBootstrap.Unlock"/> throws when they cannot be.
    /// </summary>
    /// <param name="keystoresDirectory">The directory holding the keystore files.</param>
    /// <param name="yamlPath">The keystore configuration file the secondary passphrases are read from.</param>
    /// <param name="appConnectionString">The application database, for the pinned signer, the main passphrase and the audit.</param>
    public static ISigningService CreateUnlocked(string keystoresDirectory, string yamlPath, string appConnectionString)
    {
        ArgumentNullException.ThrowIfNull(keystoresDirectory);
        ArgumentNullException.ThrowIfNull(yamlPath);
        ArgumentNullException.ThrowIfNull(appConnectionString);

        var bootstrap = SignerBootstrap.Unlock(yamlPath, keystoresDirectory, appConnectionString);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(appConnectionString));
        var provider = services.BuildServiceProvider();
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();
        return bootstrap.CreateSigner(
            keystoresDirectory,
            yamlPath,
            scopes,
            new DatabaseSignerAuditSink(scopes),
            provider.GetRequiredService<ILogger<InProcessSigningService>>(),
            keyWrapping: null);
    }

    /// <summary>A registry that holds nothing: the maintenance signer has no keys and signs nothing.</summary>
    private sealed class LockedRegistry : ISignerKeyRegistry
    {
        public List<X509Certificate> GetTrustedAuthorities() => new();

        public List<CertificateAuthorityIdentity> GetSigners() => new();

        public IPrivateKeyHandle? GetPrivateKeyFor(X509Certificate cert) => null;

        public void RegisterSigner(X509Certificate certificate, IPrivateKeyHandle handle)
            => throw new InvalidOperationException("The maintenance signer holds no keys.");

        public void RegisterTrustedCert(X509Certificate cert)
            => throw new InvalidOperationException("The maintenance signer holds no certificates.");
    }
}
