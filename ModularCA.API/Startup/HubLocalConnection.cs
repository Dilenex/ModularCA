using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Bootstrap;
using ModularCA.Core.Services.Hub;
using ModularCA.Core.Services.Settings;
using ModularCA.HubConnection.Contract;
using ModularCA.HubConnection.Server;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Signing;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// Opens the hub's local connection on a node whose control role is active, when
/// <c>MODULARCA__HUB__SOCKET</c> names a socket. With the variable unset nothing is opened: no
/// listener and no socket file. The listener is its own Kestrel host
/// (<see cref="HubLocalHost"/>), apart from the HTTPS, HTTP and health listeners.
/// </summary>
public static class HubLocalConnection
{
    /// <summary>
    /// Whether this process hosts the hub's local connection: a socket is named, the control
    /// role is active, and the instance is past its setup wizard.
    /// </summary>
    /// <param name="socketPath">The value of <c>MODULARCA__HUB__SOCKET</c>, or null when unset.</param>
    /// <param name="roles">The roles this process runs.</param>
    /// <param name="isSetupMode">Whether the setup wizard is running.</param>
    public static bool Hosts(string? socketPath, ActiveRoles roles, bool isSetupMode)
        => !string.IsNullOrWhiteSpace(socketPath) && !isSetupMode && roles.Has(ProcessRole.Control);

    /// <summary>
    /// Starts the listener and returns its host. It stops, and its socket file is removed, when
    /// <paramref name="node"/> stops. Throws when the socket cannot be bound or its mode cannot
    /// be read, which stops the start: a node told to listen for its hub that cannot is misconfigured.
    /// </summary>
    /// <param name="node">The node's host, built.</param>
    /// <param name="socketPath">The socket's path.</param>
    /// <param name="modes">The mode's state file.</param>
    /// <param name="config">The configuration in memory.</param>
    /// <param name="persistence">Saves the configuration in memory to the settings store.</param>
    public static async Task<WebApplication> StartAsync(
        WebApplication node, string socketPath, InstanceModeStore modes, SystemConfig config, SettingsPersistence persistence)
    {
        var options = new HubLocalHostOptions(
            Path.GetFullPath(socketPath.Trim()),
            HubLocalHostOptions.ParseSocketMode(Environment.GetEnvironmentVariable(HubLocalHostOptions.SocketModeVariable)),
            Path.Combine(Path.GetDirectoryName(Path.GetFullPath(socketPath.Trim())) ?? AppContext.BaseDirectory, HubRequestLedger.FileName));

        var operations = new NodeHubOperations(
            modes, config, node.Services.GetRequiredService<IServiceScopeFactory>(),
            cancellationToken => ReadHealthAsync(node.Services, cancellationToken),
            cancellationToken => CreateBackupAsync(node.Services, config),
            (store, actor, reason, cancellationToken) => persistence.SaveAsync(store, actor, reason, cancellationToken),
            InstanceVersion());

        var host = HubLocalHost.Build(options, operations, builder => builder.Host.UseSerilog());
        await HubLocalHost.StartAsync(host, options);

        Log.Information("[HUB] Listening for the hub on the Unix socket {Socket} (mode {Mode}); health, mode, backup and token replacement only",
            options.SocketPath, Convert.ToString((int)options.SocketMode, 8).PadLeft(4, '0'));
        if (operations.AffiliationTokenHash == null)
            Log.Warning("[HUB] This instance holds no affiliation token hash: the token check on the hub's local connection is OFF, "
                + "and reaching the socket {Socket} is the only proof a request comes from the hub. "
                + "Give it one with Hub.AffiliationTokenSha256 in bootstrap.yaml, --set-hub-token-hash, or over the connection",
                options.SocketPath);

        node.Lifetime.ApplicationStopping.Register(() =>
        {
            try
            {
                host.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                if (File.Exists(options.SocketPath))
                    File.Delete(options.SocketPath);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[HUB] The hub's local connection did not stop cleanly");
            }
        });
        return host;
    }

    /// <summary>The node's readiness as <c>/health/ready</c> reports it: the status and every check's data.</summary>
    private static async Task<HubHealthReport> ReadHealthAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        var report = await services.GetRequiredService<HealthCheckService>().CheckHealthAsync(cancellationToken);
        var checks = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var entry in report.Entries)
            foreach (var (key, value) in entry.Value.Data)
                checks[key] = value;
        var status = report.Status switch
        {
            HealthStatus.Healthy => "healthy",
            HealthStatus.Degraded => "degraded",
            _ => "unhealthy",
        };
        return new HubHealthReport(status, JsonSerializer.SerializeToElement(checks, HubLocalContract.Json));
    }

    /// <summary>
    /// Writes a backup archive the way the console's "Create backup" does, into the configured
    /// backup directory. Older archives are pruned by the next scheduled or console backup, not here.
    /// </summary>
    private static async Task<HubBackupResult> CreateBackupAsync(IServiceProvider services, SystemConfig config)
    {
        var directory = BackupRestore.ResolveBackupDirectory(AppContext.BaseDirectory, config.Backup?.OutputPath);
        Directory.CreateDirectory(directory);
        var name = $"modularca-backup-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()}";
        var path = Path.Combine(directory, name + ".zip");

        var signer = services.GetRequiredService<ISigningService>();
        var exitCode = await BackupRestore.Backup(path, _ => signer);
        if (exitCode != 0)
            throw new InvalidOperationException($"The backup failed with exit code {exitCode}.");

        // An encrypted archive is written under the same name with another extension.
        var written = new FileInfo(path);
        if (!written.Exists)
            written = new DirectoryInfo(directory).GetFiles(name + ".*").OrderByDescending(f => f.Length).FirstOrDefault()
                ?? throw new InvalidOperationException("The backup reported success and left no archive.");
        return new HubBackupResult(written.Name, written.Length, DateTime.UtcNow);
    }

    /// <summary>The product version, without the commit the build stamps after a plus sign.</summary>
    private static string InstanceVersion()
    {
        var informational = typeof(HubLocalConnection).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        var plus = informational.IndexOf('+');
        return plus < 0 ? informational : informational[..plus];
    }
}
