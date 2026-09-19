using ModularCA.Shared.Utils;

namespace ModularCA.Migrate;

/// <summary>
/// Finds the deployment's own <c>db.yaml</c> and reads the source side of the migration out of it.
/// <para>
/// Every value describing the database being migrated <em>from</em> already exists on the machine
/// the migration runs on: the host, the port, both database names and both accounts, written there
/// by bootstrap. Asking an operator to re-type them is asking them to make a typo in a one-way
/// copy, and asking them to hand over an administrative account because the file happens to hold
/// two separate ones is worse.
/// </para>
/// </summary>
public static class ConfigDiscovery
{
    /// <summary>
    /// Where a deployment's db.yaml is, in the order the packages put it. The first that exists
    /// wins, and <c>--config</c> overrides all of them.
    /// </summary>
    public static IReadOnlyList<string> SearchPaths { get; } =
    [
        Path.Combine(AppContext.BaseDirectory, "config", "db.yaml"),
        "/opt/modularca/config/db.yaml",
        "/etc/modularca/db.yaml",
        Path.Combine(Directory.GetCurrentDirectory(), "config", "db.yaml"),
        Path.Combine(Directory.GetCurrentDirectory(), "db.yaml"),
    ];

    /// <summary>
    /// Locates db.yaml, preferring an explicit path.
    /// </summary>
    /// <param name="explicitPath">A path given on the command line, or null to search.</param>
    /// <returns>The path found, or null when there is none.</returns>
    /// <exception cref="ArgumentException">An explicit path was given and does not exist.</exception>
    public static string? Locate(string? explicitPath)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return File.Exists(explicitPath)
                ? explicitPath
                : throw new ArgumentException($"No db.yaml at '{explicitPath}'.");
        }

        return SearchPaths.FirstOrDefault(File.Exists);
    }

    /// <summary>The source side of a migration, as read from a deployment's own configuration.</summary>
    /// <param name="Host">The MariaDB host.</param>
    /// <param name="Port">The MariaDB port.</param>
    /// <param name="AppDatabase">The application database name.</param>
    /// <param name="AppUser">The application account.</param>
    /// <param name="AppPassword">The application account's password.</param>
    /// <param name="AuditDatabase">The audit database name.</param>
    /// <param name="AuditUser">The audit account.</param>
    /// <param name="AuditPassword">The audit account's password.</param>
    public sealed record SourceSettings(
        string Host, int Port,
        string AppDatabase, string AppUser, string AppPassword,
        string AuditDatabase, string AuditUser, string AuditPassword);

    /// <summary>
    /// Reads the source settings out of a db.yaml.
    /// </summary>
    /// <param name="path">The file to read.</param>
    /// <returns>The source settings.</returns>
    /// <exception cref="ArgumentException">The file is unreadable or incomplete.</exception>
    public static SourceSettings Read(string path)
    {
        YamlDbConfigLoader.DbYamlConfig config;
        try
        {
            config = YamlDbConfigLoader.Load(path)
                ?? throw new ArgumentException($"'{path}' could not be read as a db.yaml.");
        }
        catch (UnauthorizedAccessException)
        {
            // db.yaml is deliberately owner-only: it holds the node's database passwords. Saying
            // so beats a bare access-denied, because the fix is to run the command as the user
            // that owns the installation rather than to change the file's permissions.
            throw new ArgumentException(
                $"'{path}' is not readable by this user. It holds the node's database passwords and is "
                + "owner-only by design — run this as root, or as the account the node runs under.");
        }

        if (string.IsNullOrWhiteSpace(config.App.Database) || string.IsNullOrWhiteSpace(config.Audit.Database))
            throw new ArgumentException($"'{path}' does not name both an application and an audit database.");

        return new SourceSettings(
            config.App.Host, config.App.Port,
            config.App.Database, config.App.Username, config.App.Password,
            config.Audit.Database, config.Audit.Username, config.Audit.Password);
    }
}
