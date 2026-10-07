namespace ModularCA.Migrate;

/// <summary>
/// Parses the command line into <see cref="MigrationOptions"/>.
/// </summary>
/// <remarks>
/// Every required value is named rather than positional, because a migration invoked with two
/// hosts the wrong way round is not a mistake anyone should be able to make in a hurry — and
/// because the source and the destination look alike on a command line.
/// </remarks>
public static class CommandLine
{
    /// <summary>
    /// Whether the caller asked for the usage text.
    /// </summary>
    /// <remarks>
    /// Deliberately not true for an empty argument list. On the machine a deployment runs on,
    /// <c>modularca-migrate</c> with nothing after it is the complete command: the source comes
    /// from db.yaml, the destination defaults to the same host, and the administrative role is
    /// borrowed. An earlier version printed the usage in that case, so the invocation named in
    /// its own help text, and in the node's refusal to start, did nothing at all.
    /// </remarks>
    /// <param name="args">The raw arguments.</param>
    /// <returns>True when usage was explicitly requested.</returns>
    public static bool WantsUsage(string[] args) =>
        args.Contains("--help") || args.Contains("-h");

    /// <summary>
    /// Parses arguments, applying defaults and validating that nothing required is missing.
    /// </summary>
    /// <param name="args">The raw arguments.</param>
    /// <returns>The parsed options.</returns>
    /// <exception cref="ArgumentException">A required option is missing or malformed.</exception>
    public static MigrationOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"Unexpected argument '{arg}'.");

            if (arg is "--dry-run" or "--keep-on-failure" or "--no-write-config")
            {
                flags.Add(arg);
                continue;
            }

            if (i + 1 >= args.Length)
                throw new ArgumentException($"'{arg}' needs a value.");

            values[arg] = args[++i];
        }

        int Port(string name, int fallback)
        {
            if (!values.TryGetValue(name, out var raw))
                return fallback;
            return int.TryParse(raw, out var port) && port is > 0 and <= 65535
                ? port
                : throw new ArgumentException($"'{name}' must be a port number, not '{raw}'.");
        }

        // The source side comes out of the deployment's own db.yaml when one can be found, and
        // every one of those options then becomes an override rather than a requirement. This is
        // the difference between a command an operator runs and a command an operator assembles.
        var configPath = ConfigDiscovery.Locate(values.GetValueOrDefault("--config"));
        var found = configPath is null ? null : ConfigDiscovery.Read(configPath);

        string FromConfigOrRequired(string name, Func<ConfigDiscovery.SourceSettings, string> pick)
        {
            if (values.TryGetValue(name, out var explicitValue) && !string.IsNullOrWhiteSpace(explicitValue))
                return explicitValue;
            if (found is not null && !string.IsNullOrWhiteSpace(pick(found)))
                return pick(found);
            throw new ArgumentException(
                configPath is null
                    ? $"'{name}' is required, because no db.yaml was found to read it from. Pass --config "
                      + "if the deployment's configuration is somewhere unusual."
                    : $"'{name}' is required: '{configPath}' does not carry it.");
        }

        var sourceAppDb = FromConfigOrRequired("--source-app-db", c => c.AppDatabase);
        var sourceAuditDb = FromConfigOrRequired("--source-audit-db", c => c.AuditDatabase);
        var sourceUser = FromConfigOrRequired("--source-user", c => c.AppUser);
        var sourceAuditUser = values.GetValueOrDefault("--source-audit-user") ?? found?.AuditUser;

        return new MigrationOptions
        {
            ConfigPath = configPath,

            SourceHost = values.GetValueOrDefault("--source-host") ?? found?.Host ?? "127.0.0.1",
            SourcePort = Port("--source-port", found?.Port is > 0 and not 5432 ? found.Port : 3306),
            SourceUser = sourceUser,
            SourcePassword = FromConfigOrRequired("--source-password", c => c.AppPassword),
            SourceAppDatabase = sourceAppDb,
            SourceAuditDatabase = sourceAuditDb,
            SourceAuditUser = sourceAuditUser,
            SourceAuditPassword = values.GetValueOrDefault("--source-audit-password") ?? found?.AuditPassword,

            // The destination defaults to the same machine and the same names. A PostgreSQL
            // server has no database called modularca yet, so reusing the names the operator
            // already knows costs nothing and keeps their mental model intact.
            TargetHost = values.GetValueOrDefault("--target-host") ?? "127.0.0.1",
            TargetPort = Port("--target-port", 5432),
            TargetAdminUser = values.GetValueOrDefault("--target-admin-user") ?? "",
            TargetAdminPassword = values.GetValueOrDefault("--target-admin-password") ?? "",
            TargetSslMode = values.GetValueOrDefault("--target-ssl-mode") ?? "prefer",
            TargetAppDatabase = values.GetValueOrDefault("--target-app-db") ?? sourceAppDb,
            TargetAuditDatabase = values.GetValueOrDefault("--target-audit-db") ?? sourceAuditDb,
            // The node keeps the name it already answers to. Falling back to the database name
            // only matters when the source account was not named either, which is a command
            // assembled entirely by hand.
            TargetAppRole = values.GetValueOrDefault("--target-app-role")
                ?? (sourceUser.Length > 0 ? sourceUser : sourceAppDb),
            TargetAuditRole = values.GetValueOrDefault("--target-audit-role")
                ?? (sourceAuditUser is { Length: > 0 } u ? u : sourceAuditDb),
            TargetAuditOwnerRole = values.GetValueOrDefault("--target-audit-owner-role")
                ?? ((values.GetValueOrDefault("--target-audit-role")
                     ?? (sourceAuditUser is { Length: > 0 } o ? o : sourceAuditDb)) + "_owner"),

            DryRun = flags.Contains("--dry-run"),
            KeepOnFailure = flags.Contains("--keep-on-failure"),
            NoWriteConfig = flags.Contains("--no-write-config"),
        };
    }
}
