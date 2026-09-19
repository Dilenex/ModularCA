using ModularCA.Shared.Models.Config;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Refuses to start against a MySQL or MariaDB server.
/// <para>
/// This build speaks PostgreSQL only. Pointed at the MariaDB instance a 0.3.0 deployment was
/// using, it would otherwise fail somewhere deep inside the provider with a protocol error, or —
/// worse — connect far enough to start applying an <c>InitialCreate</c> migration against a
/// database that already holds a certificate authority. Both outcomes look like a bug in
/// ModularCA rather than an upgrade performed in the wrong order, and one of them is destructive.
/// </para>
/// <para>
/// So the check is deliberately early, deliberately loud, and deliberately names the document
/// that describes the supported path: upgrade to 0.3.0 on MariaDB first, run the migration
/// helper, then start this build against the PostgreSQL database it produced.
/// </para>
/// </summary>
public static class LegacyDatabaseGuard
{
    /// <summary>The port MySQL and MariaDB listen on by default.</summary>
    public const int MySqlDefaultPort = 3306;

    /// <summary>
    /// The operator-facing explanation, used verbatim by every caller so the message is the same
    /// whether the refusal comes from the node, the bootstrap or the setup wizard.
    /// </summary>
    public const string Explanation =
        "ModularCA 0.3.1 and later run on PostgreSQL only; MySQL and MariaDB are no longer supported.\n"
        + "\n"
        + "The migration helper ships with this build and is already installed. It reads this\n"
        + "configuration itself, so there is nothing to assemble:\n"
        + "\n"
        + "    sudo modularca-migrate --dry-run     # checks everything, creates nothing\n"
        + "    sudo modularca-migrate               # does it, then prints the new db.yaml values\n"
        + "\n"
        + "It never writes to the MariaDB database, so it can be run again, and starting 0.3.0\n"
        + "against MariaDB remains a complete rollback.\n"
        + "\n"
        + "If this deployment has not reached 0.3.0 yet, upgrade to it on MariaDB first: the\n"
        + "helper understands that one schema, which is what keeps it a script rather than a\n"
        + "product. See docs/architecture/postgresql-migration.md.";

    /// <summary>
    /// Returns the reason this configuration looks like MySQL or MariaDB, or null if it does not.
    /// <para>
    /// The signal is the port. A ModularCA deployment's database configuration carries no
    /// connection string an operator could have written by hand — bootstrap generates
    /// <c>db.yaml</c> from host, port, database, user and password — so port 3306 is the only
    /// thing that survives an in-place upgrade to say "this configuration was written for the
    /// old engine". It is also the only thing that is nearly free of false positives: nobody
    /// runs PostgreSQL on 3306 by accident.
    /// </para>
    /// </summary>
    /// <param name="instance">A configured database instance.</param>
    /// <param name="label">Which instance this is, for the message ("App" or "Audit").</param>
    /// <returns>A one-line reason, or null when the configuration is acceptable.</returns>
    public static string? Diagnose(DbInstance instance, string label) =>
        instance.Port == MySqlDefaultPort
            ? $"DB.{label} is configured for {instance.Host}:{instance.Port}, the default MySQL/MariaDB port."
            : null;

    /// <summary>
    /// Returns the reason a raw connection string looks like MySQL or MariaDB, or null if it
    /// does not. Covers the paths where a connection string arrives already assembled — the
    /// setup wizard's test-connection call and anything an operator supplies directly.
    /// </summary>
    /// <param name="connectionString">The connection string to inspect.</param>
    /// <returns>A one-line reason, or null when the connection string is acceptable.</returns>
    public static string? Diagnose(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString)) return null;
        var s = connectionString.ToLowerInvariant();

        // Uid=/Pwd= are MySqlConnector spellings Npgsql does not accept at all, and
        // SslMode=Preferred is a MySqlSslMode member with no Npgsql equivalent. Any of the
        // three means the string was written for the old driver.
        if (s.Contains("uid=") || s.Contains("pwd=") || s.Contains("sslmode=preferred"))
            return "The connection string uses MySqlConnector keywords (Uid/Pwd/SslMode=Preferred).";

        if (s.Contains("port=3306"))
            return "The connection string names port 3306, the default MySQL/MariaDB port.";

        return null;
    }

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> with the full explanation when either
    /// configured database looks like MySQL or MariaDB. Call this before any connection is
    /// opened and before any migration is applied.
    /// </summary>
    /// <param name="config">The database configuration block.</param>
    /// <exception cref="InvalidOperationException">The configuration names a MySQL server.</exception>
    public static void EnsureNotMySql(DbConfig config)
    {
        var reasons = new List<string>();
        if (Diagnose(config.App, "App") is string app) reasons.Add(app);
        if (Diagnose(config.Audit, "Audit") is string audit) reasons.Add(audit);
        if (reasons.Count == 0) return;

        throw new InvalidOperationException(
            "Refusing to start: this configuration points at MySQL or MariaDB.\n\n"
            + string.Join("\n", reasons) + "\n\n"
            + Explanation);
    }

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> with the full explanation when a raw
    /// connection string looks like MySQL or MariaDB.
    /// </summary>
    /// <param name="connectionString">The connection string to inspect.</param>
    /// <exception cref="InvalidOperationException">The connection string names a MySQL server.</exception>
    public static void EnsureNotMySql(string? connectionString)
    {
        if (Diagnose(connectionString) is not string reason) return;
        throw new InvalidOperationException(
            "Refusing to connect: this connection string was written for MySQL or MariaDB.\n\n"
            + reason + "\n\n"
            + Explanation);
    }
}
