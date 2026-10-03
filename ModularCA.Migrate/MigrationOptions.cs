using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Migrate;

/// <summary>
/// Everything the helper was told, parsed and validated before it opens a connection.
/// </summary>
/// <remarks>
/// The source is named as a MariaDB connection because that is what a 0.3.0 deployment has. The
/// destination is named as a server plus two database names rather than as connection strings,
/// because the helper <em>creates</em> those databases: it is not handed them. See
/// <see cref="Preflight"/> for why that is the stronger rule.
/// </remarks>
public sealed class MigrationOptions
{
    /// <summary>The db.yaml the source side was read from, or null when it was all given by hand.</summary>
    public string? ConfigPath { get; init; }

    /// <summary>MariaDB host holding the 0.3.0 databases. Read only, never written.</summary>
    public required string SourceHost { get; init; }

    /// <summary>MariaDB port. 3306 unless the deployment moved it.</summary>
    public required int SourcePort { get; init; }

    /// <summary>A MariaDB account with SELECT on both source databases.</summary>
    public required string SourceUser { get; init; }

    /// <summary>The password for <see cref="SourceUser"/>.</summary>
    public required string SourcePassword { get; init; }

    /// <summary>The 0.3.0 application database.</summary>
    public required string SourceAppDatabase { get; init; }

    /// <summary>The 0.3.0 audit database.</summary>
    public required string SourceAuditDatabase { get; init; }

    /// <summary>
    /// An account for the source audit database, when it differs from <see cref="SourceUser"/>.
    /// <para>
    /// A deployment keeps the application and the audit on separate accounts on purpose — it is
    /// what stops the node's own credentials rewriting its audit — so assuming one account can
    /// read both would mean asking an operator to hand over the administrative account just to
    /// run this. Null falls back to the application account.
    /// </para>
    /// </summary>
    public string? SourceAuditUser { get; init; }

    /// <summary>The password for <see cref="SourceAuditUser"/>.</summary>
    public string? SourceAuditPassword { get; init; }

    /// <summary>PostgreSQL host that will hold the migrated databases.</summary>
    public required string TargetHost { get; init; }

    /// <summary>PostgreSQL port.</summary>
    public required int TargetPort { get; init; }

    /// <summary>
    /// A PostgreSQL account that can create databases and roles. Used for the whole run; the
    /// application never sees it.
    /// </summary>
    /// <remarks>
    /// Settable rather than init-only because it can be filled in after parsing, by
    /// <see cref="LocalPostgresAccess"/> creating a temporary role on a host where that is
    /// possible. Empty means none was given and none could be obtained.
    /// </remarks>
    public required string TargetAdminUser { get; set; }

    /// <summary>The password for <see cref="TargetAdminUser"/>.</summary>
    public required string TargetAdminPassword { get; set; }

    /// <summary>TLS mode for the PostgreSQL connections.</summary>
    public required string TargetSslMode { get; init; }

    /// <summary>The application database to create. Must not already exist.</summary>
    public required string TargetAppDatabase { get; init; }

    /// <summary>The audit database to create. Must not already exist.</summary>
    public required string TargetAuditDatabase { get; init; }

    /// <summary>The login role to create for the application. Must not already exist.</summary>
    public required string TargetAppRole { get; init; }

    /// <summary>The login role to create for the audit context. Must not already exist.</summary>
    public required string TargetAuditRole { get; init; }

    /// <summary>
    /// A role created to own the audit database, which can never log in. Must not already exist.
    /// <para>
    /// The audit database must not be owned by the account the node connects with, or the node
    /// could drop its own audit — the guarantee the MySQL setup stated and did not hold. It cannot
    /// be owned by the administrative account either, because that may be the temporary one this
    /// tool borrows, and owning a database would keep it alive past the end of the run. So the
    /// owner is a role with no login and no password, which exists only to be the thing the audit
    /// database belongs to.
    /// </para>
    /// </summary>
    public required string TargetAuditOwnerRole { get; init; }

    /// <summary>
    /// Run every check and stop before creating anything. The whole preflight is readable this
    /// way, which is how an operator finds out about a role-name collision at a time when it
    /// costs nothing.
    /// </summary>
    public bool DryRun { get; init; }

    /// <summary>
    /// Leave a failed run's half-built databases in place for inspection instead of dropping
    /// them. Off by default: the helper created them, so it is entitled to remove them, and a
    /// clean failure is one an operator can simply re-run.
    /// </summary>
    public bool KeepOnFailure { get; init; }

    /// <summary>
    /// Leave the deployment's db.yaml alone and print the new settings instead.
    /// <para>
    /// For a deployment whose configuration is managed from somewhere else — Ansible, a container
    /// image, anything that would overwrite a local edit — where a file this tool wrote would be
    /// reverted on the next converge and the node would go back to looking for a MariaDB.
    /// </para>
    /// </summary>
    public bool NoWriteConfig { get; init; }

    /// <summary>The MariaDB connection string for one of the source databases.</summary>
    /// <param name="database">Which source database to connect to.</param>
    /// <returns>A MySqlConnector connection string.</returns>
    public string SourceConnectionString(string database)
    {
        var audit = string.Equals(database, SourceAuditDatabase, StringComparison.OrdinalIgnoreCase);
        var user = audit ? SourceAuditUser ?? SourceUser : SourceUser;
        var password = audit ? SourceAuditPassword ?? SourcePassword : SourcePassword;
        return $"Server={SourceHost};Port={SourcePort};Database={database};"
            + $"Uid={user};Pwd={password};SslMode=Preferred;AllowUserVariables=true";
    }

    /// <summary>An administrative PostgreSQL connection string, optionally to a named database.</summary>
    /// <param name="database">The database to connect to; the maintenance database when null.</param>
    /// <returns>An Npgsql connection string.</returns>
    public string TargetConnectionString(string? database = null) =>
        PostgresConnection.BuildMaintenance(
            TargetHost, TargetPort, TargetAdminUser, TargetAdminPassword, TargetSslMode,
            database ?? "postgres");

    /// <summary>
    /// The application database instance as the node will be configured to see it, with
    /// <see cref="TargetSslMode"/>, as db.yaml gets it.
    /// </summary>
    /// <param name="password">The password generated for the application role.</param>
    /// <returns>A <see cref="DbInstance"/> ready to be written into db.yaml.</returns>
    public DbInstance AppInstance(string password) => new()
    {
        Host = TargetHost,
        Port = TargetPort,
        Username = TargetAppRole,
        Password = password,
        Database = TargetAppDatabase,
        SslMode = TargetSslMode,
    };

    /// <summary>
    /// The audit database instance as the node will be configured to see it, with
    /// <see cref="TargetSslMode"/>, as db.yaml gets it.
    /// </summary>
    /// <param name="password">The password generated for the audit role.</param>
    /// <returns>A <see cref="DbInstance"/> ready to be written into db.yaml.</returns>
    public DbInstance AuditInstance(string password) => new()
    {
        Host = TargetHost,
        Port = TargetPort,
        Username = TargetAuditRole,
        Password = password,
        Database = TargetAuditDatabase,
        SslMode = TargetSslMode,
    };
}
