using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Npgsql;

namespace ModularCA.Database;

/// <summary>
/// The connection every path that applies migrations uses: the control role at startup, bootstrap
/// and <c>modularca-migrate</c>. Unpooled, with <c>lock_timeout</c> and <c>statement_timeout</c>
/// from <see cref="SchemaConfig"/>, and a client timeout <see cref="ClientTimeoutMarginSeconds"/>
/// longer than the server's.
/// </summary>
public static class MigrationConnection
{
    /// <summary>How much longer the client waits than the server's statement timeout.</summary>
    public const int ClientTimeoutMarginSeconds = 30;

    /// <summary>The client-side command timeout: the server's limit plus the margin, or 0 for none.</summary>
    public static int ClientTimeoutSeconds(SchemaConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return config.MigrationCommandTimeoutSeconds > 0 ? config.MigrationCommandTimeoutSeconds + ClientTimeoutMarginSeconds : 0;
    }

    /// <summary>The migration connection string for <paramref name="instance"/>.</summary>
    public static string ConnectionString(DbInstance instance, SchemaConfig config)
    {
        ArgumentNullException.ThrowIfNull(instance);
        ArgumentNullException.ThrowIfNull(config);
        return new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance))
        {
            Pooling = false,
            CommandTimeout = ClientTimeoutSeconds(config),
            Options = $"-c lock_timeout={Math.Max(0, config.MigrationLockTimeoutSeconds) * 1000L} "
                + $"-c statement_timeout={Math.Max(0, config.MigrationCommandTimeoutSeconds) * 1000L}",
        }.ConnectionString;
    }

    /// <summary>A standalone context of <paramref name="kind"/> on the migration connection for <paramref name="instance"/>.</summary>
    public static DbContext CreateContext(DatabaseKind kind, DbInstance instance, SchemaConfig config)
    {
        var connectionString = ConnectionString(instance, config);
        var timeout = ClientTimeoutSeconds(config);
        return kind == DatabaseKind.Application
            ? new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(connectionString, o => o.CommandTimeout(timeout)).Options)
            : new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                .UseNpgsql(connectionString, o => o.CommandTimeout(timeout)).Options);
    }
}
