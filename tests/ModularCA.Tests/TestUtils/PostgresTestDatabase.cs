using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using Npgsql;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// Throwaway application databases for the PostgreSQL tests, copied from one migrated template
/// instead of migrated one by one. The first test of a run that asks for a database applies every
/// application migration once, to a template database; every database after that is
/// <c>CREATE DATABASE ... TEMPLATE</c>, a file copy that takes a fraction of the time and none of
/// the catalog work of fifty migrations.
/// </summary>
/// <remarks>
/// <para>
/// The template's name carries a key made from the migration ids and the build of the
/// migrations assembly, so a changed, added or removed migration gives another template and a
/// run never tests against an old schema. Templates and half-built templates under any other
/// key are dropped when a template is built.
/// </para>
/// <para>
/// Only tests that use the migrated schema as their starting point take a copy. A test that is
/// about migrating (the upgrade and ownership harnesses, the schema gate) applies its own
/// migrations, as before.
/// </para>
/// </remarks>
internal static class PostgresTestDatabase
{
    /// <summary>The environment variable naming the test server.</summary>
    public const string ServerVariable = "MODULARCA_TEST_PG";

    /// <summary>What every template database's name starts with.</summary>
    private const string TemplatePrefix = "mca_tpl_app_";

    /// <summary>The advisory lock that lets one process at a time build or sweep templates on a server.</summary>
    private const long BuildLock = 0x4D43415F54504C31; // "MCA_TPL1"

    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly HashSet<string> Built = new(StringComparer.Ordinal);
    private static readonly Lazy<string> Name = new(ComputeTemplateName);

    /// <summary>The name of the template database for this build's migrations.</summary>
    internal static string TemplateName => Name.Value;

    /// <summary>
    /// Creates a database on <paramref name="server"/> that has every application migration
    /// applied, named <paramref name="prefix"/> and a random suffix, and returns its name. The
    /// caller drops it, with <see cref="DropAsync"/>.
    /// </summary>
    public static async Task<string> CreateMigratedAsync(string server, string prefix)
    {
        var name = $"{prefix}_{Guid.NewGuid():N}";
        if (name.Length > 63)
            name = name[..63];
        await EnsureTemplateAsync(server, rebuild: false);
        try
        {
            await ExecuteAsync(server, $"CREATE DATABASE \"{name}\" TEMPLATE \"{TemplateName}\"");
        }
        catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.InvalidCatalogName)
        {
            // Another run with other migrations swept this run's template away. Build it again.
            await EnsureTemplateAsync(server, rebuild: true);
            await ExecuteAsync(server, $"CREATE DATABASE \"{name}\" TEMPLATE \"{TemplateName}\"");
        }
        return name;
    }

    /// <summary>Drops a database made by <see cref="CreateMigratedAsync"/>, closing whatever is still connected to it.</summary>
    public static Task DropAsync(string server, string name)
        => ExecuteAsync(server, $"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");

    /// <summary>
    /// Makes sure the template exists on <paramref name="server"/>: once per process and server
    /// behind a semaphore, and once per server across processes behind an advisory lock, so test
    /// classes running in parallel, or two test runs, never build it twice or copy it half built.
    /// </summary>
    private static async Task EnsureTemplateAsync(string server, bool rebuild)
    {
        await Gate.WaitAsync();
        try
        {
            if (!rebuild && Built.Contains(server))
                return;

            await using var maintenance = new NpgsqlConnection(Unpooled(server, null));
            await maintenance.OpenAsync();
            await ExecuteAsync(maintenance, $"SELECT pg_advisory_lock({BuildLock})");
            try
            {
                var existing = await NamesAsync(maintenance);
                foreach (var stale in existing.Where(n => n != TemplateName))
                    await ExecuteAsync(maintenance, $"DROP DATABASE IF EXISTS \"{stale}\" WITH (FORCE)");
                if (!existing.Contains(TemplateName))
                    await BuildAsync(server, maintenance);
            }
            finally
            {
                await ExecuteAsync(maintenance, $"SELECT pg_advisory_unlock({BuildLock})");
            }
            Built.Add(server);
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>
    /// Migrates a database under a working name, then renames it to the template's name and
    /// closes it to connections: a template that exists is complete, and nothing can be
    /// connected to it while it is copied.
    /// </summary>
    private static async Task BuildAsync(string server, NpgsqlConnection maintenance)
    {
        var working = $"{TemplateName}_wip";
        await ExecuteAsync(maintenance, $"CREATE DATABASE \"{working}\"");
        await using (var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(Unpooled(server, working)).Options))
            await db.Database.MigrateAsync();
        await ExecuteAsync(maintenance, $"ALTER DATABASE \"{working}\" RENAME TO \"{TemplateName}\"");
        await ExecuteAsync(maintenance, $"ALTER DATABASE \"{TemplateName}\" ALLOW_CONNECTIONS false");
    }

    /// <summary>Every template database on the server, finished or not, under any key.</summary>
    private static async Task<List<string>> NamesAsync(NpgsqlConnection maintenance)
    {
        var names = new List<string>();
        await using var command = new NpgsqlCommand(
            $"SELECT datname::text FROM pg_catalog.pg_database WHERE datname LIKE '{TemplatePrefix.Replace("_", "\\_")}%'", maintenance);
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            names.Add(reader.GetString(0));
        return names;
    }

    /// <summary>
    /// The template's name: the prefix and a hash of every application migration id with the
    /// module version of the assembly that holds them, which changes whenever that assembly is
    /// built from different source.
    /// </summary>
    private static string ComputeTemplateName()
    {
        using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql("Host=unused").Options);
        var key = new StringBuilder();
        foreach (var id in db.Database.GetMigrations())
            key.Append(id).Append('\n');
        key.Append(typeof(ModularCADbContext).Assembly.ManifestModule.ModuleVersionId.ToString("N"));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key.ToString()));
        return TemplatePrefix + Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
    }

    private static string Unpooled(string server, string? database)
    {
        var builder = new NpgsqlConnectionStringBuilder(server) { Pooling = false };
        if (database != null)
            builder.Database = database;
        return builder.ConnectionString;
    }

    private static async Task ExecuteAsync(string server, string sql)
    {
        await using var connection = new NpgsqlConnection(Unpooled(server, null));
        await connection.OpenAsync();
        await ExecuteAsync(connection, sql);
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
