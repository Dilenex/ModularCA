using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Tests.Api;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The lifecycle summary and the certificate list's <c>replaced</c> filter against a real
/// PostgreSQL database migrated to the latest migration: the queries in
/// <c>CertificateLifecycle</c> and <c>AdminCertificateController</c> otherwise only run on the
/// in-memory provider, which translates nothing. Each test creates a throwaway database, applies
/// every migration, runs one of the <see cref="CertificateLifecycleScenarios"/>, and drops it.
/// Opt-in through <c>MODULARCA_TEST_PG</c>, as <see cref="PostgresUpgradeHarnessTests"/>.
/// </summary>
[Trait("Category", "PostgreSQL")]
public class PostgresLifecycleQueryTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [RequiresEnvironmentFact(ServerVariable)]
    public Task Another_spaces_certificates_are_not_counted() =>
        OnPostgresAsync(CertificateLifecycleScenarios.Another_spaces_certificates_are_not_counted);

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_reissue_link_or_flag_marks_the_predecessor_replaced() =>
        OnPostgresAsync(CertificateLifecycleScenarios.A_reissue_link_or_flag_marks_the_predecessor_replaced);

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_newer_valid_certificate_with_the_same_subject_and_san_set_replaces_regardless_of_order_and_case() =>
        OnPostgresAsync(CertificateLifecycleScenarios.A_newer_valid_certificate_with_the_same_subject_and_san_set_replaces_regardless_of_order_and_case);

    [RequiresEnvironmentFact(ServerVariable)]
    public Task Counts_do_not_depend_on_the_list_page() =>
        OnPostgresAsync(CertificateLifecycleScenarios.Counts_do_not_depend_on_the_list_page);

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_retired_or_dismissed_certificate_needs_no_attention() =>
        OnPostgresAsync(CertificateLifecycleScenarios.A_retired_or_dismissed_certificate_needs_no_attention);

    /// <summary>
    /// The lifecycle indexes the <c>CertificateLifecycleIndexes</c> migration creates are present
    /// once every migration has applied.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_lifecycle_indexes_exist_after_migrating() =>
        OnPostgresAsync(async db =>
        {
            var conn = (NpgsqlConnection)db.Database.GetDbConnection();
            if (conn.State != System.Data.ConnectionState.Open)
                await conn.OpenAsync();
            await using var command = new NpgsqlCommand(
                """
                SELECT indexname::text FROM pg_catalog.pg_indexes
                WHERE schemaname = 'public' AND indexname IN ('IX_Certificates_NotAfter', 'IX_CertificateRequests_RenewalOfCertificateId')
                ORDER BY 1
                """, conn);
            var names = new List<string>();
            await using (var reader = await command.ExecuteReaderAsync())
                while (await reader.ReadAsync())
                    names.Add(reader.GetString(0));
            Assert.Equal(["IX_CertificateRequests_RenewalOfCertificateId", "IX_Certificates_NotAfter"], names);
        });

    /// <summary>
    /// Creates a database on the <c>MODULARCA_TEST_PG</c> server, applies every application
    /// migration, runs <paramref name="scenario"/> over it and drops it, whatever the outcome.
    /// </summary>
    private static async Task OnPostgresAsync(Func<ModularCADbContext, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = $"modularca_lifecycle_{Guid.NewGuid():N}"[..32];
        await ExecAsync(server, $"CREATE DATABASE \"{name}\"");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
            await db.Database.MigrateAsync();
            await scenario(db);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await ExecAsync(server, $"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");
        }
    }

    private static async Task ExecAsync(string server, string sql)
    {
        await using var connection = new NpgsqlConnection(server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
