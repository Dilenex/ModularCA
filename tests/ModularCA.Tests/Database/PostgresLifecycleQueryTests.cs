using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.TestUtils;
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
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Six)]
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

    [RequiresEnvironmentFact(ServerVariable)]
    public Task Expiry_warnings_follow_each_certificates_stored_instants() =>
        OnPostgresAsync(CertificateLifecycleScenarios.Expiry_warnings_follow_each_certificates_stored_instants);

    /// <summary>
    /// The SQL re-compute after a profile edit (<see cref="CertificateExpiry.RecomputeAfterProfileChangeAsync"/>)
    /// gives each live certificate of the profile and of its inheriting child the instants
    /// <see cref="ExpiryWarningRule.Compute"/> gives, to the microsecond, CA certificates
    /// included, and leaves revoked, expired and other profiles' certificates alone; a never-warn
    /// profile moves both instants to expiry.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_profile_edit_recomputes_its_certificates_in_sql_as_the_rule_does() =>
        OnPostgresAsync(async db =>
        {
            var w = CertificateExpiryWarningTests.EditWorld.Seed(db);
            async Task<CertificateEntity> Read(CertificateEntity c) =>
                await db.Certificates.AsNoTracking().SingleAsync(x => x.CertificateId == c.CertificateId);
            async Task AssertRule(CertificateEntity c, ExpiryWarningSettings? settings)
            {
                var row = await Read(c);
                var (warningAt, alertAt) = ExpiryWarningRule.Compute(row.NotBefore, row.NotAfter, row.IsCA, settings);
                Assert.True(Math.Abs((warningAt - row.ExpiryWarningAt).TotalMilliseconds) < 1, $"{c.SerialNumber}: warning {row.ExpiryWarningAt:O}, rule {warningAt:O}");
                Assert.True(Math.Abs((alertAt - row.ExpiryAlertAt).TotalMilliseconds) < 1, $"{c.SerialNumber}: alert {row.ExpiryAlertAt:O}, rule {alertAt:O}");
            }
            var before = new[] { await Read(w.Revoked), await Read(w.Expired), await Read(w.OtherLive) };

            var parent = await db.CertProfiles.SingleAsync(p => p.Id == w.Parent.Id);
            parent.ExpiryWarningPercent = 60;
            parent.ExpiryWarningMaxWindow = "P40D";
            parent.ExpiryAlertMaxWindow = "PT12H";
            await db.SaveChangesAsync();
            Assert.Equal(3, await CertificateExpiry.RecomputeAfterProfileChangeAsync(db, w.Parent.Id, DateTime.UtcNow));

            var settings = new ExpiryWarningSettings(60, "P40D", null, "PT12H");
            await AssertRule(w.ParentLive, settings);
            await AssertRule(w.ParentCa, settings);
            await AssertRule(w.ChildLive, settings);
            await AssertRule(w.Revoked, null);
            await AssertRule(w.Expired, null);
            Assert.Equal(before.Select(c => (c.ExpiryWarningAt, c.ExpiryAlertAt)),
                new[] { await Read(w.Revoked), await Read(w.Expired), await Read(w.OtherLive) }.Select(c => (c.ExpiryWarningAt, c.ExpiryAlertAt)));

            // A CA certificate under a profile that sets no level keeps 30 and 7 days.
            Assert.Equal(1, await CertificateExpiry.RecomputeAsync(db, w.Other.Id, ExpiryWarningSettings.None, DateTime.UtcNow));
            var otherCa = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N")[..20], SubjectDN = "CN=ca", Issuer = "CN=ca",
                NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(400), IsCA = true, CertProfileId = w.Other.Id,
                ExpiryWarningAt = DateTime.UtcNow, ExpiryAlertAt = DateTime.UtcNow,
            };
            db.Certificates.Add(otherCa);
            await db.SaveChangesAsync();
            Assert.Equal(2, await CertificateExpiry.RecomputeAsync(db, w.Other.Id, ExpiryWarningSettings.None, DateTime.UtcNow));
            await AssertRule(otherCa, null);
            var ca = await Read(otherCa);
            Assert.True(Math.Abs((ca.NotAfter.AddDays(-30) - ca.ExpiryWarningAt).TotalMilliseconds) < 1);

            Assert.Equal(2, await CertificateExpiry.RecomputeAsync(db, w.Other.Id, new ExpiryWarningSettings(NeverWarn: true), DateTime.UtcNow));
            var quiet = await Read(w.OtherLive);
            Assert.Equal((quiet.NotAfter, quiet.NotAfter), (quiet.ExpiryWarningAt, quiet.ExpiryAlertAt));
        });

    /// <summary>Fails the re-compute's UPDATE, as a statement timeout would.</summary>
    private sealed class FailingRecompute : DbCommandInterceptor
    {
        public int? Timeout { get; private set; }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("UPDATE \"Certificates\" AS c", StringComparison.Ordinal))
            {
                Timeout = command.CommandTimeout;
                throw new InvalidOperationException("The re-compute failed.");
            }
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }
    }

    /// <summary>
    /// A profile edit whose re-compute fails leaves the profile as it was, not saved with its
    /// certificates' instants stale; the re-compute runs at its own command timeout, and saving the
    /// same values again re-computes (<see cref="CertificateExpiry.SaveAndRecomputeAsync"/>).
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_profile_edit_whose_recompute_fails_is_rolled_back() =>
        OnPostgresAsync(async db =>
        {
            var w = CertificateExpiryWarningTests.EditWorld.Seed(db);
            var edit = CertificateExpiryWarningTests.Request(w.Parent);
            edit.ExpiryWarningPercent = 60;

            var interceptor = new FailingRecompute();
            await using (var failing = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
                             .UseNpgsql(db.Database.GetConnectionString()).AddInterceptors(interceptor).Options))
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() => new CertProfileService(failing).UpdateAsync(w.Parent.Id, edit));
            }
            Assert.Equal((int)CertificateExpiry.RecomputeCommandTimeout.TotalSeconds, interceptor.Timeout);
            Assert.Null((await db.CertProfiles.AsNoTracking().SingleAsync(p => p.Id == w.Parent.Id)).ExpiryWarningPercent);

            await using var retry = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(db.Database.GetConnectionString()).Options);
            Assert.Equal(3, await new CertProfileService(retry).UpdateAsync(w.Parent.Id, edit));
            Assert.Equal(60, (await db.CertProfiles.AsNoTracking().SingleAsync(p => p.Id == w.Parent.Id)).ExpiryWarningPercent);
        });

    /// <summary>
    /// The lifecycle indexes the <c>CertificateLifecycleIndexes</c> migration creates, and the
    /// expiry warning index of <c>ProfileExpiryWarnings</c>, are present once every migration has applied.
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
                WHERE schemaname = 'public' AND indexname IN ('IX_Certificates_NotAfter', 'IX_CertificateRequests_RenewalOfCertificateId', 'IX_Certificates_ExpiryWarningAt')
                ORDER BY 1
                """, conn);
            var names = new List<string>();
            await using (var reader = await command.ExecuteReaderAsync())
                while (await reader.ReadAsync())
                    names.Add(reader.GetString(0));
            Assert.Equal(["IX_CertificateRequests_RenewalOfCertificateId", "IX_Certificates_ExpiryWarningAt", "IX_Certificates_NotAfter"], names);
        });

    /// <summary>
    /// Copies the run's migrated template to a new database on the <c>MODULARCA_TEST_PG</c> server (every application
    /// migration applied), runs <paramref name="scenario"/> over it and drops it, whatever the outcome.
    /// </summary>
    private static async Task OnPostgresAsync(Func<ModularCADbContext, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, "modularca_lifecycle");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
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
