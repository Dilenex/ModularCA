using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The mTLS issuer-standing queries (<see cref="MtlsIssuerStanding.LoadAsync"/>, the
/// <see cref="MtlsCredentialStatus.Usable(DateTime, MtlsIssuerStanding)"/> filter and
/// <see cref="MtlsCredentialStatus.FindForAuthenticationAsync"/>) against a real PostgreSQL
/// database migrated to the latest migration, since SQLite translates them differently: a root
/// CA, an issuing CA beneath it and a client certificate the issuing CA signed, then the root
/// revoked, released and deleted. Opt-in through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresMtlsIssuerStandingTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_root_revoked_or_deleted_above_the_issuing_CA_stops_the_leaf_on_postgres() =>
        OnPostgresAsync(async db =>
        {
            var userId = Guid.NewGuid();
            var rootCaId = Guid.NewGuid();
            var rootCertId = Guid.NewGuid();
            var caId = Guid.NewGuid();
            var caCertId = Guid.NewGuid();
            var leafId = Guid.NewGuid();
            db.Users.Add(new UserEntity { Id = userId, Username = "maya", Email = "maya@example.test", IsActive = true, SecurityStamp = "s" });
            db.Certificates.Add(Row(rootCertId, "01", "CN=Root", "CN=Root", isCa: true, issuerId: null));
            db.Certificates.Add(Row(caCertId, "02", "CN=Issuing", "CN=Root", isCa: true, issuerId: rootCertId));
            db.Certificates.Add(Row(leafId, "03", "CN=maya", "CN=Issuing", isCa: false, issuerId: caCertId));
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = rootCaId, Name = "Root", Label = "root", Type = "Root", CertificateId = rootCertId });
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = caId, Name = "Issuing", Label = "issuing", Type = "Issuing", CertificateId = caCertId, ParentCaId = rootCaId });
            db.MtlsCredentials.Add(new MtlsCredentialEntity
            {
                UserId = userId, CertificateId = leafId, SigningCaId = caId, Thumbprint = "AB", SerialNumber = "03",
                ExpiresAt = DateTime.UtcNow.AddDays(30),
            });
            await db.SaveChangesAsync();

            async Task<(int Usable, MtlsCredentialRefusal Refusal)> StateAsync()
            {
                db.ChangeTracker.Clear();
                var usable = await db.MtlsCredentials.Where(await MtlsCredentialStatus.UsableAsync(db, DateTime.UtcNow)).CountAsync(c => c.UserId == userId);
                var match = await MtlsCredentialStatus.FindForAuthenticationAsync(db, "AB", userId, DateTime.UtcNow);
                return (usable, match.Refusal);
            }

            Assert.Equal((1, MtlsCredentialRefusal.None), await StateAsync());

            await db.Certificates.Where(c => c.CertificateId == rootCertId).ExecuteUpdateAsync(s => s.SetProperty(c => c.Revoked, true));
            Assert.Equal((0, MtlsCredentialRefusal.IssuerRevoked), await StateAsync());

            await db.Certificates.Where(c => c.CertificateId == rootCertId).ExecuteUpdateAsync(s => s.SetProperty(c => c.Revoked, false));
            Assert.Equal((1, MtlsCredentialRefusal.None), await StateAsync());

            await db.CertificateAuthorities.IgnoreQueryFilters().Where(c => c.Id == rootCaId).ExecuteUpdateAsync(s => s.SetProperty(c => c.IsDeleted, true));
            Assert.Equal((0, MtlsCredentialRefusal.IssuerDisabled), await StateAsync());
        });

    private static CertificateEntity Row(Guid id, string serial, string subject, string issuer, bool isCa, Guid? issuerId) => new()
    {
        CertificateId = id,
        SerialNumber = serial,
        SubjectDN = subject,
        Issuer = issuer,
        Pem = "-",
        NotBefore = DateTime.UtcNow.AddDays(-1),
        NotAfter = DateTime.UtcNow.AddYears(1),
        IsCA = isCa,
        IssuerCertificateId = issuerId,
        SubjectAlternativeNamesJson = "[]",
        KeyUsagesJson = "[]",
        ExtendedKeyUsagesJson = "[]",
    };

    private static async Task OnPostgresAsync(Func<ModularCADbContext, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, "modularca_mtls");
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
