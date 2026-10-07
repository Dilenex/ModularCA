using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The CRL service signing through the typed signer, on a real PostgreSQL database. CRL
/// generation locks its counter row with raw SQL, so it never runs on the in-memory provider;
/// this is the one place the full and delta TBSCertList the service really builds meet the
/// signer's parser. Each test creates a throwaway database, applies every migration and drops
/// it. Opt-in through <c>MODULARCA_TEST_PG</c>, as <see cref="PostgresLifecycleQueryTests"/>.
/// </summary>
[Trait("Category", "PostgreSQL")]
public class PostgresTypedCrlTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_crl_service_signs_a_full_and_a_delta_crl_through_the_typed_signer()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = $"modularca_typedcrl_{Guid.NewGuid():N}"[..32];
        await ExecAsync(server, $"CREATE DATABASE \"{name}\"");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
            await db.Database.MigrateAsync();

            var ca = TestCaMaterial.CreateCa("CN=Typed CRL CA, O=ModularCA");
            var spaceId = Guid.NewGuid();
            var caCertificateId = Guid.NewGuid();
            var caId = Guid.NewGuid();
            var revokedSerial = BigInteger.ValueOf(0x1234ABCD);
            db.Spaces.Add(new SpaceEntity { Id = spaceId, Name = "typed-crl", Slug = "typed-crl" });
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = caCertificateId,
                SerialNumber = CertificateUtil.FormatSerialNumber(ca.Certificate.SerialNumber),
                SubjectDN = ca.SubjectDn,
                Issuer = ca.SubjectDn,
                IsCA = true,
                Pem = CertificateUtil.ConvertDerToPem(ca.Certificate.GetEncoded(), "CERTIFICATE"),
                RawCertificate = ca.Certificate.GetEncoded(),
                NotBefore = ca.Certificate.NotBefore,
                NotAfter = ca.Certificate.NotAfter,
            });
            await db.SaveChangesAsync();
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = caId, Name = "typed-crl-ca", Label = "typed-crl-ca", SpaceId = spaceId, CertificateId = caCertificateId, IsEnabled = true,
            });
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = Guid.NewGuid(),
                SerialNumber = CertificateUtil.FormatSerialNumber(revokedSerial),
                SubjectDN = "CN=revoked.typed.test",
                Issuer = ca.SubjectDn,
                IssuerCertificateId = caCertificateId,
                Revoked = true,
                RevocationDate = DateTime.UtcNow.AddMinutes(-5),
                RevocationReason = "KeyCompromise",
                NotBefore = DateTime.UtcNow.AddDays(-1),
                NotAfter = DateTime.UtcNow.AddDays(30),
            });
            db.CrlConfigurations.Add(new CrlConfigurationEntity { CaCertificateId = caCertificateId, UpdateInterval = "0 */6 * * *", DeltaInterval = "0 * * * *" });
            await db.SaveChangesAsync();

            var services = new ServiceCollection();
            services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(connection));
            var scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
            var keystore = new TestKeystore(ca.AsSigner());
            var signer = new InProcessSigningService(keystore, scopes, new DatabaseSignerAuditSink(scopes),
                new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance);
            var crls = new CrlService(db, keystore, NullLogger<CrlService>.Instance, new RecordingAuditService(),
                new NoServiceUrls(), InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), signer);

            var full = new X509CrlParser().ReadCrl(PemToDer(await crls.GenerateCrlAsync(caCertificateId)));
            full.Verify(ca.Certificate.GetPublicKey());
            Assert.NotNull(full.GetRevokedCertificate(revokedSerial));
            Assert.Null(full.GetExtensionValue(X509Extensions.DeltaCrlIndicator));

            var delta = new X509CrlParser().ReadCrl(PemToDer(await crls.GenerateDeltaCrlAsync(caCertificateId)));
            delta.Verify(ca.Certificate.GetPublicKey());
            Assert.NotNull(delta.GetExtensionValue(X509Extensions.DeltaCrlIndicator));

            var rows = await db.SignerAudit.AsNoTracking().Where(r => r.Operation == "Sign").ToListAsync();
            Assert.Equal(2, rows.Count);
            Assert.All(rows, r => Assert.Equal(SignerAuditEntity.AllowedOutcome, r.Outcome));
            Assert.All(rows, r => Assert.Equal(nameof(SigningPurpose.Crl), r.Purpose));

            // The same key refuses the CRL the service just built under any other label.
            var tbs = full.GetTbsCertList();
            var algorithm = SignatureAlgorithm.ForPublicKey(ca.Certificate.GetPublicKey());
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(new KeyRef(caCertificateId), algorithm, tbs,
                SigningContext.ForCa("typed-crl", SigningPurpose.Ocsp, caId, spaceId)));
            Assert.Equal(SigningRefusalReason.UntypedData, ex.Reason);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await ExecAsync(server, $"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");
        }
    }

    private static byte[] PemToDer(string pem)
    {
        using var reader = new StringReader(pem);
        return new Org.BouncyCastle.Utilities.IO.Pem.PemReader(reader).ReadPemObject().Content;
    }

    private static async Task ExecAsync(string server, string sql)
    {
        await using var connection = new NpgsqlConnection(server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => Task.FromResult(new CaServiceUrlEntity());
        public Task<ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ResolvedCaServiceUrls([], [], []));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }
}
