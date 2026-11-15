using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.Tests.Database;

/// <summary>
/// What the rollback-continuity tests on PostgreSQL share: a throwaway copy of the migrated
/// template database, one CA with real key material and a CRL configuration in it, and the real
/// <see cref="CrlService"/> signing through the typed signer over that CA.
/// </summary>
internal static class PostgresCaFixture
{
    /// <summary>The environment variable naming the test server.</summary>
    public const string ServerVariable = "MODULARCA_TEST_PG";

    /// <summary>A CA seeded by <see cref="SeedCaAsync"/>.</summary>
    public sealed record SeededCa(TestCaMaterial Material, Guid CaId, Guid CaCertificateId);

    /// <summary>Runs <paramref name="body"/> over a new migrated database and drops it afterwards.</summary>
    public static async Task WithDatabaseAsync(string prefix, Func<string, Task> body)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, prefix);
        try
        {
            await body(new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await PostgresTestDatabase.DropAsync(server, name);
        }
    }

    /// <summary>A context over <paramref name="connection"/>.</summary>
    public static ModularCADbContext Open(string connection)
        => new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);

    /// <summary>Adds a space, a self-signed CA in it and one CRL configuration that also names a delta interval.</summary>
    public static async Task<SeededCa> SeedCaAsync(ModularCADbContext db, string label)
    {
        var ca = TestCaMaterial.CreateCa($"CN={label}, O=ModularCA");
        var seeded = new SeededCa(ca, Guid.NewGuid(), Guid.NewGuid());
        var spaceId = Guid.NewGuid();
        db.Spaces.Add(new SpaceEntity { Id = spaceId, Name = label, Slug = label });
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = seeded.CaCertificateId,
            SerialNumber = CertificateUtil.FormatSerialNumber(ca.Certificate.SerialNumber),
            SubjectDN = ca.SubjectDn, Issuer = ca.SubjectDn, IsCA = true,
            Pem = CertificateUtil.ConvertDerToPem(ca.Certificate.GetEncoded(), "CERTIFICATE"),
            RawCertificate = ca.Certificate.GetEncoded(),
            NotBefore = ca.Certificate.NotBefore, NotAfter = ca.Certificate.NotAfter,
        });
        await db.SaveChangesAsync();
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = seeded.CaId, Name = label, Label = label, SpaceId = spaceId, CertificateId = seeded.CaCertificateId, IsEnabled = true,
        });
        db.CrlConfigurations.Add(new CrlConfigurationEntity
        {
            Name = label, CaCertificateId = seeded.CaCertificateId, IssuerDN = ca.SubjectDn, UpdateInterval = "0 */6 * * *", DeltaInterval = "0 * * * *",
        });
        await db.SaveChangesAsync();
        return seeded;
    }

    /// <summary>The real CRL service over <paramref name="db"/>, signing with <paramref name="ca"/>'s key through the typed signer.</summary>
    public static CrlService Crls(ModularCADbContext db, string connection, TestCaMaterial ca)
    {
        var services = new ServiceCollection();
        services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(connection));
        var scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
        var keystore = new TestKeystore(ca.AsSigner());
        var signer = new InProcessSigningService(keystore, scopes, new DatabaseSignerAuditSink(scopes),
            new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance);
        return new CrlService(db, keystore, NullLogger<CrlService>.Instance, new RecordingAuditService(),
            new NoServiceUrls(), InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), signer);
    }

    /// <summary>The DER of a PEM object.</summary>
    public static byte[] PemToDer(string pem)
    {
        using var reader = new StringReader(pem);
        return new Org.BouncyCastle.Utilities.IO.Pem.PemReader(reader).ReadPemObject().Content;
    }

    /// <summary>Parses a PEM CRL.</summary>
    public static X509Crl ParseCrl(string pem) => new X509CrlParser().ReadCrl(PemToDer(pem));

    /// <summary>The CRL number extension of <paramref name="crl"/>.</summary>
    public static long CrlNumberOf(X509Crl crl)
        => DerInteger.GetInstance(X509ExtensionUtilities.FromExtensionValue(crl.GetExtensionValue(X509Extensions.CrlNumber))).LongValueExact;

    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => Task.FromResult(new CaServiceUrlEntity());
        public Task<ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ResolvedCaServiceUrls([], [], []));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }
}
