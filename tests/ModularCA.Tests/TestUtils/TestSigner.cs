using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// An in-process signer for tests of the services that sign through <see cref="ISigningService"/>.
/// The signer classifies keys from the database, so it needs the rows the node would have
/// written; <see cref="ForCa"/> seeds them for one CA, and <see cref="Over"/> binds a signer to
/// rows a test seeded itself.
/// </summary>
internal static class TestSigner
{
    /// <summary>A scope factory whose scopes resolve a context over the named in-memory database.</summary>
    public static IServiceScopeFactory ScopesFor(string databaseName)
    {
        var services = new ServiceCollection();
        services.AddDbContext<ModularCADbContext>(o => o
            .UseInMemoryDatabase(databaseName)
            .ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning)));
        return services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
    }

    /// <summary>
    /// An in-process signer over <paramref name="keystore"/>, classifying keys and writing its
    /// audit through the named in-memory database.
    /// </summary>
    public static InProcessSigningService Over(ISignerKeyRegistry keystore, string databaseName, InMemorySignerKeyPersistence? persistence = null)
    {
        var scopes = ScopesFor(databaseName);
        return new InProcessSigningService(keystore, scopes, new DatabaseSignerAuditSink(scopes),
            persistence ?? new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance);
    }

    /// <summary>
    /// Seeds a fresh database with the certificate and CA rows for <paramref name="ca"/>, and
    /// returns a signer holding its key together with the reference and context that let a
    /// caller sign certificates with it.
    /// </summary>
    public static (ISigningService Signer, KeyRef Key, SigningContext Context) ForCa(TestCaMaterial ca, string caller = "test")
    {
        var databaseName = $"signer-{Guid.NewGuid():N}";
        var certificateId = Guid.NewGuid();
        var caId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        using (var db = InMemoryDbContextFactory.Create(databaseName))
        {
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = certificateId,
                SerialNumber = CertificateUtil.FormatSerialNumber(ca.Certificate.SerialNumber),
                SubjectDN = ca.SubjectDn,
                Issuer = ca.SubjectDn,
                IsCA = true,
                Pem = CertificateUtil.ConvertDerToPem(ca.Certificate.GetEncoded(), "CERTIFICATE"),
                RawCertificate = ca.Certificate.GetEncoded(),
                NotBefore = ca.Certificate.NotBefore,
                NotAfter = ca.Certificate.NotAfter,
            });
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = caId,
                Name = "test-ca",
                Label = "test-ca",
                TenantId = tenantId,
                CertificateId = certificateId,
            });
            db.SaveChanges();
        }

        var signer = Over(new TestKeystore(ca.AsSigner()), databaseName);
        return (signer, new KeyRef(certificateId), SigningContext.ForCa(caller, SigningPurpose.Certificate, caId, tenantId));
    }
}
