using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.SchedulerJobs;

/// <summary>
/// Tests for <see cref="CrlExportJob.CheckNewCrlEntries"/>. The result decides whether to
/// regenerate the CRL on a given pass — a false-negative leaves consumers with a stale CRL
/// that's missing recent revocations (compliance + security gap); a false-positive churns
/// CRL numbers and causes unnecessary downstream re-publishes (LDAP, browser caches).
/// </summary>
public class CrlExportNewEntriesTests
{
    private static CrlExportJob MakeJob(ModularCADbContext db)
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        var config = new SystemConfig();
        // The runner is required by the constructor but CheckNewCrlEntries doesn't invoke it.
        var runner = new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test");
        return new CrlExportJob(
            serviceProvider: sp,
            logger: NullLogger<CrlExportJob>.Instance,
            crlService: null!,
            db: db,
            audit: null!,
            config: config,
            runner: runner);
    }

    private static CertificateEntity MakeCa(string subjectDn) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = Guid.NewGuid().ToString("N"),
        SubjectDN = subjectDn,
        IsCA = true,
        NotBefore = DateTime.UtcNow.AddYears(-1),
        NotAfter = DateTime.UtcNow.AddYears(9),
    };

    /// <summary>
    /// The CRL configuration of <paramref name="ca"/>, created on first use: every CRL row belongs
    /// to one, and the job finds a CA's CRLs through it.
    /// </summary>
    private static Guid ConfigFor(ModularCADbContext db, CertificateEntity ca)
    {
        var existing = db.CrlConfigurations.Local.FirstOrDefault(c => c.CaCertificateId == ca.CertificateId);
        if (existing != null) return existing.TaskId;
        var config = new CrlConfigurationEntity { CaCertificateId = ca.CertificateId, IssuerDN = ca.SubjectDN, UpdateInterval = "0 */6 * * *" };
        db.CrlConfigurations.Add(config);
        return config.TaskId;
    }

    /// <summary>
    /// Another CA with the same subject DN (a rename changes the name, not the CN) published a
    /// newer CRL. That is not this CA's CRL, so this CA's revocation since its own CRL is still
    /// new. The latest CRL used to be found by issuer DN, so the other CA's CRL hid it.
    /// </summary>
    [Fact]
    public async Task Another_cas_crl_under_the_same_subject_dn_does_not_count()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = MakeCa("CN=Test CA, O=Acme");
        var twin = MakeCa("CN=Test CA, O=Acme");
        db.Certificates.AddRange(ca, twin);
        db.Crls.AddRange(
            new CrlEntity { IssuerName = ca.SubjectDN, TaskId = ConfigFor(db, ca), CrlNumber = 1, GeneratedAt = new DateTime(2026, 4, 1, 12, 0, 0, DateTimeKind.Utc) },
            new CrlEntity { IssuerName = twin.SubjectDN, TaskId = ConfigFor(db, twin), CrlNumber = 2, GeneratedAt = new DateTime(2026, 4, 26, 12, 0, 0, DateTimeKind.Utc) });
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            SubjectDN = "CN=client.example.com",
            Issuer = ca.SubjectDN,
            IssuerCertificateId = ca.CertificateId,
            Revoked = true,
            RevocationDate = new DateTime(2026, 4, 10, 9, 0, 0, DateTimeKind.Utc),
        });
        await db.SaveChangesAsync();

        Assert.True(await MakeJob(db).CheckNewCrlEntries(ca));
    }

    [Fact]
    public async Task Returns_True_When_No_Crl_Exists_Yet()
    {
        // Per RFC 5280 §3.3: even an empty CRL is required if none has been issued yet.
        // CheckNewCrlEntries returns true so the first generation actually happens.
        using var db = InMemoryDbContextFactory.Create();
        var ca = MakeCa("CN=Test CA, O=Acme");
        db.Certificates.Add(ca);
        await db.SaveChangesAsync();

        var job = MakeJob(db);

        Assert.True(await job.CheckNewCrlEntries(ca));
    }

    [Fact]
    public async Task Returns_True_When_Revocation_Is_Newer_Than_Latest_Crl()
    {
        // Standard "we have new revocations to publish" path.
        using var db = InMemoryDbContextFactory.Create();
        var ca = MakeCa("CN=Test CA, O=Acme");
        db.Certificates.Add(ca);
        db.Crls.Add(new CrlEntity
        {
            IssuerName = ca.SubjectDN,
            TaskId = ConfigFor(db, ca),
            CrlNumber = 1,
            GeneratedAt = new DateTime(2026, 4, 1, 12, 0, 0, DateTimeKind.Utc),
        });
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            SubjectDN = "CN=client.example.com",
            Issuer = ca.SubjectDN,
            Revoked = true,
            RevocationDate = new DateTime(2026, 4, 26, 9, 0, 0, DateTimeKind.Utc), // newer than CRL
        });
        await db.SaveChangesAsync();

        var job = MakeJob(db);

        Assert.True(await job.CheckNewCrlEntries(ca));
    }

    [Fact]
    public async Task Returns_False_When_All_Revocations_Are_Older_Than_Latest_Crl()
    {
        // The CRL already covers the latest revocations — nothing to publish on this tick.
        using var db = InMemoryDbContextFactory.Create();
        var ca = MakeCa("CN=Test CA, O=Acme");
        db.Certificates.Add(ca);
        db.Crls.Add(new CrlEntity
        {
            IssuerName = ca.SubjectDN,
            TaskId = ConfigFor(db, ca),
            CrlNumber = 5,
            GeneratedAt = new DateTime(2026, 4, 26, 12, 0, 0, DateTimeKind.Utc),
        });
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            SubjectDN = "CN=already-on-crl.example.com",
            Issuer = ca.SubjectDN,
            Revoked = true,
            RevocationDate = new DateTime(2026, 4, 25, 9, 0, 0, DateTimeKind.Utc), // older than CRL
        });
        await db.SaveChangesAsync();

        var job = MakeJob(db);

        Assert.False(await job.CheckNewCrlEntries(ca));
    }

    [Fact]
    public async Task Returns_False_When_There_Are_No_Revoked_Certs_And_A_Crl_Exists()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = MakeCa("CN=Test CA, O=Acme");
        db.Certificates.Add(ca);
        db.Crls.Add(new CrlEntity
        {
            IssuerName = ca.SubjectDN,
            TaskId = ConfigFor(db, ca),
            CrlNumber = 1,
            GeneratedAt = DateTime.UtcNow.AddDays(-1),
        });
        await db.SaveChangesAsync();

        var job = MakeJob(db);

        Assert.False(await job.CheckNewCrlEntries(ca));
    }

    [Fact]
    public async Task Picks_Latest_Crl_By_CrlNumber_Not_Insertion_Order()
    {
        // Multiple CRLs exist for the CA — the helper must compare against the highest
        // CrlNumber, not the first/last inserted. A revocation older than CRL#5 but newer
        // than CRL#1 must NOT count as "new".
        using var db = InMemoryDbContextFactory.Create();
        var ca = MakeCa("CN=Test CA, O=Acme");
        db.Certificates.Add(ca);
        // Insert in non-monotonic order to flush out OrderByDescending bugs.
        db.Crls.AddRange(
            new CrlEntity { IssuerName = ca.SubjectDN, TaskId = ConfigFor(db, ca), CrlNumber = 5, GeneratedAt = new DateTime(2026, 4, 26, 12, 0, 0, DateTimeKind.Utc) },
            new CrlEntity { IssuerName = ca.SubjectDN, TaskId = ConfigFor(db, ca), CrlNumber = 1, GeneratedAt = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc) },
            new CrlEntity { IssuerName = ca.SubjectDN, TaskId = ConfigFor(db, ca), CrlNumber = 3, GeneratedAt = new DateTime(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc) });
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            SubjectDN = "CN=middle-cert.example.com",
            Issuer = ca.SubjectDN,
            Revoked = true,
            // Older than CRL#5's GeneratedAt but newer than CRL#1's. Must compare against #5.
            RevocationDate = new DateTime(2026, 4, 1, 12, 0, 0, DateTimeKind.Utc),
        });
        await db.SaveChangesAsync();

        var job = MakeJob(db);

        Assert.False(await job.CheckNewCrlEntries(ca));
    }
}
