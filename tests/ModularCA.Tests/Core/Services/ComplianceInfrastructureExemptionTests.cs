using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The compliance scan and the health score judge end-entity certificates by their validity
/// period and their subject alternative names. A CA certificate, and a certificate a CA issues
/// to itself (OCSP responder, timestamp signer, CMP signer), is not judged by either.
/// </summary>
public sealed class ComplianceInfrastructureExemptionTests
{
    private const string TlsServer = "[\"1.3.6.1.5.5.7.3.1\"]";
    private const string OcspAndTls = "[\"1.3.6.1.5.5.7.3.9\",\"1.3.6.1.5.5.7.3.1\",\"1.3.6.1.5.5.7.3.2\"]";

    private static CertificateEntity Cert(string subject, int years, string? ekus = null, bool isCa = false)
    {
        var now = DateTime.UtcNow;
        return new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N"), SubjectDN = subject, Issuer = "CN=ca",
            NotBefore = now.AddDays(-30), NotAfter = now.AddDays(-30).AddYears(years),
            // No warning yet, so only the checks under test can speak.
            ExpiryWarningAt = now.AddDays(-30).AddYears(years), ExpiryAlertAt = now.AddDays(-30).AddYears(years),
            ExtendedKeyUsagesJson = ekus ?? "[]", SubjectAlternativeNamesJson = "[]", IsCA = isCa,
        };
    }

    private static void IssuedAsInfrastructure(ModularCADbContext db, CertificateEntity cert)
        => db.CertificateRequests.Add(new CertRequestEntity
        {
            Subject = cert.SubjectDN, SubjectAlternativeNames = "[]", CSR = "-", Status = "Issued",
            IsInfrastructureCert = true, IssuedCertificateId = cert.CertificateId,
        });

    private static ComplianceScanJob Job(ModularCADbContext db, SystemConfig config)
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        return new ComplianceScanJob(sp, db, new RecordingAlertService(), config, NullLogger<ComplianceScanJob>.Instance,
            new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test"));
    }

    [Fact]
    public async Task The_request_that_issued_it_or_a_seeded_profile_makes_a_certificate_infrastructure()
    {
        using var db = InMemoryDbContextFactory.Create();
        var responder = Cert("CN=Staging CA OCSP Responder", 10, OcspAndTls);
        var ordinary = Cert("CN=host.example.test", 1, TlsServer);
        var seeded = new CertProfileEntity { Id = Guid.NewGuid(), Name = InfrastructureCertProfiles.Tsa.DefaultProfileName };
        var underSeededProfile = Cert("CN=Staging CA TSA", 10);
        underSeededProfile.CertProfileId = seeded.Id;
        db.CertProfiles.Add(seeded);
        db.Certificates.AddRange(responder, ordinary, underSeededProfile);
        IssuedAsInfrastructure(db, responder);
        db.SaveChanges();

        var all = await InfrastructureCertificates.LoadAsync(db);
        Assert.True(all.Contains(responder));
        Assert.True(all.Contains(underSeededProfile));
        Assert.False(all.Contains(ordinary));

        // Asked about some certificates only, it answers for those.
        var some = await InfrastructureCertificates.LoadAsync(db, [responder.CertificateId, ordinary.CertificateId]);
        Assert.True(some.Contains(responder));
        Assert.False(some.Contains(ordinary));
        Assert.False(InfrastructureCertificates.None.Contains(responder));
    }

    [Fact]
    public void The_scan_does_not_judge_a_CA_or_an_infrastructure_certificate_by_validity_or_names()
    {
        using var db = InMemoryDbContextFactory.Create();
        var config = new SystemConfig();
        var job = Job(db, config);
        var now = DateTime.UtcNow;
        string[] Types(CertificateEntity c, bool infrastructure) => job.AnalyzeCertificate(c, config.ComplianceScan, now, [], infrastructure)
            .Select(f => f.Type).Order().ToArray();

        // An ordinary long-lived TLS server certificate with no names: both findings, as before.
        var ordinary = Cert("CN=host.example.test", 10, TlsServer);
        Assert.Equal(new[] { "MissingSANs", "OverLongValidity" }, Types(ordinary, false));

        // The same shape issued by a CA to itself: neither.
        var responder = Cert("CN=Staging CA OCSP Responder", 10, OcspAndTls);
        Assert.Empty(Types(responder, true));

        // A CA certificate of 25 years: neither, whether or not anything marks it.
        var ca = Cert("CN=Staging CA", 25, isCa: true);
        Assert.Empty(Types(ca, false));
    }

    [Fact]
    public async Task The_health_score_makes_the_same_exemptions()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ordinary = Cert("CN=host.example.test", 10, TlsServer);
        var responder = Cert("CN=Staging CA OCSP Responder", 10, OcspAndTls);
        var ca = Cert("CN=Staging CA", 25, isCa: true);
        db.Certificates.AddRange(ordinary, responder, ca);
        IssuedAsInfrastructure(db, responder);
        db.SaveChanges();
        var service = new CertHealthScoreService(db, NullLogger<CertHealthScoreService>.Instance, new SystemConfig());

        async Task<string[]> Judged(CertificateEntity c) => (await service.CalculateScoreAsync(c.CertificateId)).Factors
            .Where(f => f.Name is "OverLongValidity" or "OverLongValidityPublicTls" or "MissingSans").Select(f => f.Name).Order().ToArray();

        Assert.Equal(new[] { "MissingSans", "OverLongValidity" }, await Judged(ordinary));
        Assert.Empty(await Judged(responder));
        Assert.Empty(await Judged(ca));

        // The bulk path answers the same.
        var bulk = await service.CalculateBulkScoresAsync([ordinary.CertificateId, responder.CertificateId, ca.CertificateId]);
        Assert.Equal(1, bulk.Count(s => s.Factors.Any(f => f.Name is "OverLongValidity" or "MissingSans")));
    }

    [Fact]
    public async Task A_scan_closes_the_findings_earlier_scans_raised_against_exempt_certificates()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ordinary = Cert("CN=host.example.test", 10, TlsServer);
        var responder = Cert("CN=Staging CA OCSP Responder", 10, OcspAndTls);
        var ca = Cert("CN=Staging CA", 25, isCa: true);
        db.Certificates.AddRange(ordinary, responder, ca);
        IssuedAsInfrastructure(db, responder);
        CertComplianceFindingEntity Old(CertificateEntity c, string type) => new()
        {
            CertificateId = c.CertificateId, Type = type, Severity = "Warning", Description = "from an earlier scan",
        };
        db.CertComplianceFindings.AddRange(
            Old(ordinary, "OverLongValidity"), Old(ordinary, "MissingSANs"),
            Old(responder, "OverLongValidity"), Old(responder, "MissingSANs"),
            Old(ca, "OverLongValidity"));
        db.SaveChanges();

        // The step of the scan that closes them, with what the scan hands it: the unresolved
        // findings, the active certificates and which of those are infrastructure.
        await Job(db, new SystemConfig()).AutoResolveExemptFindings(
            db.CertComplianceFindings.Where(f => !f.IsResolved).ToList(), db.Certificates.ToList(),
            await InfrastructureCertificates.LoadAsync(db), DateTime.UtcNow, CancellationToken.None);

        var open = db.CertComplianceFindings.Where(f => !f.IsResolved).Select(f => f.CertificateId).ToList();
        Assert.Equal(2, open.Count);
        Assert.All(open, id => Assert.Equal(ordinary.CertificateId, id));
        Assert.All(db.CertComplianceFindings.Where(f => f.IsResolved).ToList(), f => Assert.NotNull(f.ResolvedAt));
    }
}
