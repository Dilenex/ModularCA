using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The compliance scan's <c>ExpiringWithoutRenewal</c> finding and the health score's expiry
/// factors read each certificate's stored warning and alert instants, not a fixed 30 or 7 days.
/// </summary>
public sealed class ExpiryWarningConsumerTests
{
    private static CertificateEntity Cert(double fromDays, double toDays, Action<CertificateEntity>? configure = null)
    {
        var now = DateTime.UtcNow;
        var cert = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N")[..16], SubjectDN = "CN=consumer", Issuer = "CN=ca",
            NotBefore = now.AddDays(fromDays), NotAfter = now.AddDays(toDays),
        };
        configure?.Invoke(cert);
        return cert;
    }

    [Fact]
    public void The_compliance_scan_reports_a_certificate_in_its_warning_with_no_renewal()
    {
        using var db = InMemoryDbContextFactory.Create();
        var tenHours = Cert(-8.0 / 24, 2.0 / 24);
        var fresh = Cert(-1.0 / 24, 9.0 / 24);
        var year = Cert(-300, 65);
        var renewing = Cert(-300, 65);
        var quiet = Cert(-89, 1, c => (c.ExpiryWarningAt, c.ExpiryAlertAt) = (c.NotAfter, c.NotAfter));
        db.Certificates.AddRange(tenHours, fresh, year, renewing, quiet);
        db.SaveChanges();

        var config = new SystemConfig();
        var sp = new ServiceCollection().BuildServiceProvider();
        var job = new ComplianceScanJob(sp, db, new RecordingAlertService(), config, NullLogger<ComplianceScanJob>.Instance,
            new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test"));
        var now = DateTime.UtcNow;
        bool Flagged(CertificateEntity c) => job.AnalyzeCertificate(c, config.ComplianceScan, now, [renewing.CertificateId])
            .Any(f => f.Type == "ExpiringWithoutRenewal");

        Assert.True(Flagged(tenHours));
        Assert.False(Flagged(fresh));
        Assert.True(Flagged(year));
        Assert.False(Flagged(renewing));
        Assert.False(Flagged(quiet));
    }

    [Fact]
    public async Task The_health_score_weighs_the_alert_and_the_warning_from_the_instants()
    {
        using var db = InMemoryDbContextFactory.Create();
        var alerted = Cert(-95, 5);
        var warned = Cert(-80, 20);
        var fine = Cert(-10, 20);
        var quiet = Cert(-95, 5, c => (c.ExpiryWarningAt, c.ExpiryAlertAt) = (c.NotAfter, c.NotAfter));
        var expired = Cert(-95, -1);
        db.Certificates.AddRange(alerted, warned, fine, quiet, expired);
        db.SaveChanges();
        var service = new CertHealthScoreService(db, NullLogger<CertHealthScoreService>.Instance, new SystemConfig());

        async Task<string[]> Expiry(CertificateEntity c) => (await service.CalculateScoreAsync(c.CertificateId)).Factors
            .Where(f => f.Name is "ExpiryAlert" or "ExpiryWarning" or "Expired").Select(f => $"{f.Name}:{f.Severity}").ToArray();

        Assert.Equal(new[] { $"ExpiryAlert:{AlertSeverity.Critical}" }, await Expiry(alerted));
        Assert.Equal(new[] { $"ExpiryWarning:{AlertSeverity.Warning}" }, await Expiry(warned));
        Assert.Empty(await Expiry(fine));
        Assert.Empty(await Expiry(quiet));
        Assert.Equal(new[] { $"Expired:{AlertSeverity.Critical}" }, await Expiry(expired));
    }
}
