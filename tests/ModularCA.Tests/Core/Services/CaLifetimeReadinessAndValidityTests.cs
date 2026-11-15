using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A CA certificate near its end, or past it, is reported and never makes the node not ready;
/// the validity chosen for a CA certificate raises a notice or a warning and refuses nothing;
/// and the certificate history is whole from a CA's creation on.
/// </summary>
public sealed class CaLifetimeReadinessAndValidityTests
{
    private static X509Certificate SelfSigned(string name, DateTime notAfter)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(Random.Shared.NextInt64(1, long.MaxValue)));
        generator.SetIssuerDN(new X509Name(name));
        generator.SetSubjectDN(new X509Name(name));
        generator.SetNotBefore(notAfter.AddYears(-5));
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(keys.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        return generator.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private));
    }

    /// <summary>The keystore part of the main health check, over a registry holding one CA certificate that ends at <paramref name="notAfter"/>.</summary>
    private static (string Status, System.Text.Json.JsonElement Data) Keystore(DateTime notAfter)
    {
        var certificate = SelfSigned("CN=Readiness Root", notAfter);
        var keystore = new TestKeystore((certificate, new SoftwarePrivateKeyHandle(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Private)));
        var type = ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.ModularCAHealthCheck");
        var check = Activator.CreateInstance(type, null, keystore, null, null, new SystemConfig(), null, null, null)!;
        var result = type.GetMethod("CheckKeystore", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(check, null)!;
        var status = (string)result.GetType().GetField("Item1")!.GetValue(result)!;
        return (status, System.Text.Json.JsonSerializer.SerializeToElement(result.GetType().GetField("Item2")!.GetValue(result)));
    }

    /// <summary>31 days out nothing is said; from 30 days to past the end it is counted, and the keystore check stays healthy throughout.</summary>
    [Theory]
    [InlineData(31, 0, 0)]
    [InlineData(30, 1, 0)]
    [InlineData(7, 1, 0)]
    [InlineData(0, 1, 1)]
    [InlineData(-1, 1, 1)]
    public void An_expiring_or_expired_ca_certificate_is_counted_and_never_fails_readiness(int daysLeft, int expiring, int expired)
    {
        // A minute inside the day, so the boundary itself is not raced by the clock.
        var (status, data) = Keystore(DateTime.UtcNow.AddDays(daysLeft).AddMinutes(daysLeft > 0 ? -1 : -1));

        Assert.Equal("healthy", status);
        Assert.Equal("healthy", data.GetProperty("status").GetString());
        Assert.Equal(expiring, data.TryGetProperty("expiringCaCerts", out var e) ? e.GetInt32() : 0);
        Assert.Equal(expired, data.TryGetProperty("expiredCaCerts", out var x) ? x.GetInt32() : 0);
    }

    /// <summary>The same five days through <c>checks.caLifecycle</c>: the level a monitor reads now that the status no longer changes.</summary>
    [Theory]
    [InlineData(31, CaKeyAdvisory.Notice, CaCryptoperiod.CertificateExpiring)]
    [InlineData(30, CaKeyAdvisory.Warning, CaCryptoperiod.CertificateExpiring)]
    [InlineData(7, CaKeyAdvisory.Critical, CaCryptoperiod.CertificateExpiring)]
    [InlineData(0, CaKeyAdvisory.Critical, CaCryptoperiod.CertificateExpired)]
    [InlineData(-1, CaKeyAdvisory.Critical, CaCryptoperiod.CertificateExpired)]
    public void The_lifecycle_notice_gives_the_level_at_each_boundary(int daysLeft, string severity, string reason)
    {
        var now = new DateTime(2027, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        var end = now.AddDays(daysLeft);
        var facts = new CaCryptoperiodFacts(true, now.AddYears(-4), 1, now.AddYears(-4), end, end.AddDays(-30), end.AddDays(-7), null, null, null, null, null);

        var first = CaCryptoperiod.Advisories(facts, CaCryptoperiodSettings.Defaults, now)[0];

        Assert.Equal((reason, severity), (first.Reason, first.Severity));
    }

    [Fact]
    public async Task The_expiry_job_raises_a_security_alert_for_a_ca_in_its_warning_and_a_critical_one_once_expired()
    {
        using var db = InMemoryDbContextFactory.Create();
        var now = DateTime.UtcNow;
        CertificateAuthorityEntity Ca(string name, DateTime notAfter, bool enabled = true)
        {
            var row = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N"), SubjectDN = $"CN={name}", Issuer = $"CN={name}", IsCA = true, Pem = "x",
                NotBefore = notAfter.AddYears(-5), NotAfter = notAfter, ExpiryWarningAt = notAfter.AddDays(-30), ExpiryAlertAt = notAfter.AddDays(-7),
            };
            db.Certificates.Add(row);
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = name, Label = name.ToLowerInvariant(), CertificateId = row.CertificateId, IsEnabled = enabled };
            db.CertificateAuthorities.Add(ca);
            return ca;
        }
        Ca("Far", now.AddDays(400));
        Ca("Warning", now.AddDays(20));
        Ca("Alert", now.AddDays(3));
        Ca("Expired", now.AddDays(-2));
        Ca("Disabled", now.AddDays(-2), enabled: false);
        db.SaveChanges();
        var alerts = new RecordingAlertService();
        var job = new CertExpiryNotificationJob(null!, db, null!, alerts, new SystemConfig(), NullLogger<CertExpiryNotificationJob>.Instance, null!);

        Assert.Equal(3, await job.AlertOnCaCertificatesAsync(CancellationToken.None));

        Assert.Equal(new[]
            {
                (CertExpiryNotificationJob.CaCertificateExpiredAlert, AlertSeverity.Critical),
                (CertExpiryNotificationJob.CaCertificateExpiringAlert, AlertSeverity.Critical),
                (CertExpiryNotificationJob.CaCertificateExpiringAlert, AlertSeverity.Warning),
            }.OrderBy(x => x.Item1).ThenBy(x => x.Item2),
            alerts.Raised.Select(a => (a.EventType, a.Severity)).OrderBy(x => x.EventType).ThenBy(x => x.Severity));
    }

    // ── The validity chosen ─────────────────────────────────────────────────────────────────

    private static readonly DateTime Start = new(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData(true, 25, false)]
    [InlineData(true, 26, true)]
    [InlineData(false, 10, false)]
    [InlineData(false, 11, true)]
    public void A_validity_beyond_common_practice_is_a_notice_and_nothing_more(bool root, int years, bool expected)
    {
        var advisories = CaKeyPolicy.ValidityAdvisories(root, Start, Start.AddYears(years), rsaBits: null);

        Assert.Equal(expected, advisories.Any(a => a.Reason == CaKeyPolicy.ValidityBeyondCommonPractice));
        Assert.All(advisories, a => Assert.Equal(CaKeyAdvisory.Notice, a.Severity));
        if (expected)
            Assert.Contains("No standard that binds a private CA sets a limit", advisories.Single().Message);
    }

    [Theory]
    [InlineData(2048, "2030-12-31T23:59:59Z", false)]   // through 2030 is what SP 800-57 accepts
    [InlineData(2048, "2031-01-01T00:00:00Z", true)]
    [InlineData(3072, "2040-01-01T00:00:00Z", false)]
    public void An_rsa_key_under_3072_bits_past_2030_is_a_warning_to_acknowledge(int bits, string notAfter, bool expected)
    {
        var end = DateTime.Parse(notAfter, null, System.Globalization.DateTimeStyles.AdjustToUniversal);

        var advisories = CaKeyPolicy.ValidityAdvisories(true, Start, end, bits);

        Assert.Equal(expected, advisories.Any(a => a.Reason == CaKeyPolicy.RsaBelow3072Past2030 && a.Severity == CaKeyAdvisory.Warning));
        if (expected)
        {
            // It says what the standing notice on the CA says: the same number of bits, the same year.
            var message = advisories.Single(a => a.Reason == CaKeyPolicy.RsaBelow3072Past2030).Message;
            Assert.Contains("only through 2030", message);
            Assert.Contains("only through 2030", CaKeyPolicy.RsaBelow3072Message(bits));
            Assert.Contains("RSA 2048", message);
        }
    }

    // ── The history is whole ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_ca_has_its_first_certificate_recorded_when_it_is_created()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var root = await world.W.CreateRootAsync("Recorded Root", null, null);
        var issuing = await world.W.CreateIntermediateAsync(root, "Recorded Issuing", null, null);

        using var db = world.W.World.OpenDb();
        foreach (var ca in new[] { root, issuing })
        {
            var row = db.CaCertificates.Single(h => h.CertificateAuthorityId == ca.Id);
            Assert.Equal((ca.CertificateId!.Value, CaCertificateEntity.OriginInitial), (row.CertificateId, row.Origin));
            Assert.Null(row.SupersededAt);
            Assert.Equal(64, row.KeyId.Length);
        }
    }

    [Fact]
    public async Task A_ca_made_before_the_history_existed_gets_its_first_entry_once()
    {
        using var db = InMemoryDbContextFactory.Create();
        var material = TestCaMaterial.CreateCa("CN=Older Root");
        var certificate = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = "0A", SubjectDN = material.SubjectDn, Issuer = material.SubjectDn, IsCA = true,
            Pem = CertificateUtil.ConvertDerToPem(material.Certificate.GetEncoded(), "CERTIFICATE"), RawCertificate = material.Certificate.GetEncoded(),
            NotBefore = material.Certificate.NotBefore, NotAfter = material.Certificate.NotAfter, CreatedAt = new DateTime(2026, 2, 3, 0, 0, 0, DateTimeKind.Utc),
        };
        db.Certificates.Add(certificate);
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Older Root", Label = "older-root", CertificateId = certificate.CertificateId, IsEnabled = true };
        db.CertificateAuthorities.Add(ca);
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Ssh", Label = "ssh", IsSshCa = true, IsEnabled = true });
        db.SaveChanges();

        Assert.Equal(1, await CaCertificateHistory.EnsureInitialRowsAsync(db));
        Assert.Equal(0, await CaCertificateHistory.EnsureInitialRowsAsync(db));

        var row = db.CaCertificates.Single();
        Assert.Equal((ca.Id, certificate.CertificateId, CaCertificateEntity.OriginInitial, certificate.CreatedAt), (row.CertificateAuthorityId, row.CertificateId, row.Origin, row.ActivatedAt));
        Assert.Equal(CaCertificateHistory.KeyIdOf(certificate), row.KeyId);
    }

    /// <summary>What a process does at its start: the registry learns the current certificate of a renewed CA, ahead of the earlier one.</summary>
    [Fact]
    public async Task At_start_the_registry_is_told_the_current_certificate_of_every_renewed_ca()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var root = await world.W.CreateRootAsync("Restarted Root", null, null);
        await world.W.CreateRootAsync("Never Renewed", null, null);
        var before = world.Certificate(root.CertificateId);
        var after = (await world.RenewAsync(root)).Certificate;

        // A registry as the keystore files give it after a restart: the certificate the key was committed with.
        var restarted = new TestKeystore((before, new SoftwarePrivateKeyHandle(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Private)));
        using var db = world.W.World.OpenDb();

        Assert.Equal(1, await CaCertificateHistory.RegisterRenewedAsync(db, restarted));

        Assert.Equal(new[] { after.SerialNumber, before.SerialNumber }, restarted.GetSigners().Select(s => s.PublicCertificate.SerialNumber).ToArray());
        Assert.Contains(restarted.GetTrustedAuthorities(), c => c.SerialNumber.Equals(after.SerialNumber));
        Assert.Contains(restarted.GetTrustedAuthorities(), c => c.SerialNumber.Equals(before.SerialNumber));
    }
}
