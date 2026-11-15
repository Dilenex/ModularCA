using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Continuity;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services.Continuity;

/// <summary>
/// The published-CRL check of a start (rollback-continuity.md, section 3): a CRL this instance
/// published elsewhere, read back with a higher number than the database knows, proves the
/// database went back, whatever the incarnation says. Pins the comparison, that only a CRL the
/// CA signed counts, and that a finding is treated as an incarnation change.
/// </summary>
public sealed class PublishedCrlCheckTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public RecordingAuditService Audit { get; } = new();
        public TestCaMaterial Ca { get; } = TestCaMaterial.CreateCa("CN=Published CA, O=ModularCA");
        public Guid CaCertificateId { get; } = Guid.NewGuid();
        public CrlConfigurationEntity Full { get; }
        public CrlConfigurationEntity Delta { get; }

        public World(long fullCounter = 40, long deltaCounter = 41, long storedCrlNumber = 41)
        {
            Db.Certificates.Add(new CertificateEntity
            {
                CertificateId = CaCertificateId,
                SerialNumber = CertificateUtil.FormatSerialNumber(Ca.Certificate.SerialNumber),
                SubjectDN = Ca.SubjectDn, Issuer = Ca.SubjectDn, IsCA = true,
                Pem = CertificateUtil.ConvertDerToPem(Ca.Certificate.GetEncoded(), "CERTIFICATE"),
                RawCertificate = Ca.Certificate.GetEncoded(),
                NotBefore = Ca.Certificate.NotBefore, NotAfter = Ca.Certificate.NotAfter,
            });
            Full = new CrlConfigurationEntity { Name = "full", CaCertificateId = CaCertificateId, IssuerDN = Ca.SubjectDn, UpdateInterval = "0 * * * *", LastCrlNumber = fullCounter };
            Delta = new CrlConfigurationEntity { Name = "delta", IsDelta = true, CaCertificateId = CaCertificateId, IssuerDN = Ca.SubjectDn, UpdateInterval = "0 * * * *", LastCrlNumber = deltaCounter };
            Db.CrlConfigurations.AddRange(Full, Delta);
            Db.Crls.Add(new CrlEntity { CrlNumber = storedCrlNumber, IsDelta = true, IssuerName = Ca.SubjectDn, TaskId = Delta.TaskId, RawData = [1], PemData = "x" });
            Db.SaveChanges();
        }

        public PublishedCrl Published(long number, TestCaMaterial? signedBy = null, string? issuer = null)
            => new(CaCertificateId, "LDAP publisher 'test'", Crl(signedBy ?? Ca, number, issuer));

        public Task<IReadOnlyList<PublishedCrlAhead>> Check(params PublishedCrl[] published)
            => InstanceContinuity.CheckPublishedCrlsAsync(Db, null, Audit, published, Now, NullLogger.Instance);

        public long[] Counters => [.. Db.CrlConfigurations.AsNoTracking().OrderBy(c => c.Name).Select(c => c.LastCrlNumber)];
    }

    /// <summary>A CRL with the given number, signed by <paramref name="ca"/>, under its name or <paramref name="issuer"/>.</summary>
    private static byte[] Crl(TestCaMaterial ca, long number, string? issuer = null)
    {
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(issuer == null ? ca.Certificate.SubjectDN : new X509Name(issuer));
        generator.SetThisUpdate(DateTime.UtcNow.AddHours(-1));
        generator.SetNextUpdate(DateTime.UtcNow.AddHours(5));
        generator.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.ValueOf(number)));
        return generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", ca.KeyPair.Private, new SecureRandom())).GetEncoded();
    }

    [Fact]
    public async Task A_published_crl_at_or_below_what_the_database_knows_is_the_same_timeline()
    {
        var w = new World();

        Assert.Empty(await w.Check(w.Published(41)));
        Assert.Empty(await w.Check(w.Published(7)));
        Assert.Empty(await w.Check());

        Assert.Equal([41, 40], w.Counters);
        Assert.Empty(w.Db.InstanceContinuityEvents);
        Assert.Empty(w.Audit.Entries);
    }

    [Fact]
    public async Task The_database_knows_the_highest_of_its_counters_and_its_stored_crls()
    {
        // The counters stand at 40 and 41, but a stored CRL row carries 57.
        var w = new World(storedCrlNumber: 57);

        Assert.Empty(await w.Check(w.Published(57)));
        var ahead = Assert.Single(await w.Check(w.Published(58)));
        Assert.Equal(57, ahead.DatabaseNumber);
        Assert.Equal(58, ahead.PublishedNumber);
    }

    [Fact]
    public async Task A_published_crl_ahead_of_the_database_is_treated_as_an_incarnation_change()
    {
        var w = new World();

        var ahead = Assert.Single(await w.Check(w.Published(39), w.Published(64)));

        Assert.Equal(w.CaCertificateId, ahead.CaCertificateId);
        Assert.Equal(64, ahead.PublishedNumber);
        Assert.Equal(41, ahead.DatabaseNumber);
        Assert.Equal(w.Ca.SubjectDn, ahead.IssuerDn);

        // The floor, as the product's restore applies it: both counters, well past the published number.
        var floor = Now.ToUnixTimeSeconds();
        Assert.Equal([floor, floor], w.Counters);

        var recorded = Assert.Single(w.Db.InstanceContinuityEvents.AsNoTracking());
        Assert.Equal(ContinuityEventKind.PublishedCrlAhead, recorded.Kind);
        Assert.Equal(floor, recorded.CrlNumberFloor);
        Assert.Equal(2, recorded.CrlCountersRaised);
        Assert.Null(recorded.AcknowledgedAt);
        Assert.Contains("\"publishedNumber\":64", recorded.DetailsJson);
        Assert.Contains("published carries a higher number", InstanceContinuity.MessageFor(recorded));

        var audit = Assert.Single(w.Audit.Entries);
        Assert.Equal(AuditActionType.InstanceIncarnationChanged, audit.Action);
        var details = JsonSerializer.Serialize(audit.Details);
        Assert.Contains("published-crl", details);
        Assert.Contains("\"PublishedNumber\":64", details);
        Assert.Contains("nothing was replayed", details);

        // Reported once: the same directory read at the next start is no longer ahead.
        Assert.Empty(await w.Check(w.Published(64)));
        Assert.Single(w.Db.InstanceContinuityEvents);
    }

    [Fact]
    public async Task The_floor_goes_past_a_published_number_that_is_itself_above_the_time_derived_floor()
    {
        var w = new World();
        var published = Now.ToUnixTimeSeconds() + 5_000;   // a CA restored before, then busy

        await w.Check(w.Published(published));

        Assert.Equal([published, published], w.Counters);  // the next CRL takes published + 1
    }

    [Fact]
    public async Task A_crl_the_ca_did_not_sign_proves_nothing()
    {
        var w = new World();
        var impostor = TestCaMaterial.CreateCa("CN=Published CA, O=ModularCA");   // same name, another key

        Assert.Empty(await w.Check(
            w.Published(9_000, signedBy: impostor),
            w.Published(9_000, issuer: "CN=Somebody Else"),
            new PublishedCrl(w.CaCertificateId, "junk", [0x30, 0x03, 0x01, 0x01, 0xFF]),
            new PublishedCrl(Guid.NewGuid(), "unknown CA", Crl(w.Ca, 9_000))));

        Assert.Equal([41, 40], w.Counters);
        Assert.Empty(w.Db.InstanceContinuityEvents);
        Assert.Empty(w.Audit.Entries);
    }

    [Fact]
    public async Task Finding_alone_changes_nothing()
    {
        var w = new World();

        var ahead = await InstanceContinuity.FindPublishedAheadAsync(w.Db, [w.Published(64)], NullLogger.Instance);

        Assert.Single(ahead);
        Assert.Equal([41, 40], w.Counters);
        Assert.Empty(w.Db.InstanceContinuityEvents);
    }
}
