using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The notices a CA's cryptoperiod raises (<see cref="CaCryptoperiod"/>), each at its boundary;
/// the facts <see cref="CaLifecycleService"/> reads for them; the three settings; and the health
/// entry, which never makes the node not ready.
/// </summary>
public sealed class CaCryptoperiodTests
{
    private static readonly DateTime Now = new(2027, 6, 1, 12, 0, 0, DateTimeKind.Utc);

    private static CaCryptoperiodFacts Facts(
        bool root = true, DateTime? notAfter = null, DateTime? since = null, DateTime? warningAt = null, DateTime? alertAt = null,
        TimeSpan? longest = null, DateTime? parentEnd = null)
    {
        var end = notAfter ?? Now.AddYears(10);
        return new CaCryptoperiodFacts(root, since ?? Now.AddYears(-1), 1, Now.AddYears(-1), end,
            warningAt ?? end.AddDays(-30), alertAt ?? end.AddDays(-7), null, longest, longest == null ? null : "TLS Server",
            parentEnd == null ? null : "Parent Root", parentEnd);
    }

    private static string[] Reasons(CaCryptoperiodFacts facts, CaCryptoperiodSettings? settings = null)
        => CaCryptoperiod.Advisories(facts, settings ?? CaCryptoperiodSettings.Defaults, Now).Select(a => a.Reason).ToArray();

    // ── The certificate nearing its end ─────────────────────────────────────────────────────

    [Fact]
    public void A_ca_far_from_its_end_raises_nothing()
        => Assert.Empty(Reasons(Facts()));

    [Theory]
    [InlineData(true, 730, true)]     // a root, exactly at its two-year window
    [InlineData(true, 731, false)]
    [InlineData(false, 365, true)]    // an intermediate, exactly at its one-year window
    [InlineData(false, 366, false)]
    [InlineData(false, 730, false)]   // the root's window is not the intermediate's
    public void The_expiry_notice_starts_at_the_window_of_the_kind_of_ca(bool root, int daysLeft, bool expected)
    {
        var advisories = CaCryptoperiod.Advisories(Facts(root, Now.AddDays(daysLeft)), CaCryptoperiodSettings.Defaults, Now);

        Assert.Equal(expected, advisories.Any(a => a.Reason == CaCryptoperiod.CertificateExpiring));
        if (expected)
            Assert.Equal(CaKeyAdvisory.Notice, advisories.Single(a => a.Reason == CaCryptoperiod.CertificateExpiring).Severity);
    }

    [Fact]
    public void A_window_of_zero_gives_no_early_notice_and_the_certificates_own_warning_still_shows()
    {
        var off = new CaCryptoperiodSettings(0, 0, 0);

        Assert.Empty(Reasons(Facts(notAfter: Now.AddDays(100)), off));
        var warned = CaCryptoperiod.Advisories(Facts(notAfter: Now.AddDays(30)), off, Now).Single();
        Assert.Equal(CaCryptoperiod.CertificateExpiring, warned.Reason);
        Assert.Equal(CaKeyAdvisory.Warning, warned.Severity);
    }

    /// <summary>The warning and the alert are the instants stored on the certificate, the ones the certificate list already uses.</summary>
    [Theory]
    [InlineData(31, CaKeyAdvisory.Notice)]
    [InlineData(30, CaKeyAdvisory.Warning)]
    [InlineData(8, CaKeyAdvisory.Warning)]
    [InlineData(7, CaKeyAdvisory.Critical)]
    [InlineData(1, CaKeyAdvisory.Critical)]
    public void The_notice_becomes_a_warning_and_then_critical_at_the_certificates_own_instants(int daysLeft, string severity)
    {
        var expiring = CaCryptoperiod.Advisories(Facts(notAfter: Now.AddDays(daysLeft)), CaCryptoperiodSettings.Defaults, Now)
            .Single(a => a.Reason == CaCryptoperiod.CertificateExpiring);

        Assert.Equal(severity, expiring.Severity);
        Assert.Contains("Renew the CA certificate", expiring.Message);
    }

    [Fact]
    public void A_profile_that_moved_the_warning_instant_moves_the_level()
    {
        var end = Now.AddDays(200);

        var expiring = CaCryptoperiod.Advisories(Facts(notAfter: end, warningAt: end.AddDays(-250)), CaCryptoperiodSettings.Defaults, Now).Single();

        Assert.Equal(CaKeyAdvisory.Warning, expiring.Severity);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void An_expired_certificate_is_critical_and_is_not_also_expiring(int daysLeft)
    {
        var advisory = CaCryptoperiod.Advisories(Facts(notAfter: Now.AddDays(daysLeft)), CaCryptoperiodSettings.Defaults, Now).Single();

        Assert.Equal(CaCryptoperiod.CertificateExpired, advisory.Reason);
        Assert.Equal(CaKeyAdvisory.Critical, advisory.Severity);
    }

    // ── Profiles asking for more time than the certificate has left ─────────────────────────

    /// <summary>
    /// A profile has no default validity, so every request gets its maximum and is shortened from
    /// the day the CA has less than that left. The notice waits until a certificate issued now
    /// would lose a tenth of the profile's maximum.
    /// </summary>
    [Theory]
    [InlineData(1000, 1000, false)]   // exactly what is left: nothing is shortened
    [InlineData(1000, 1001, false)]   // shortened by a day in a thousand: not worth saying
    [InlineData(901, 1000, false)]    // 9.9% lost
    [InlineData(900, 1000, true)]     // exactly a tenth lost
    [InlineData(899, 1000, true)]
    [InlineData(358, 397, false)]     // a 397-day profile: 39 days lost is under a tenth (39.7)
    [InlineData(357, 397, true)]      // 40 days lost
    [InlineData(3000, 397, false)]
    [InlineData(3649, 3650, false)]   // a 10-year profile on a 10-year CA made yesterday
    [InlineData(3285, 3650, true)]    // the same CA a year later
    public void A_profile_says_issuance_is_shortened_once_a_tenth_of_its_maximum_is_lost(int daysLeft, int profileDays, bool expected)
    {
        var advisories = CaCryptoperiod.Advisories(
            Facts(notAfter: Now.AddDays(daysLeft), longest: TimeSpan.FromDays(profileDays)), new CaCryptoperiodSettings(0, 0, 0), Now);

        Assert.Equal(expected, CaCryptoperiod.ShortensMaterially(TimeSpan.FromDays(profileDays), TimeSpan.FromDays(daysLeft)));
        Assert.Equal(expected, advisories.Any(a => a.Reason == CaCryptoperiod.ProfilesOutliveCertificate));
        if (expected)
        {
            var advisory = advisories.Single();
            Assert.Contains("issued shorter", advisory.Message);
            Assert.Contains("TLS Server", advisory.Message);
            Assert.Equal(CaKeyAdvisory.Notice, advisory.Severity);
        }
    }

    [Fact]
    public void An_infrastructure_profile_shown_for_want_of_another_raises_no_notice()
    {
        var facts = Facts(notAfter: Now.AddDays(100), longest: TimeSpan.FromDays(3650)) with { LongestProfileIsInfrastructure = true };

        Assert.DoesNotContain(CaCryptoperiod.ProfilesOutliveCertificate, Reasons(facts, new CaCryptoperiodSettings(0, 0, 0)));
    }

    // ── Every message is short ──────────────────────────────────────────────────────────────

    private static int Words(string text) => text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;

    /// <summary>Every notice a CA can carry, from inputs with long names, long spans and every branch of the wording.</summary>
    public static TheoryData<string, string> EveryAdvisory()
    {
        const string longName = "Engineering Department Device Identity Issuing Authority";
        var settings = new CaCryptoperiodSettings(730, 365, 1095);
        var found = new List<CaKeyAdvisory>();
        CaCryptoperiodFacts Of(bool root, DateTime end, TimeSpan? longest = null, DateTime? parentEnd = null, string? profile = longName, string? parent = longName)
            => new(root, Now.AddDays(-4000), 3, Now.AddDays(-4000), end, end.AddDays(-30), end.AddDays(-7), null, longest, longest == null ? null : profile,
                parentEnd == null ? null : parent, parentEnd);

        foreach (var root in new[] { true, false })
        {
            found.AddRange(CaCryptoperiod.Advisories(Of(root, Now.AddDays(-400)), settings, Now));                                    // expired, key past its period
            found.AddRange(CaCryptoperiod.Advisories(Of(root, Now.AddDays(299), TimeSpan.FromDays(3650), Now.AddDays(200)), settings, Now)); // expiring, profiles, outlives parent
            found.AddRange(CaCryptoperiod.Advisories(Of(root, Now.AddDays(5), TimeSpan.FromDays(825), Now.AddDays(-1), profile: null, parent: null), settings, Now));
            // A parent the reader may not see: neither named nor dated, in both wordings.
            found.AddRange(CaCryptoperiod.Advisories(Of(root, Now.AddDays(4000)) with { WithheldParent = CaWithheldParent.EndsFirst }, settings, Now));
            found.AddRange(CaCryptoperiod.Advisories(Of(root, Now.AddDays(4000)) with { WithheldParent = CaWithheldParent.Expired }, settings, Now));
            found.AddRange(CaKeyPolicy.ValidityAdvisories(root, Now, Now.AddYears(50), 2048));
        }
        found.AddRange(CaKeyPolicy.AdvisoriesForRsa(2048));

        var data = new TheoryData<string, string>();
        foreach (var advisory in found.DistinctBy(a => a.Message))
            data.Add(advisory.Reason, advisory.Message);
        foreach (var algorithm in new[] { "ECDSA", "ML-DSA-87", "Ed25519" })
            foreach (var advisory in ModularCA.Shared.Enrollment.ProtocolCompatibility.Advisories("SCEP", algorithm))
                data.Add(advisory.Reason, advisory.Message);
        return data;
    }

    [Theory]
    [MemberData(nameof(EveryAdvisory))]
    public void No_notice_runs_past_forty_words(string reason, string message)
    {
        Assert.True(Words(message) <= 40, $"{reason} is {Words(message)} words: {message}");
        Assert.True(Words(message) >= 12, $"{reason} is {Words(message)} words, too few to say what is so and what to do: {message}");
    }

    [Fact]
    public void The_word_count_covers_every_reason_a_ca_can_carry()
    {
        var reasons = EveryAdvisory().Select(row => (string)row[0]).ToHashSet();

        Assert.Superset(new HashSet<string>
        {
            CaCryptoperiod.CertificateExpiring, CaCryptoperiod.CertificateExpired, CaCryptoperiod.ProfilesOutliveCertificate,
            CaCryptoperiod.KeyUsagePeriodExceeded, CaCryptoperiod.OutlivesParent, CaKeyPolicy.ValidityBeyondCommonPractice,
            CaKeyPolicy.RsaBelow3072Past2030, CaKeyPolicy.RsaKeyBelow3072, ModularCA.Shared.Enrollment.ProtocolCompatibility.ScepRequiresRsaKey,
        }, reasons);
    }

    // ── A key past the usage period ─────────────────────────────────────────────────────────

    [Fact]
    public void The_key_usage_notice_is_off_until_a_period_is_set()
        => Assert.DoesNotContain(CaCryptoperiod.KeyUsagePeriodExceeded, Reasons(Facts(since: Now.AddYears(-40))));

    [Theory]
    [InlineData(1095, 1095, false)]   // exactly the period: not yet past it
    [InlineData(1095, 1096, true)]
    public void A_key_past_the_configured_period_raises_the_notice(int periodDays, int ageDays, bool expected)
    {
        var advisories = CaCryptoperiod.Advisories(Facts(since: Now.AddDays(-ageDays)), new CaCryptoperiodSettings(0, 0, periodDays), Now);

        Assert.Equal(expected, advisories.Any(a => a.Reason == CaCryptoperiod.KeyUsagePeriodExceeded));
        if (expected)
        {
            Assert.Contains("SP 800-57", advisories.Single().Message);
            Assert.DoesNotContain("complian", advisories.Single().Message, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ── A certificate that outlives its parent's ────────────────────────────────────────────

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]    // the same instant is not outliving
    [InlineData(1, false)]
    public void A_ca_whose_parent_expires_first_raises_the_notice(int parentDaysAfterOwnEnd, bool expected)
    {
        var end = Now.AddYears(5);

        var reasons = Reasons(Facts(root: false, notAfter: end, parentEnd: end.AddDays(parentDaysAfterOwnEnd)));

        Assert.Equal(expected, reasons.Contains(CaCryptoperiod.OutlivesParent));
    }

    /// <summary>A parent outside the reader's space fence: the notice says so without a name or a date of the parent's certificate.</summary>
    [Theory]
    [InlineData(CaWithheldParent.EndsFirst, CaKeyAdvisory.Notice, "its parent's certificate expires earlier.")]
    [InlineData(CaWithheldParent.Expired, CaKeyAdvisory.Critical, "its parent's certificate has expired.")]
    public void A_parent_the_reader_may_not_see_is_neither_named_nor_dated(CaWithheldParent standing, string severity, string says)
    {
        var end = Now.AddYears(5);
        var facts = Facts(root: false, notAfter: end) with { WithheldParent = standing };

        var advisory = CaCryptoperiod.Advisories(facts, CaCryptoperiodSettings.Defaults, Now).Single(a => a.Reason == CaCryptoperiod.OutlivesParent);

        Assert.Equal(
            $"This certificate is valid until {end:yyyy-MM-dd}, but {says} Ask an administrator of the parent CA to renew it.",
            advisory.Message);
        Assert.Equal(22, Words(advisory.Message));
        Assert.Equal(severity, advisory.Severity);
        Assert.Equal("Outlives its parent's certificate", advisory.Title);
    }

    [Fact]
    public void A_withheld_parent_whose_certificate_does_not_end_first_raises_nothing()
        => Assert.DoesNotContain(CaCryptoperiod.OutlivesParent,
            Reasons(Facts(root: false, notAfter: Now.AddYears(5)) with { WithheldParent = CaWithheldParent.NoEarlierEnd }));

    [Fact]
    public void The_most_pressing_notice_comes_first()
    {
        var advisories = CaCryptoperiod.Advisories(
            Facts(notAfter: Now.AddDays(5), since: Now.AddYears(-9), longest: TimeSpan.FromDays(90)), new CaCryptoperiodSettings(730, 365, 365), Now);

        Assert.Equal(new[] { CaCryptoperiod.CertificateExpiring, CaCryptoperiod.ProfilesOutliveCertificate, CaCryptoperiod.KeyUsagePeriodExceeded },
            advisories.Select(a => a.Reason).ToArray());
        Assert.All(advisories, a => Assert.False(string.IsNullOrWhiteSpace(a.Title)));
    }

    // ── The settings ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_defaults_are_two_years_one_year_and_no_key_usage_notice()
    {
        var config = new SystemConfig();

        Assert.Equal(730, config.CaLifecycle.RootExpiryNoticeDays);
        Assert.Equal(365, config.CaLifecycle.IntermediateExpiryNoticeDays);
        Assert.Equal(0, config.CaLifecycle.KeyUsagePeriodDays);
        Assert.Equal(CaCryptoperiodSettings.Defaults, config.CaLifecycle.ToSettings());
    }

    [Theory]
    [InlineData("CaLifecycle_RootExpiryNoticeDays")]
    [InlineData("CaLifecycle_IntermediateExpiryNoticeDays")]
    [InlineData("CaLifecycle_KeyUsagePeriodDays")]
    public void Each_setting_is_kept_in_the_database_and_applies_live(string key)
    {
        var definition = SettingsCatalog.Find(key);

        Assert.NotNull(definition);
        Assert.Equal(SettingClass.InstanceWide, definition!.Class);
        Assert.Equal(SettingReload.Live, definition.Reload);
    }

    [Theory]
    [InlineData(0, 0, 0, true)]
    [InlineData(36500, 36500, 36500, true)]
    [InlineData(-1, 365, 0, false)]
    [InlineData(730, 36501, 0, false)]
    [InlineData(730, 365, -1, false)]
    public void A_value_outside_zero_to_a_hundred_years_is_refused(int root, int intermediate, int usage, bool accepted)
        => Assert.Equal(accepted, CaCryptoperiod.Problem(new CaCryptoperiodSettings(root, intermediate, usage)) == null);

    private sealed class CurrentUserStub : ICurrentUserService
    {
        public Guid? UserId { get; } = Guid.NewGuid();
        public UserEntity? User => new() { Id = UserId!.Value, Username = "sysadmin" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static async Task<IActionResult> PutCaLifecycleAsync(SystemConfig config, int root, int intermediate, int usage)
    {
        const string ns = "ModularCA.API.Controllers.v1.Admin.";
        var controller = (ControllerBase)Activator.CreateInstance(ApiAssembly.TypeNamed(ns + "AdminConfigController"),
            config, null, new RecordingAuditService(), new CurrentUserStub(),
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new RecordingAlertService(), null, null, null, null, null)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(ns + "CaLifecycleUpdateRequest"))!;
        body.GetType().GetProperty("RootExpiryNoticeDays")!.SetValue(body, root);
        body.GetType().GetProperty("IntermediateExpiryNoticeDays")!.SetValue(body, intermediate);
        body.GetType().GetProperty("KeyUsagePeriodDays")!.SetValue(body, usage);
        return await (Task<IActionResult>)controller.GetType().GetMethod("UpdateCaLifecycle")!.Invoke(controller, [body])!;
    }

    [Fact]
    public async Task The_endpoint_refuses_a_bad_value_and_changes_nothing()
    {
        var config = new SystemConfig();

        var result = await PutCaLifecycleAsync(config, 100, 50, 40000);

        Assert.Equal(400, Assert.IsAssignableFrom<ObjectResult>(result).StatusCode);
        Assert.Equal(CaCryptoperiodSettings.Defaults, config.CaLifecycle.ToSettings());
    }

    /// <summary>The values reach the live configuration; writing config.yaml is not exercised here (see <c>MtlsConfigUpdateTests</c>).</summary>
    [Fact]
    public async Task The_endpoint_sets_the_three_values()
    {
        var config = new SystemConfig();

        await PutCaLifecycleAsync(config, 1000, 0, 3650);

        Assert.Equal(new CaCryptoperiodSettings(1000, 0, 3650), config.CaLifecycle.ToSettings());
    }

    // ── The facts, read from the database ───────────────────────────────────────────────────

    private static CertificateEntity Row(Org.BouncyCastle.X509.X509Certificate cert, Guid? issuerRow = null, bool ca = true)
    {
        var id = Guid.NewGuid();
        var (warning, alert) = ExpiryWarningRule.Compute(cert.NotBefore, cert.NotAfter, ca, null);
        return new CertificateEntity
        {
            CertificateId = id,
            SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
            SubjectDN = cert.SubjectDN.ToString(),
            Issuer = cert.IssuerDN.ToString(),
            IsCA = ca,
            Pem = CertificateUtil.ConvertDerToPem(cert.GetEncoded(), "CERTIFICATE"),
            RawCertificate = cert.GetEncoded(),
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            ExpiryWarningAt = warning.ToUniversalTime(),
            ExpiryAlertAt = alert.ToUniversalTime(),
            IssuerCertificateId = issuerRow ?? (ca ? id : null),
        };
    }

    /// <summary>A root with an earlier certificate over the same key, a leaf, and a linked profile with a maximum.</summary>
    private static (ModularCADbContext Db, CertificateAuthorityEntity Ca, CertificateEntity Current, CertificateEntity Earlier, CertificateEntity Leaf) Seed()
    {
        var db = InMemoryDbContextFactory.Create();
        var material = TestCaMaterial.CreateCa("CN=Lifecycle Root");
        var current = Row(material.Certificate);
        var earlier = Row(material.Issue(BigInteger.ValueOf(77), material.SubjectDn, material.KeyPair.Public, isCa: true));
        earlier.NotBefore = current.NotBefore.AddYears(-6);
        earlier.NotAfter = current.NotBefore.AddYears(1);
        var otherKey = TestCaMaterial.CreateCa("CN=Leaf");
        var leaf = Row(material.Issue(BigInteger.ValueOf(78), "CN=leaf.example", otherKey.KeyPair.Public, isCa: false), earlier.CertificateId, ca: false);
        var revoked = Row(material.Issue(BigInteger.ValueOf(79), "CN=revoked.example", otherKey.KeyPair.Public, isCa: false), current.CertificateId, ca: false);
        revoked.Revoked = true;
        revoked.NotAfter = current.NotAfter;
        leaf.NotAfter = new DateTime(2031, 3, 1, 0, 0, 0, DateTimeKind.Utc);
        db.Certificates.AddRange(current, earlier, leaf, revoked);

        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Lifecycle Root", Label = "lifecycle-root", CertificateId = current.CertificateId, Certificate = current, IsEnabled = true };
        db.CertificateAuthorities.Add(ca);

        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "Lifecycle signing", IssuerId = current.CertificateId };
        var parentProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Base", ValidityPeriodMax = "P825D" };
        var inheriting = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Inheriting", InheritanceEnabled = true, InheritsFromId = parentProfile.Id };
        var shorter = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Short", ValidityPeriodMax = "P90D" };
        var caProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Sub CA", IsCaProfile = true, ValidityPeriodMax = "P20Y" };
        db.SigningProfiles.Add(signing);
        db.CertProfiles.AddRange(parentProfile, inheriting, shorter, caProfile);
        foreach (var profile in new[] { inheriting, shorter, caProfile })
            db.AllowedCertProfileSigningProfiles.Add(new AllowedCertProfileSigningProfileEntity { CertProfileId = profile.Id, SigningProfileId = signing.Id });
        db.SaveChanges();
        return (db, ca, current, earlier, leaf);
    }

    [Fact]
    public async Task The_facts_come_from_the_cas_certificates_what_it_issued_and_its_profiles()
    {
        var (db, ca, current, earlier, leaf) = Seed();
        using var _ = db;
        var now = current.NotBefore.AddYears(1);

        var report = (await new CaLifecycleService(db, new SystemConfig()).DescribeAsync([ca], now))[ca.Id];

        Assert.True(report.Facts.IsRoot);
        Assert.Equal(earlier.NotBefore, report.Facts.KeyInUseSince);          // the earliest certificate over the same key
        Assert.Equal(2, report.Facts.CertificateCount);
        Assert.Equal(current.NotAfter, report.Facts.CertificateNotAfter);
        Assert.Equal(leaf.NotAfter, report.Facts.LatestIssuedNotAfter);       // issued under the earlier certificate; the revoked one is left out
        Assert.Equal(TimeSpan.FromDays(825), report.Facts.LongestProfileValidity);   // inherited; the CA profile's 20 years is not a leaf's
        Assert.Equal("Inheriting", report.Facts.LongestProfileName);
        Assert.Null(report.Facts.ParentCertificateNotAfter);
    }

    /// <summary>
    /// An intermediate made today for ten years under a longer-lived root, with the profiles a new
    /// install gives it: the three infrastructure profiles (ten years each, found by their seeded
    /// names because the CA names none) and, unless left out, a 397-day TLS profile.
    /// </summary>
    private static (ModularCADbContext Db, CertificateAuthorityEntity Ca, SigningProfileEntity Signing, DateTime Now) FreshIntermediate(bool withEndEntityProfile = true)
    {
        var db = InMemoryDbContextFactory.Create();
        var now = DateTime.UtcNow;
        var rootMaterial = TestCaMaterial.CreateCa("CN=Fresh Root");
        var rootRow = Row(rootMaterial.Certificate);
        rootRow.NotBefore = now.AddYears(-1);
        rootRow.NotAfter = now.AddYears(19);
        var key = TestCaMaterial.CreateCa("CN=Fresh Intermediate");
        var row = Row(rootMaterial.Issue(BigInteger.ValueOf(501), "CN=Fresh Intermediate", key.KeyPair.Public, isCa: true), rootRow.CertificateId);
        row.NotBefore = now.AddMinutes(-5);
        row.NotAfter = now.AddYears(10);
        (row.ExpiryWarningAt, row.ExpiryAlertAt) = (row.NotAfter.AddDays(-30), row.NotAfter.AddDays(-7));
        db.Certificates.AddRange(rootRow, row);

        var root = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Fresh Root", Label = "fresh-root", CertificateId = rootRow.CertificateId, Certificate = rootRow, IsEnabled = true };
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Fresh Intermediate", Label = "fresh-intermediate", ParentCaId = root.Id, CertificateId = row.CertificateId, Certificate = row, IsEnabled = true };
        db.CertificateAuthorities.AddRange(root, ca);

        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "Fresh signing", IssuerId = row.CertificateId };
        db.SigningProfiles.Add(signing);
        var profiles = InfrastructureCertProfiles.All
            .Select(role => new CertProfileEntity { Id = Guid.NewGuid(), Name = role.DefaultProfileName, ValidityPeriodMin = "P1D", ValidityPeriodMax = "P10Y" })
            .ToList();
        if (withEndEntityProfile)
            profiles.Add(new CertProfileEntity { Id = Guid.NewGuid(), Name = "TLS Server", ValidityPeriodMin = "P30D", ValidityPeriodMax = "P397D" });
        db.CertProfiles.AddRange(profiles);
        foreach (var profile in profiles)
            db.AllowedCertProfileSigningProfiles.Add(new AllowedCertProfileSigningProfileEntity { CertProfileId = profile.Id, SigningProfileId = signing.Id });
        db.SaveChanges();
        return (db, ca, signing, now);
    }

    [Fact]
    public async Task A_fresh_ten_year_intermediate_with_default_profiles_carries_no_notice()
    {
        var (db, ca, _, now) = FreshIntermediate();
        using var __ = db;

        var report = (await new CaLifecycleService(db, new SystemConfig()).DescribeAsync([ca], now))[ca.Id];

        Assert.Empty(report.Advisories);
        Assert.Equal(TimeSpan.FromDays(397), report.Facts.LongestProfileValidity);   // the ten-year infrastructure profiles are left out
        Assert.Equal("TLS Server", report.Facts.LongestProfileName);
        Assert.False(report.Facts.LongestProfileIsInfrastructure);
    }

    [Fact]
    public async Task With_only_infrastructure_profiles_the_fact_shows_one_marked_as_such_and_there_is_still_no_notice()
    {
        var (db, ca, _, now) = FreshIntermediate(withEndEntityProfile: false);
        using var __ = db;
        var service = new CaLifecycleService(db, new SystemConfig());

        var fresh = (await service.DescribeAsync([ca], now))[ca.Id];
        // Five years on, the ten-year infrastructure profiles ask for twice what is left: still no notice.
        var later = (await service.DescribeAsync([ca], now.AddYears(5)))[ca.Id];

        Assert.Empty(fresh.Advisories);
        Assert.True(fresh.Facts.LongestProfileIsInfrastructure);
        Assert.NotNull(fresh.Facts.LongestProfileValidity);
        Assert.DoesNotContain(later.Advisories, a => a.Reason == CaCryptoperiod.ProfilesOutliveCertificate);
    }

    [Fact]
    public async Task A_profile_the_ca_names_for_a_role_is_infrastructure_whatever_it_is_called()
    {
        var (db, ca, signing, now) = FreshIntermediate();
        using var __ = db;
        var own = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Responder, twenty years", ValidityPeriodMin = "P1D", ValidityPeriodMax = "P20Y" };
        db.CertProfiles.Add(own);
        db.AllowedCertProfileSigningProfiles.Add(new AllowedCertProfileSigningProfileEntity { CertProfileId = own.Id, SigningProfileId = signing.Id });
        InfrastructureCertProfiles.Choose(ca, InfrastructureCertProfiles.OcspResponder, own.Id);
        db.SaveChanges();

        var report = (await new CaLifecycleService(db, new SystemConfig()).DescribeAsync([ca], now))[ca.Id];

        Assert.Empty(report.Advisories);
        Assert.Equal("TLS Server", report.Facts.LongestProfileName);
    }

    [Fact]
    public async Task An_end_entity_profile_as_long_as_the_ca_raises_the_notice_only_once_a_tenth_is_lost()
    {
        var (db, ca, signing, now) = FreshIntermediate();
        using var __ = db;
        var device = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Device, ten years", ValidityPeriodMin = "P1D", ValidityPeriodMax = "P10Y" };
        db.CertProfiles.Add(device);
        db.AllowedCertProfileSigningProfiles.Add(new AllowedCertProfileSigningProfileEntity { CertProfileId = device.Id, SigningProfileId = signing.Id });
        db.SaveChanges();
        var service = new CaLifecycleService(db, new SystemConfig());

        var fresh = (await service.DescribeAsync([ca], now))[ca.Id];
        var afterElevenMonths = (await service.DescribeAsync([ca], now.AddDays(335)))[ca.Id];
        var afterThirteenMonths = (await service.DescribeAsync([ca], now.AddDays(395)))[ca.Id];

        Assert.Empty(fresh.Advisories);
        Assert.Equal("Device, ten years", fresh.Facts.LongestProfileName);
        Assert.Empty(afterElevenMonths.Advisories);
        Assert.Equal(CaCryptoperiod.ProfilesOutliveCertificate, Assert.Single(afterThirteenMonths.Advisories).Reason);
    }

    [Fact]
    public async Task The_notices_follow_the_settings_as_they_are_when_asked()
    {
        var (db, ca, current, earlier, _) = Seed();
        using var __ = db;
        var config = new SystemConfig();
        var service = new CaLifecycleService(db, config);
        var now = current.NotAfter.AddDays(-600);

        var defaults = (await service.DescribeAsync([ca], now))[ca.Id].Advisories.Select(a => a.Reason).ToArray();
        config.CaLifecycle.RootExpiryNoticeDays = 0;
        config.CaLifecycle.KeyUsagePeriodDays = 365;
        var changed = (await service.DescribeAsync([ca], now))[ca.Id].Advisories.Select(a => a.Reason).ToArray();

        Assert.Equal(new[] { CaCryptoperiod.CertificateExpiring, CaCryptoperiod.ProfilesOutliveCertificate }, defaults);
        Assert.Equal(new[] { CaCryptoperiod.ProfilesOutliveCertificate, CaCryptoperiod.KeyUsagePeriodExceeded }, changed);
    }

    [Fact]
    public async Task A_child_reads_its_parents_end_when_the_parent_was_not_asked_about_and_the_reader_may_see_it()
    {
        var db = InMemoryDbContextFactory.Create();
        using var _ = db;
        var parentMaterial = TestCaMaterial.CreateCa("CN=Short Parent");
        var childMaterial = TestCaMaterial.CreateCa("CN=Long Child");
        var parentRow = Row(parentMaterial.Certificate);
        parentRow.NotAfter = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var childRow = Row(parentMaterial.Issue(BigInteger.ValueOf(5), childMaterial.SubjectDn, childMaterial.KeyPair.Public, isCa: true), parentRow.CertificateId);
        childRow.NotAfter = new DateTime(2035, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var parent = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Short Parent", Label = "short-parent", CertificateId = parentRow.CertificateId, IsEnabled = true };
        var child = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Long Child", Label = "long-child", CertificateId = childRow.CertificateId, Certificate = childRow, ParentCaId = parent.Id, IsEnabled = true };
        db.Certificates.AddRange(parentRow, childRow);
        db.CertificateAuthorities.AddRange(parent, child);
        db.SaveChanges();

        var service = new CaLifecycleService(db, new SystemConfig());
        var now = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var report = (await service.DescribeAsync([child], now, default, readerMaySeeSpace: _ => true))[child.Id];

        Assert.False(report.Facts.IsRoot);
        Assert.Equal(parentRow.NotAfter, report.Facts.ParentCertificateNotAfter);
        var outlives = report.Advisories.Single(a => a.Reason == CaCryptoperiod.OutlivesParent);
        Assert.Contains("Short Parent", outlives.Message);

        // Said nothing of the reader, the service names no parent it was not asked about
        // (ParentCaFenceTests covers the fence through the hierarchy feed).
        var withheld = (await service.DescribeAsync([child], now))[child.Id];
        Assert.Null(withheld.Facts.ParentName);
        Assert.Null(withheld.Facts.ParentCertificateNotAfter);
        Assert.DoesNotContain("Short Parent", withheld.Advisories.Single(a => a.Reason == CaCryptoperiod.OutlivesParent).Message);
    }

    [Fact]
    public async Task The_health_entry_names_a_parent_for_its_system_scope_reader()
    {
        // /health/ready is for a system-scope auditor and lists every CA of the instance, so the
        // "outlives its parent" notice names the parent there even when the parent is not listed
        // (a disabled one here).
        var db = InMemoryDbContextFactory.Create();
        using var _ = db;
        var parentMaterial = TestCaMaterial.CreateCa("CN=Short Parent");
        var childMaterial = TestCaMaterial.CreateCa("CN=Long Child");
        var parentRow = Row(parentMaterial.Certificate);
        parentRow.NotAfter = DateTime.UtcNow.AddYears(3);
        var childRow = Row(parentMaterial.Issue(BigInteger.ValueOf(5), childMaterial.SubjectDn, childMaterial.KeyPair.Public, isCa: true), parentRow.CertificateId);
        childRow.NotAfter = DateTime.UtcNow.AddYears(8);
        (childRow.ExpiryWarningAt, childRow.ExpiryAlertAt) = (childRow.NotAfter.AddDays(-30), childRow.NotAfter.AddDays(-7));
        var parent = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Short Parent CA", Label = "short-parent", CertificateId = parentRow.CertificateId, IsEnabled = false };
        var child = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Long Child", Label = "long-child", CertificateId = childRow.CertificateId, Certificate = childRow, ParentCaId = parent.Id, IsEnabled = true, SpaceId = Guid.NewGuid() };
        db.Certificates.AddRange(parentRow, childRow);
        db.CertificateAuthorities.AddRange(parent, child);
        db.SaveChanges();

        var (_, report) = await HealthAsync(db, new SystemConfig());

        var listed = report.GetProperty("cas").EnumerateArray().Single(c => c.GetProperty("caId").GetGuid() == child.Id);
        var outlives = listed.GetProperty("keyAdvisories").EnumerateArray().Single(a => a.GetProperty("reason").GetString() == CaCryptoperiod.OutlivesParent);
        Assert.Contains("'Short Parent CA'", outlives.GetProperty("message").GetString());
    }

    // ── Health ──────────────────────────────────────────────────────────────────────────────

    private static async Task<(HealthCheckResult Result, System.Text.Json.JsonElement Report)> HealthAsync(ModularCADbContext db, SystemConfig config)
    {
        var services = new ServiceCollection();
        services.AddSingleton(db);
        services.AddSingleton(new CaLifecycleService(db, config));
        var check = (IHealthCheck)Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.CaLifecycleHealthCheck"), services.BuildServiceProvider())!;
        var result = await check.CheckHealthAsync(new HealthCheckContext());
        return (result, System.Text.Json.JsonSerializer.SerializeToElement(result.Data["caLifecycle"]));
    }

    [Fact]
    public async Task The_health_entry_lists_the_notices_and_stays_healthy_even_for_an_expired_ca()
    {
        var (db, ca, current, _, _) = Seed();
        using var __ = db;
        current.NotAfter = DateTime.UtcNow.AddDays(-1);
        current.ExpiryWarningAt = current.NotAfter.AddDays(-30);
        current.ExpiryAlertAt = current.NotAfter.AddDays(-7);
        db.SaveChanges();

        var (result, report) = await HealthAsync(db, new SystemConfig());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("attention", report.GetProperty("status").GetString());
        Assert.Equal(1, report.GetProperty("casNeedingAttention").GetInt32());
        var listed = report.GetProperty("cas")[0];
        Assert.Equal(ca.Id, listed.GetProperty("caId").GetGuid());
        Assert.Equal($"/admin/authorities/manage/{ca.Id:D}", listed.GetProperty("consolePath").GetString());
        // The test CA's key is RSA 2048, so its key notice travels in the same list.
        var reasons = listed.GetProperty("keyAdvisories").EnumerateArray().ToDictionary(a => a.GetProperty("reason").GetString()!, a => a.GetProperty("severity").GetString());
        Assert.Equal("critical", reasons[CaCryptoperiod.CertificateExpired]);
        Assert.Equal("notice", reasons[CaKeyPolicy.RsaKeyBelow3072]);
    }

    [Fact]
    public async Task The_health_entry_is_ok_with_no_notice_and_leaves_out_a_disabled_ca()
    {
        var (db, ca, current, _, _) = Seed();
        using var __ = db;
        current.NotAfter = DateTime.UtcNow.AddDays(-1);
        db.CertificateAuthorities.Single(c => c.Id == ca.Id).IsEnabled = false;
        db.SaveChanges();

        var (result, report) = await HealthAsync(db, new SystemConfig());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("ok", report.GetProperty("status").GetString());
        Assert.Equal(0, report.GetProperty("cas").GetArrayLength());
    }

    [Fact]
    public async Task The_health_entry_answers_healthy_when_it_cannot_read()
    {
        var check = (IHealthCheck)Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.CaLifecycleHealthCheck"), new ServiceCollection().BuildServiceProvider())!;

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("unknown", System.Text.Json.JsonSerializer.SerializeToElement(result.Data["caLifecycle"]).GetProperty("status").GetString());
    }
}
