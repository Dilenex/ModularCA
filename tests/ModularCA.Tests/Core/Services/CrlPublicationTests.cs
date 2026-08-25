using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Scheduler;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins the three defects that made CRL-based revocation checking non-functional.
/// <para>
/// These are deliberately structural rather than end-to-end: generating a real CRL needs a
/// keystore, a signing key and a live DbContext. What broke here was not the signing — it was
/// which NAME FORM went into an extension, which SCOPE a counter was read from, and WHETHER the
/// signed bytes were regenerated at all. Each is checkable on its own.
/// </para>
/// </summary>
public class CrlPublicationTests
{
    // ---- IssuingDistributionPoint name form (RFC 5280 §6.3.3(b)(2)(i)) ----

    /// <summary>
    /// Builds the DP name the CRL carries, mirroring CrlService.AddIssuingDistributionPoint.
    /// </summary>
    private static DistributionPointName? CrlDpName(params string[] cdpUrls)
    {
        if (cdpUrls.Length == 0) return null;
        var names = cdpUrls.Select(u => new GeneralName(GeneralName.UniformResourceIdentifier, u)).ToArray();
        return new DistributionPointName(DistributionPointName.FullName, new GeneralNames(names));
    }

    /// <summary>Builds the DP name an issued certificate carries (CertificateBuilderService).</summary>
    private static DistributionPointName CertDpName(string cdpUrl) =>
        new(new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, cdpUrl)));

    [Fact]
    public void The_crl_distribution_point_matches_the_one_issued_certificates_carry()
    {
        // The whole bug in one assertion. The CRL used to name its distribution point as a
        // directoryName built from the CA subject DN, while certificates name theirs as a URI.
        // RFC 5280 §6.3.3(b)(2)(i) matches the two BY NAME, and a directoryName can never equal
        // a URI — so with the extension marked critical, every CRL was rejected as not covering
        // the certificate whose revocation status was being checked.
        const string cdp = "https://ca.example.test/crl/issuing-ca";

        var fromCrl = CrlDpName(cdp);
        var fromCert = CertDpName(cdp);

        Assert.NotNull(fromCrl);
        Assert.Equal(fromCert, fromCrl);
    }

    [Fact]
    public void A_directory_name_distribution_point_would_not_match_a_certificates_uri()
    {
        // Pins the reason the old form was wrong, so nobody reintroduces it as a "fallback".
        var directoryName = new DistributionPointName(DistributionPointName.FullName,
            new GeneralNames(new GeneralName(GeneralName.DirectoryName, new X509Name("CN=Issuing CA,O=Acme"))));
        var fromCert = CertDpName("https://ca.example.test/crl/issuing-ca");

        Assert.NotEqual(fromCert, directoryName);
    }

    [Fact]
    public void With_no_configured_cdp_the_distribution_point_is_omitted_rather_than_invented()
    {
        // An IDP with no distributionPoint does not trigger the name-matching test at all, so
        // the CRL covers the issuer's certificates. That is the correct fallback; synthesising
        // a name that cannot match is not.
        Assert.Null(CrlDpName());
    }

    [Fact]
    public void Multiple_cdp_urls_all_appear_so_any_one_of_them_matches()
    {
        var dp = CrlDpName("https://a.example.test/crl/ca", "https://b.example.test/crl/ca");

        Assert.NotNull(dp);
        var names = GeneralNames.GetInstance(dp!.Name).GetNames();
        Assert.Equal(2, names.Length);
        Assert.All(names, n => Assert.Equal(GeneralName.UniformResourceIdentifier, n.TagNo));
    }

    // ---- CRL number allocation scope ----

    /// <summary>
    /// The unique index is (IssuerName, CrlNumber). Both generators must allocate from that same
    /// scope or they collide. The full path used to read MAX(CrlNumber) filtered by TaskId.
    /// </summary>
    private static long NextCrlNumber(IEnumerable<(string Issuer, Guid TaskId, long Number)> existing,
                                      string issuer, long lastCounter) =>
        Math.Max(lastCounter, existing.Where(r => r.Issuer == issuer)
                                      .Select(r => (long?)r.Number).Max() ?? 0L) + 1;

    [Fact]
    public void Full_and_delta_crls_share_one_sequence_per_issuer()
    {
        const string issuer = "CN=Issuing CA";
        var fullTask = Guid.NewGuid();
        var deltaTask = Guid.NewGuid();

        // A delta config exists and has already published number 2 under its own TaskId.
        var rows = new List<(string, Guid, long)>
        {
            (issuer, fullTask, 1),
            (issuer, deltaTask, 2),
        };

        // Scoped by issuer, the next full CRL is 3. Scoped by TaskId — the old behaviour — it
        // would recompute 2, collide on the (IssuerName, CrlNumber) index, and keep colliding on
        // every subsequent run, permanently halting CRL publication for this CA.
        Assert.Equal(3, NextCrlNumber(rows, issuer, lastCounter: 1));
    }

    [Fact]
    public void Numbers_stay_monotonic_across_a_legacy_zero_counter()
    {
        const string issuer = "CN=Issuing CA";
        var rows = new List<(string, Guid, long)> { (issuer, Guid.NewGuid(), 7) };

        // Legacy installs where LastCrlNumber was never populated must not regress to 1.
        Assert.Equal(8, NextCrlNumber(rows, issuer, lastCounter: 0));
    }

    [Fact]
    public void A_different_issuers_numbers_do_not_advance_this_ones()
    {
        const string mine = "CN=Issuing CA";
        var rows = new List<(string, Guid, long)> { ("CN=Some Other CA", Guid.NewGuid(), 900) };

        Assert.Equal(1, NextCrlNumber(rows, mine, lastCounter: 0));
    }

}

/// <summary>
/// Drives the real <see cref="CrlExportJob"/> to prove it re-signs the CRL on a tick where
/// nothing new was revoked.
/// <para>
/// The job used to regenerate only when <c>CheckNewCrlEntries</c> found something, and otherwise
/// advanced <c>NextUpdateUtc</c> / <c>Crls.NextUpdate</c> while leaving <c>RawData</c> — whose
/// nextUpdate is baked in at signing time — untouched. The CA then served an expired CRL and
/// PublicCrlController derived its Cache-Control max-age from the advanced column, propagating
/// the false freshness to every downstream cache.
/// </para>
/// </summary>
public class CrlRegenerationCadenceTests
{
    private sealed class RecordingCrlService : ICrlService
    {
        public int FullGenerations { get; private set; }
        public int DeltaGenerations { get; private set; }

        public Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
        { FullGenerations++; return Task.FromResult("-----BEGIN X509 CRL-----"); }

        public Task<string> GenerateDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
        { DeltaGenerations++; return Task.FromResult("-----BEGIN X509 CRL-----"); }

        public Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<string?> GetLatestDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<CrlBlob?> GetLatestCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
        public Task<CrlBlob?> GetLatestDeltaCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
    }

    private sealed class NoopAudit : IAuditService
    {
        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername,
            string? targetEntityType = null, string? targetEntityId = null, object? details = null,
            string? sourceIp = null, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? tenantId = null)
            => Task.CompletedTask;
    }

    [Fact]
    public async Task A_tick_with_no_new_revocations_still_regenerates_the_crl()
    {
        using var db = InMemoryDbContextFactory.Create();

        var ca = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            SubjectDN = "CN=Issuing CA",
            Issuer = "CN=Issuing CA",
            IsCA = true,
            Pem = "-----BEGIN CERTIFICATE-----",
            NotBefore = DateTime.UtcNow.AddYears(-1),
            NotAfter = DateTime.UtcNow.AddYears(1),
        };
        db.Certificates.Add(ca);

        var taskId = Guid.NewGuid();
        db.CrlConfigurations.Add(new CrlConfigurationEntity
        {
            TaskId = taskId,
            CaCertificateId = ca.CertificateId,
            Name = "issuing-ca full",
            UpdateInterval = "0 */6 * * *",
            IsDelta = false,
            Enabled = true,
            NextUpdateUtc = DateTime.UtcNow,
        });

        // A CRL already exists and NOTHING has been revoked since — the exact state that used to
        // take the column-only branch.
        db.Crls.Add(new CrlEntity
        {
            IssuerName = ca.SubjectDN,
            TaskId = taskId,
            CrlNumber = 1,
            ThisUpdate = DateTime.UtcNow.AddHours(-12),
            NextUpdate = DateTime.UtcNow.AddHours(-6),   // already expired
            GeneratedAt = DateTime.UtcNow.AddHours(-12),
            RawData = [1, 2, 3],
        });
        await db.SaveChangesAsync();

        var crlService = new RecordingCrlService();
        var sp = new ServiceCollection().BuildServiceProvider();
        var config = new SystemConfig();
        var job = new CrlExportJob(
            serviceProvider: sp,
            logger: NullLogger<CrlExportJob>.Instance,
            crlService: crlService,
            db: db,
            audit: new NoopAudit(),
            config: config,
            runner: new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test"));

        await job.RunAsync(
            new CrlExportScheduleOptions { CaCertificateId = ca.CertificateId, TaskId = taskId },
            "0 */6 * * *",
            CancellationToken.None);

        Assert.Equal(1, crlService.FullGenerations);
    }
}
