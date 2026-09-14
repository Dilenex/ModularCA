using ModularCA.Core.Services.Est;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Est;

/// <summary>
/// Pins what the EST handshake trusts, and how it behaves when the database cannot be read.
/// </summary>
public class EstTrustAnchorCacheTests
{
    private static Guid AddCaWithCert(ModularCADbContext db, string label, bool caEnabled, bool estEnabled, bool hasEstRow = true)
    {
        using var cert = TestCertificates.CreateCa($"CN={label}");
        var certId = Guid.NewGuid();
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = certId,
            SubjectDN = cert.Subject,
            Issuer = cert.Issuer,
            RawCertificate = cert.RawData,
            IsCA = true,
        });
        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(),
            Name = label,
            Label = label,
            IsEnabled = caEnabled,
            CertificateId = certId,
        };
        db.CertificateAuthorities.Add(ca);
        if (hasEstRow)
        {
            db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
            {
                Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "EST", IsEnabled = estEnabled,
            });
        }
        return ca.Id;
    }

    [Fact]
    public void Only_enabled_CAs_with_EST_enabled_are_anchors_and_the_rest_are_chain_material()
    {
        var name = $"anchors-{Guid.NewGuid():N}";
        using (var seed = InMemoryDbContextFactory.Create(name))
        {
            AddCaWithCert(seed, "est-on", caEnabled: true, estEnabled: true);
            AddCaWithCert(seed, "est-off", caEnabled: true, estEnabled: false);
            AddCaWithCert(seed, "no-est-row", caEnabled: true, estEnabled: false, hasEstRow: false);
            // Disabling a CA is the operator's response to a compromise. Its EST row may well still
            // say enabled; the CA's own switch must win, or its certificates keep passing the
            // handshake for as long as nobody notices the row.
            AddCaWithCert(seed, "ca-disabled", caEnabled: false, estEnabled: true);
            seed.SaveChanges();
        }

        var cache = new EstTrustAnchorCache(() => InMemoryDbContextFactory.Create(name), TimeSpan.FromMinutes(1));

        Assert.Equal(1, cache.LoadNow());
        var set = cache.Current;
        Assert.Single(set.EstCaCerts);
        Assert.Contains("est-on", set.EstCaCerts[0].Subject);
        // Two chain-material certificates: est-off and no-est-row. The disabled CA is excluded
        // entirely; it must not help a chain terminate either.
        Assert.Equal(2, set.ChainCerts.Count);
        Assert.DoesNotContain(set.ChainCerts, c => c.Subject.Contains("ca-disabled"));
    }

    [Fact]
    public void A_failed_initial_load_leaves_the_empty_set_which_rejects_everything()
    {
        var errors = new List<string>();
        var cache = new EstTrustAnchorCache(
            () => throw new InvalidOperationException("database unreachable"),
            TimeSpan.FromMinutes(1),
            errors.Add);

        Assert.Equal(0, cache.LoadNow());
        Assert.Empty(cache.Current.EstCaCerts);
        Assert.Contains(errors, e => e.Contains("database unreachable"));
    }

    [Fact]
    public void A_failed_refresh_keeps_the_previous_snapshot_and_its_age()
    {
        var name = $"refresh-{Guid.NewGuid():N}";
        using (var seed = InMemoryDbContextFactory.Create(name))
        {
            AddCaWithCert(seed, "est-on", caEnabled: true, estEnabled: true);
            seed.SaveChanges();
        }

        var fail = false;
        var cache = new EstTrustAnchorCache(
            () => fail ? throw new InvalidOperationException("down") : InMemoryDbContextFactory.Create(name),
            EstTrustAnchorCache.MinimumRefreshInterval);

        Assert.Equal(1, cache.LoadNow());
        var loadedAt = cache.Current.LoadedUtc;

        // An empty set rejects every certificate, so treating a transient read error as "no CAs
        // have EST enabled" would turn a blip into a fleet-wide enrollment outage. And the
        // snapshot's timestamp must stay honest: an earlier version re-stamped it on failure,
        // which made a CA disabled during an outage look freshly trusted.
        fail = true;
        Thread.Sleep(EstTrustAnchorCache.MinimumRefreshInterval + TimeSpan.FromMilliseconds(200));
        var afterFailure = cache.Current;   // triggers a background refresh that fails
        Thread.Sleep(500);
        var settled = cache.Current;

        Assert.Single(afterFailure.EstCaCerts);
        Assert.Single(settled.EstCaCerts);
        Assert.Equal(loadedAt, settled.LoadedUtc);
    }

    [Fact]
    public void The_refresh_interval_has_a_floor()
    {
        // A misconfigured zero must not turn every handshake into a database query.
        var cache = new EstTrustAnchorCache(() => throw new InvalidOperationException(), TimeSpan.Zero);
        Assert.Equal(0, cache.LoadNow());
        Assert.True(EstTrustAnchorCache.MinimumRefreshInterval >= TimeSpan.FromSeconds(5));
    }
}
