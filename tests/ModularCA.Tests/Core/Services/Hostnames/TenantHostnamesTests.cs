using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Hostnames;

/// <summary>
/// A tenant's hostnames are validated and unique, get their certificate from the tenant's own
/// CA, and disappear again without a trace when issuance fails or the name is removed.
/// </summary>
public class TenantHostnameServiceTests
{
    /// <summary>Stands in for the issuance pipeline: records calls, mints a certificate row, or refuses.</summary>
    private sealed class FakeIssuer(ModularCADbContext db) : ITenantHostnameCertificateIssuer
    {
        public List<string> Issued { get; } = [];
        public List<string> Retired { get; } = [];
        public string? RefuseWith { get; set; }

        public async Task<CertificateEntity> IssueAsync(TenantHostnameEntity hostname, CancellationToken cancellation = default)
        {
            Issued.Add(hostname.Hostname);
            if (RefuseWith != null) throw new InvalidOperationException(RefuseWith);
            var cert = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N")[..12].ToUpperInvariant(), Pem = "x",
                SubjectDN = $"CN={hostname.Hostname}", Issuer = "CN=Issuer", NotBefore = DateTime.UtcNow, NotAfter = DateTime.UtcNow.AddDays(397),
            };
            db.Certificates.Add(cert);
            var row = await db.TenantHostnames.FirstAsync(h => h.Id == hostname.Id, cancellation);
            row.CertificateId = cert.CertificateId;
            await db.SaveChangesAsync(cancellation);
            hostname.CertificateId = cert.CertificateId;
            return cert;
        }

        public Task RetireAsync(TenantHostnameEntity hostname, CancellationToken cancellation = default)
        {
            Retired.Add(hostname.Hostname);
            return Task.CompletedTask;
        }
    }

    private sealed class Harness
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public SystemConfig Config { get; } = new() { Https = { PublicDomain = "ca4.example.test", PublicPort = 443 }, Mtls = { AuthSubdomain = "mtls" } };
        public FakeIssuer Issuer { get; }
        public int Reloads { get; private set; }
        public TenantHostnameCertificateCache Cache { get; }
        public Guid TenantId { get; } = Guid.NewGuid();
        public Guid OtherTenantId { get; } = Guid.NewGuid();
        public CertificateAuthorityEntity Ca { get; }
        public CertificateAuthorityEntity OtherTenantCa { get; }
        public CertificateAuthorityEntity SshCa { get; }
        public CertificateAuthorityEntity DisabledCa { get; }

        public Harness()
        {
            Issuer = new FakeIssuer(Db);
            Cache = new TenantHostnameCertificateCache(() => { Reloads++; return new Dictionary<string, X509Certificate2>(); }, TimeSpan.FromMinutes(5));
            Db.Tenants.Add(new TenantEntity { Id = TenantId, Name = "Customer A", Slug = "customer-a" });
            Db.Tenants.Add(new TenantEntity { Id = OtherTenantId, Name = "Customer B", Slug = "customer-b" });
            Ca = AddCa("Staging", "staging", TenantId);
            OtherTenantCa = AddCa("B Issuing", "b-issuing", OtherTenantId);
            SshCa = AddCa("SSH", "ssh", TenantId, ssh: true);
            DisabledCa = AddCa("Old", "old", TenantId, enabled: false);
            Db.SaveChanges();
        }

        private CertificateAuthorityEntity AddCa(string name, string label, Guid tenantId, bool ssh = false, bool enabled = true)
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = name, Label = label, TenantId = tenantId, IsEnabled = enabled, IsSshCa = ssh, CertificateId = Guid.NewGuid() };
            Db.CertificateAuthorities.Add(ca);
            return ca;
        }

        public TenantHostnameService Service => new(Db, Config, Issuer, Cache);
    }

    [Theory]
    [InlineData("  CA.Customer-A.Example. ", "ca.customer-a.example")]
    [InlineData("intranet-ca", "intranet-ca")]
    [InlineData("Ca4.Example.Test", "ca4.example.test")]
    public void Hostnames_are_lower_cased_and_stripped_of_the_trailing_dot(string raw, string expected)
        => Assert.Equal(expected, TenantHostnameService.NormalizeHostname(raw));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("https://ca.example.test")]
    [InlineData("ca.example.test:8443")]
    [InlineData("ca.example.test/msae")]
    [InlineData("*.example.test")]
    [InlineData("10.0.0.5")]
    [InlineData("[::1]")]
    [InlineData("ca example.test")]
    [InlineData("-bad.example.test")]
    [InlineData("under_score.example.test")]
    public void Names_that_are_not_plain_dns_names_are_refused(string raw)
        => Assert.Throws<InvalidOperationException>(() => TenantHostnameService.NormalizeHostname(raw));

    [Fact]
    public void A_name_longer_than_a_dns_name_can_be_is_refused()
    {
        var label = new string('a', 63);
        var tooLong = string.Join('.', Enumerable.Repeat(label, 4)) + ".x";   // 257 characters
        Assert.Throws<InvalidOperationException>(() => TenantHostnameService.NormalizeHostname(tooLong));
    }

    [Fact]
    public async Task A_name_must_be_new_across_every_tenant_and_must_not_be_one_the_listener_already_answers()
    {
        var h = new Harness();
        await h.Service.CreateAsync(h.OtherTenantId, "ca.customer-b.example", h.OtherTenantCa.Id, null);

        var dup = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "CA.Customer-B.Example", h.Ca.Id, null));
        Assert.Contains("already in use", dup.Message);

        var console = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "ca4.example.test", h.Ca.Id, null));
        Assert.Contains("public hostname", console.Message);

        var mtls = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "mtls.ca4.example.test", h.Ca.Id, null));
        Assert.Contains("mTLS", mtls.Message);

        Assert.Equal(["ca.customer-b.example"], h.Issuer.Issued);
        Assert.Single(h.Db.TenantHostnames);
    }

    [Fact]
    public async Task The_issuing_ca_must_be_an_enabled_non_ssh_ca_of_the_same_tenant()
    {
        var h = new Harness();
        var foreign = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "ca.customer-a.example", h.OtherTenantCa.Id, null));
        Assert.Contains("belong to this tenant", foreign.Message);
        var ssh = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "ca.customer-a.example", h.SshCa.Id, null));
        Assert.Contains("SSH", ssh.Message);
        var disabled = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "ca.customer-a.example", h.DisabledCa.Id, null));
        Assert.Contains("cannot issue", disabled.Message);
        var missing = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "ca.customer-a.example", Guid.NewGuid(), null));
        Assert.Contains("Choose one", missing.Message);

        Assert.Empty(h.Issuer.Issued);
        Assert.Empty(h.Db.TenantHostnames);
    }

    [Fact]
    public async Task Creating_a_name_issues_its_certificate_and_a_refused_issuance_leaves_no_row_behind()
    {
        var h = new Harness();
        var created = await h.Service.CreateAsync(h.TenantId, " CA.Customer-A.Example ", h.Ca.Id, "  primary  ");
        Assert.Equal("ca.customer-a.example", created.Hostname);
        Assert.Equal("primary", created.Notes);
        Assert.NotNull(created.CertificateId);
        Assert.NotNull(created.Certificate);
        Assert.Equal("staging", created.IssuingCa!.Label);

        h.Issuer.RefuseWith = "the profile refused the key";
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.CreateAsync(h.TenantId, "second.customer-a.example", h.Ca.Id, null));
        Assert.Contains("second.customer-a.example", refused.Message);
        Assert.Contains("the profile refused the key", refused.Message);
        Assert.Equal(["ca.customer-a.example"], (await h.Service.ListAsync(h.TenantId)).Select(x => x.Hostname));
        Assert.Equal(1, h.Reloads);   // the listener is told after the cleanup, in case anything was served meanwhile
    }

    [Fact]
    public async Task Removing_a_name_retires_its_certificate_deletes_the_row_and_reloads_the_listener()
    {
        var h = new Harness();
        var created = await h.Service.CreateAsync(h.TenantId, "ca.customer-a.example", h.Ca.Id, null);
        var reloadsAfterCreate = h.Reloads;

        await h.Service.DeleteAsync(created.Id);

        Assert.Equal(["ca.customer-a.example"], h.Issuer.Retired);
        Assert.Empty(h.Db.TenantHostnames);
        Assert.Equal(reloadsAfterCreate + 1, h.Reloads);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => h.Service.DeleteAsync(created.Id));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => h.Service.ReissueAsync(created.Id));
    }

    [Fact]
    public async Task Reissue_goes_through_the_issuer_for_the_stored_row()
    {
        var h = new Harness();
        var created = await h.Service.CreateAsync(h.TenantId, "ca.customer-a.example", h.Ca.Id, null);
        var first = created.CertificateId;
        var issued = await h.Service.ReissueAsync(created.Id);
        Assert.NotEqual(first, issued.CertificateId);
        Assert.Equal(issued.CertificateId, (await h.Service.GetAsync(created.Id))!.CertificateId);
        Assert.Equal(["ca.customer-a.example", "ca.customer-a.example"], h.Issuer.Issued);
    }
}

/// <summary>
/// The listener picks a tenant hostname's certificate by exact SNI match and falls back to the
/// console's certificate for everything else; the snapshot survives a failed reload.
/// </summary>
public class TenantHostnameCertificateCacheTests
{
    private static readonly X509Certificate2 TenantA = TestCertificates.CreateCa("CN=ca.customer-a.example");
    private static readonly X509Certificate2 TenantB = TestCertificates.CreateCa("CN=ca.customer-b.example");
    private static readonly X509Certificate2 Console = TestCertificates.CreateCa("CN=ca4.example.test");

    private static TenantHostnameCertificateCache Build(Func<IReadOnlyDictionary<string, X509Certificate2>> load)
    {
        var cache = new TenantHostnameCertificateCache(load, TimeSpan.FromMinutes(5));
        cache.LoadNow();
        return cache;
    }

    private static Dictionary<string, X509Certificate2> Two() => new()
    {
        ["ca.customer-a.example"] = TenantA,
        ["ca.customer-b.example"] = TenantB,
    };

    [Fact]
    public void The_certificate_for_a_name_is_found_by_exact_case_insensitive_match_only()
    {
        var cache = Build(Two);
        Assert.Same(TenantA, cache.Find("ca.customer-a.example"));
        Assert.Same(TenantA, cache.Find("CA.Customer-A.Example"));
        Assert.Same(TenantB, cache.Find("ca.customer-b.example"));
        Assert.Null(cache.Find("sub.ca.customer-a.example"));
        Assert.Null(cache.Find("ca.customer-a.example."));
        Assert.Null(cache.Find("customer-a.example"));
        Assert.Null(cache.Find("ca4.example.test"));
        Assert.Null(cache.Find(null));
        Assert.Null(cache.Find(""));
    }

    [Fact]
    public void The_selector_serves_a_tenant_name_its_own_certificate_and_everything_else_the_default()
    {
        var cache = Build(Two);
        Assert.Same(TenantA, TlsServerCertificateSelector.Select("ca.customer-a.example", cache, Console));
        Assert.Same(TenantB, TlsServerCertificateSelector.Select("CA.CUSTOMER-B.EXAMPLE", cache, Console));
        Assert.Same(Console, TlsServerCertificateSelector.Select("ca4.example.test", cache, Console));
        Assert.Same(Console, TlsServerCertificateSelector.Select("unknown.example", cache, Console));
        Assert.Same(Console, TlsServerCertificateSelector.Select(null, cache, Console));      // no SNI
        Assert.Same(Console, TlsServerCertificateSelector.Select("", cache, Console));
        Assert.Null(TlsServerCertificateSelector.Select("unknown.example", cache, null));
    }

    [Fact]
    public void Reload_picks_up_changes_and_a_failed_reload_keeps_the_previous_snapshot()
    {
        var current = Two();
        var fail = false;
        var errors = new List<string>();
        var cache = new TenantHostnameCertificateCache(() => fail ? throw new InvalidOperationException("db down") : current, TimeSpan.FromMinutes(5), errors.Add);
        Assert.Equal(2, cache.LoadNow());

        current = new Dictionary<string, X509Certificate2> { ["ca.customer-a.example"] = TenantA };
        cache.Reload();
        Assert.Equal(1, cache.Count);
        Assert.Null(cache.Find("ca.customer-b.example"));

        fail = true;
        cache.Reload();
        Assert.Equal(1, cache.Count);
        Assert.Same(TenantA, cache.Find("ca.customer-a.example"));
        Assert.Equal(["db down"], errors);
    }
}

/// <summary>
/// URLs that point back at this service name the host the client used only when that host is
/// one of ours for the tenant; anything else is the public domain.
/// </summary>
public class PublicNameResolverTests
{
    private sealed class Harness
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public SystemConfig Config { get; } = new() { Https = { PublicDomain = "ca4.example.test", PublicPort = 443 } };
        public Guid TenantA { get; } = Guid.NewGuid();
        public Guid TenantB { get; } = Guid.NewGuid();

        public Harness()
        {
            var caA = Guid.NewGuid();
            var caB = Guid.NewGuid();
            Db.TenantHostnames.Add(new TenantHostnameEntity { TenantId = TenantA, Hostname = "ca.customer-a.example", IssuingCaId = caA });
            Db.TenantHostnames.Add(new TenantHostnameEntity { TenantId = TenantB, Hostname = "ca.customer-b.example", IssuingCaId = caB });
            Db.SaveChanges();
        }

        public PublicNameResolver Resolver => new(Db, Config);
    }

    [Fact]
    public async Task The_public_domain_is_known_for_every_tenant_and_a_tenant_hostname_only_for_its_own()
    {
        var h = new Harness();
        var pub = await h.Resolver.ResolveAsync("CA4.Example.Test.", h.TenantB);
        Assert.NotNull(pub);
        Assert.True(pub!.IsPublicDomain);
        Assert.Equal("ca4.example.test", pub.Host);

        var own = await h.Resolver.ResolveAsync("CA.Customer-A.Example", h.TenantA);
        Assert.NotNull(own);
        Assert.False(own!.IsPublicDomain);
        Assert.Equal("ca.customer-a.example", own.Host);
        Assert.Equal(h.TenantA, own.TenantHostname!.TenantId);

        Assert.Null(await h.Resolver.ResolveAsync("ca.customer-b.example", h.TenantA));   // another tenant's name
        Assert.Null(await h.Resolver.ResolveAsync("evil.example", h.TenantA));
        Assert.Null(await h.Resolver.ResolveAsync(null, h.TenantA));
        Assert.Null(await h.Resolver.ResolveAsync("ca.customer-a.example", Guid.Empty));
    }

    [Fact]
    public async Task A_request_host_is_advertised_only_when_known_and_the_public_port_rule_applies_to_every_name()
    {
        var h = new Harness();
        Assert.Equal("https://ca.customer-a.example", await h.Resolver.BaseUrlForRequestAsync("ca.customer-a.example", h.TenantA));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForRequestAsync("ca4.example.test", h.TenantA));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForRequestAsync("ca.customer-b.example", h.TenantA));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForRequestAsync("attacker.example", h.TenantA));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForRequestAsync(null, h.TenantA));

        h.Config.Https.PublicPort = 8443;
        Assert.Equal("https://ca.customer-a.example:8443", await h.Resolver.BaseUrlForRequestAsync("ca.customer-a.example", h.TenantA));
        Assert.Equal("https://ca4.example.test:8443", await h.Resolver.BaseUrlForRequestAsync("nope.example", h.TenantA));
    }

    [Theory]
    [InlineData("HTTP/ca.customer-a.example", "ca.customer-a.example")]
    [InlineData("HTTP/CA.Customer-A.Example.", "ca.customer-a.example")]
    [InlineData("HTTP/ca.customer-a.example@LAB.MSAE.TEST", "ca.customer-a.example")]
    [InlineData("HTTP/ca.customer-a.example:8443", "ca.customer-a.example")]
    [InlineData("ca.customer-a.example", "ca.customer-a.example")]
    [InlineData("HTTP/", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void The_host_is_read_out_of_a_service_principal(string? spn, string? expected)
        => Assert.Equal(expected, PublicNameResolver.HostFromServicePrincipal(spn));

    [Fact]
    public async Task A_service_principal_yields_its_host_when_known_for_the_tenant_else_the_public_domain()
    {
        var h = new Harness();
        Assert.Equal("https://ca.customer-a.example", await h.Resolver.BaseUrlForServicePrincipalAsync("HTTP/ca.customer-a.example", h.TenantA));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForServicePrincipalAsync("HTTP/ca4.example.test", h.TenantA));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForServicePrincipalAsync("HTTP/ca.customer-a.example", h.TenantB));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForServicePrincipalAsync("HTTP/ca.lab.msae.test", h.TenantA));
        Assert.Equal("https://ca4.example.test", await h.Resolver.BaseUrlForServicePrincipalAsync(null, h.TenantA));
    }
}
