using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Models;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Core.Services.Msae;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Msae;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// The readiness checklist tells the truth about each precondition of Windows autoenrollment and
/// points at the page that fixes it. Every state here is one an operator hit in the lab.
/// </summary>
public class MsaeReadinessServiceTests
{
    private sealed class Principals : IEnrollmentPrincipalAuthorizer
    {
        public HashSet<string> MayEnroll { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Task<bool> MayEnrollAsync(string username, Guid caId) => Task.FromResult(MayEnroll.Contains(username));
    }

    private sealed class Profiles : IProfileResolutionService
    {
        public HashSet<Guid> Gated { get; } = [];
        public Task<EffectiveRequestProfile> ResolveRequestProfileAsync(Guid requestProfileId)
            => Task.FromResult(new EffectiveRequestProfile { SourceProfileId = requestProfileId, RequireApproval = Gated.Contains(requestProfileId) });
        public Task<EffectiveCertProfile> ResolveCertProfileAsync(Guid certProfileId) => throw new NotSupportedException();
        public Task<List<string>> ValidateCertProfileInheritanceAsync(Guid childProfileId) => throw new NotSupportedException();
        public Task<List<string>> ValidateRequestProfileInheritanceAsync(Guid childProfileId) => throw new NotSupportedException();
    }

    private sealed class Names : IHostNameProbe
    {
        public Dictionary<string, string?> Canonical { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Task<string?> CanonicalNameAsync(string host, CancellationToken cancellation = default)
            => Task.FromResult(Canonical.TryGetValue(host, out var c) ? c : null);
    }

    private sealed class Harness
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public Principals Principals { get; } = new();
        public Profiles Profiles { get; } = new();
        public Names Names { get; } = new();
        public SystemConfig Config { get; } = new SystemConfig { Https = { PublicDomain = "ca4.example.test", PublicPort = 443 } };
        public Guid TenantId { get; } = Guid.NewGuid();
        public CertificateAuthorityEntity Ca { get; }

        public Harness()
        {
            Db.Tenants.Add(new TenantEntity { Id = TenantId, Name = "Customer A", Slug = "customer-a" });
            Ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Staging", Label = "staging", TenantId = TenantId, IsEnabled = true };
            Db.CertificateAuthorities.Add(Ca);
            Db.SaveChanges();
            Names.Canonical["ca4.example.test"] = "ca4.example.test";
        }

        public MsaeReadinessService Service => new(Db, Config, Principals, Profiles, Names, new PublicNameResolver(Db, Config));

        public TenantHostnameEntity AddHostname(string host, DateTime? notAfter = null, bool withCert = true, Guid? tenantId = null, bool revoked = false)
        {
            CertificateEntity? cert = null;
            if (withCert)
            {
                cert = new CertificateEntity
                {
                    CertificateId = Guid.NewGuid(), SerialNumber = "0A", Pem = "x", SubjectDN = $"CN={host}", Issuer = "CN=Staging",
                    NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = notAfter ?? DateTime.UtcNow.AddDays(200), Revoked = revoked,
                };
                Db.Certificates.Add(cert);
            }
            var row = new TenantHostnameEntity { Id = Guid.NewGuid(), TenantId = tenantId ?? TenantId, Hostname = host, IssuingCaId = Ca.Id, CertificateId = cert?.CertificateId };
            Db.TenantHostnames.Add(row);
            Db.SaveChanges();
            Names.Canonical[host] = host;
            return row;
        }

        public CaProtocolConfigEntity EnableMsae(bool kerberos = true, bool profiles = true)
        {
            var row = new CaProtocolConfigEntity
            {
                CaId = Ca.Id, Protocol = "MSAE", IsEnabled = true,
                SigningProfileId = profiles ? Guid.NewGuid() : null, CertProfileId = profiles ? Guid.NewGuid() : null,
                MsaeAllowUsernameToken = true, MsaeAllowKerberos = kerberos,
            };
            Db.CaProtocolConfigs.Add(row); Db.SaveChanges();
            return row;
        }

        public KerberosRealmEntity BindRealm(string realm = "LAB.MSAE.TEST", string spn = "HTTP/ca4.example.test", bool liveKey = true, bool mayEnroll = true, bool active = true)
        {
            var user = new UserEntity { Id = Guid.NewGuid(), Username = $"svc-{realm.ToLowerInvariant()}", Email = "x@y", PasswordHash = "x", IsActive = active, IsServiceIdentity = true };
            Db.Users.Add(user);
            var entity = new KerberosRealmEntity { Id = Guid.NewGuid(), TenantId = TenantId, Realm = realm, DnsDomain = realm.ToLowerInvariant(), ServicePrincipal = spn, EnrollmentUserId = user.Id, IsEnabled = true };
            entity.Keys.Add(new KerberosRealmKeyEntity { Id = Guid.NewGuid(), RealmId = entity.Id, Kvno = 4, EncryptionType = "AES256", ProtectedKey = "x", Source = KerberosKeySource.Password, RetireAfter = liveKey ? null : DateTime.UtcNow.AddHours(-1) });
            Db.KerberosRealms.Add(entity); Db.SaveChanges();
            if (mayEnroll) Principals.MayEnroll.Add(user.Username);
            return entity;
        }

        public CertificateTemplateEntity OfferTemplate(string name, string oid, Guid? requestProfileId = null)
        {
            var t = new CertificateTemplateEntity { Id = Guid.NewGuid(), Name = name, CaId = Ca.Id, IsEnabled = true, MsaeTemplateOid = oid, RequestProfileId = requestProfileId, CertProfileId = Guid.NewGuid(), SigningProfileId = Guid.NewGuid() };
            Db.CertificateTemplates.Add(t); Db.SaveChanges();
            return t;
        }
    }

    private static MsaeReadinessStep Step(MsaeReadiness r, string key) => Assert.Single(r.Steps, s => s.Key == key);

    [Fact]
    public async Task A_bare_ca_fails_every_precondition_and_each_failure_points_somewhere()
    {
        var h = new Harness();
        var r = (await h.Service.EvaluateAsync(h.Ca.Id))!;

        Assert.False(r.Ready);
        Assert.Equal("https://ca4.example.test/msae/staging/cep", r.CepUrl);
        Assert.Equal($"{{{h.Ca.Id.ToString().ToUpperInvariant()}}}", r.PolicyId);
        foreach (var key in new[] { "msae-enabled", "profiles", "realms", "templates" })
        {
            var s = Step(r, key);
            Assert.Equal(MsaeReadinessState.Fail, s.State);
            Assert.NotNull(s.Fix);
            Assert.StartsWith("/", s.Fix!.Path);
        }
        // Dependent checks are skipped rather than failed when there is nothing to check.
        Assert.Equal(MsaeReadinessState.Skip, Step(r, "realm-keys").State);
        Assert.Equal(MsaeReadinessState.Skip, Step(r, "enrollment-identity").State);
        // Username-only is the default: a warning, since Group Policy cannot supply a username.
        Assert.Equal(MsaeReadinessState.Warn, Step(r, "auth-modes").State);
        Assert.Null(await h.Service.EvaluateAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task A_fully_configured_ca_is_ready_and_says_what_the_client_needs()
    {
        var h = new Harness();
        h.EnableMsae(); h.BindRealm(); h.OfferTemplate("LabDevice", "2.25.1.2.3.4");
        var r = (await h.Service.EvaluateAsync(h.Ca.Id))!;

        Assert.True(r.Ready, string.Join(" | ", r.Steps.Where(s => s.State == MsaeReadinessState.Fail).Select(s => $"{s.Key}: {s.Detail} {string.Join("; ", s.Items)}")));
        Assert.All(r.Steps.Where(s => s.Key != "client-policy"), s => Assert.Equal(MsaeReadinessState.Pass, s.State));
        var client = Step(r, "client-policy");
        Assert.Contains(client.Items, i => i.Contains(r.CepUrl));
        Assert.Contains(client.Items, i => i.Contains(r.PolicyId));
        Assert.Contains("acts as svc-lab.msae.test (service identity)", Step(r, "enrollment-identity").Items[0]);
    }

    [Fact]
    public async Task An_alias_hostname_or_a_mismatched_service_principal_fails_the_name_check_and_names_the_ntlm_fallback()
    {
        var h = new Harness();
        h.EnableMsae(); h.BindRealm(); h.OfferTemplate("LabDevice", "2.25.1.2.3.4");
        h.Names.Canonical["ca4.example.test"] = "host-01.example.test";   // a CNAME, or an alias in a hosts file
        var alias = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, alias.State);
        Assert.Contains(alias.Items, i => i.Contains("HTTP/host-01.example.test") && i.Contains("NTLM"));

        h.Names.Canonical["ca4.example.test"] = "ca4.example.test";
        var realm = await h.Db.KerberosRealms.SingleAsync();
        realm.ServicePrincipal = "HTTP/ca.lab.msae.test";
        await h.Db.SaveChangesAsync();
        var mismatch = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, mismatch.State);
        Assert.Contains(mismatch.Items, i => i.Contains("ca.lab.msae.test") && i.Contains("ca4.example.test"));

        // Unresolvable from the CA host is a warning, not a failure: the forest's clients resolve on their own.
        realm.ServicePrincipal = "HTTP/ca4.example.test";
        await h.Db.SaveChangesAsync();
        h.Names.Canonical.Remove("ca4.example.test");
        Assert.Equal(MsaeReadinessState.Warn, Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname").State);

        h.Config.Https.PublicDomain = "";
        var none = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, none.State);
        Assert.Equal("/settings?tab=General", none.Fix!.Path);
    }

    [Fact]
    public async Task A_service_principal_may_name_a_hostname_of_the_tenant_and_the_urls_follow_it()
    {
        var h = new Harness();
        h.EnableMsae(); h.OfferTemplate("LabDevice", "2.25.1.2.3.4");
        h.AddHostname("ca.customer-a.example");
        h.BindRealm(spn: "HTTP/ca.customer-a.example");
        var r = (await h.Service.EvaluateAsync(h.Ca.Id))!;

        Assert.True(r.Ready, string.Join(" | ", r.Steps.Where(s => s.State == MsaeReadinessState.Fail).Select(s => $"{s.Key}: {string.Join("; ", s.Items)}")));
        var host = Step(r, "hostname");
        Assert.Equal(MsaeReadinessState.Pass, host.State);
        Assert.Contains(host.Items, i => i.Contains("HTTP/ca.customer-a.example") && i.Contains("valid until"));
        Assert.Contains(host.Items, i => i.StartsWith("ca.customer-a.example resolves as a canonical name"));
        Assert.DoesNotContain(host.Items, i => i.Contains("ca4.example.test"));
        Assert.Equal("https://ca.customer-a.example/msae/staging/cep", r.CepUrl);
        Assert.Contains(Step(r, "client-policy").Items, i => i == $"Policy server URL: {r.CepUrl}");

        // A second forest on the public name. Bindings are listed by realm, so B.TEST is now the
        // headline and the tenant-hostname forest's URL, which differs, is listed on its own line.
        h.BindRealm("B.TEST", spn: "HTTP/ca4.example.test");
        var two = (await h.Service.EvaluateAsync(h.Ca.Id))!;
        Assert.Equal(MsaeReadinessState.Pass, Step(two, "hostname").State);
        Assert.Equal("https://ca4.example.test/msae/staging/cep", two.CepUrl);
        Assert.Contains(Step(two, "client-policy").Items, i => i == "Policy server URL for LAB.MSAE.TEST: https://ca.customer-a.example/msae/staging/cep");
    }

    [Fact]
    public async Task A_tenant_hostname_without_a_live_certificate_fails_and_points_at_the_hostnames_tab()
    {
        var h = new Harness();
        h.EnableMsae(); h.OfferTemplate("LabDevice", "2.25.1.2.3.4");
        var row = h.AddHostname("ca.customer-a.example", notAfter: DateTime.UtcNow.AddDays(-1));
        h.BindRealm(spn: "HTTP/ca.customer-a.example");

        var expired = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, expired.State);
        Assert.Contains(expired.Items, i => i.Contains("expired") && i.Contains("ca.customer-a.example"));
        Assert.Equal($"/tenants/{h.TenantId}?tab=hostnames", expired.Fix!.Path);

        var tracked = await h.Db.TenantHostnames.SingleAsync();
        tracked.CertificateId = null;
        await h.Db.SaveChangesAsync();
        var missing = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, missing.State);
        Assert.Contains(missing.Items, i => i.Contains("no endpoint certificate"));
        Assert.Equal($"/tenants/{h.TenantId}?tab=hostnames", missing.Fix!.Path);

        var fresh = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = "0B", Pem = "x", SubjectDN = "CN=x", Issuer = "CN=Staging", NotBefore = DateTime.UtcNow, NotAfter = DateTime.UtcNow.AddDays(100), Revoked = true };
        h.Db.Certificates.Add(fresh);
        tracked.CertificateId = fresh.CertificateId;
        await h.Db.SaveChangesAsync();
        var revoked = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, revoked.State);
        Assert.Contains(revoked.Items, i => i.Contains("revoked"));

        // The tenant hostname itself can be an alias, with the same NTLM warning as the public name.
        fresh.Revoked = false;
        await h.Db.SaveChangesAsync();
        h.Names.Canonical["ca.customer-a.example"] = "host-07.customer-a.example";
        var alias = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, alias.State);
        Assert.Contains(alias.Items, i => i.Contains("HTTP/host-07.customer-a.example") && i.Contains("NTLM"));
        _ = row;
    }

    [Fact]
    public async Task Another_tenants_hostname_in_the_service_principal_is_a_mismatch_not_a_known_name()
    {
        var h = new Harness();
        h.EnableMsae(); h.OfferTemplate("LabDevice", "2.25.1.2.3.4");
        h.AddHostname("ca.customer-b.example", tenantId: Guid.NewGuid());
        h.BindRealm(spn: "HTTP/ca.customer-b.example");
        var r = (await h.Service.EvaluateAsync(h.Ca.Id))!;
        var host = Step(r, "hostname");
        Assert.Equal(MsaeReadinessState.Fail, host.State);
        Assert.Contains(host.Items, i => i.Contains("ca.customer-b.example") && i.Contains("neither the public hostname ca4.example.test nor a hostname of this tenant"));
        Assert.Equal("https://ca4.example.test/msae/staging/cep", r.CepUrl);   // the URL never follows an unknown name
        Assert.False(r.Ready);
    }

    [Fact]
    public async Task Keys_and_identities_are_checked_per_forest()
    {
        var h = new Harness();
        h.EnableMsae(); h.OfferTemplate("LabDevice", "2.25.1.2.3.4");
        h.BindRealm("A.TEST");
        h.BindRealm("B.TEST", liveKey: false);
        h.BindRealm("C.TEST", mayEnroll: false);
        h.BindRealm("D.TEST", active: false);
        var r = (await h.Service.EvaluateAsync(h.Ca.Id))!;

        var keys = Step(r, "realm-keys");
        Assert.Equal(MsaeReadinessState.Fail, keys.State);
        Assert.Contains(keys.Items, i => i.StartsWith("A.TEST: key version 4"));
        Assert.Contains(keys.Items, i => i.StartsWith("B.TEST: no live key"));

        var ids = Step(r, "enrollment-identity");
        Assert.Equal(MsaeReadinessState.Fail, ids.State);
        Assert.Contains(ids.Items, i => i.StartsWith("C.TEST:") && i.Contains("holds no enrollment right"));
        Assert.Contains(ids.Items, i => i.StartsWith("D.TEST:") && i.Contains("is disabled"));
        Assert.Contains(ids.Items, i => i.StartsWith("A.TEST:") && i.Contains("may enroll"));
        Assert.False(r.Ready);
    }

    [Fact]
    public async Task Templates_windows_cannot_read_fail_and_approval_gated_ones_warn()
    {
        var h = new Harness();
        h.EnableMsae(); h.BindRealm();
        var gated = Guid.NewGuid(); h.Profiles.Gated.Add(gated);
        h.OfferTemplate("LabReq", "2.25.1.2.3.4", gated);
        var warned = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "templates");
        Assert.Equal(MsaeReadinessState.Warn, warned.State);
        Assert.Contains(warned.Items, i => i.StartsWith("LabReq") && i.Contains("approval"));

        h.OfferTemplate("LabDevice2", "2.25.245003695776623753622119796933289142842");   // an arc above 2^63-1
        var failed = Step((await h.Service.EvaluateAsync(h.Ca.Id))!, "templates");
        Assert.Equal(MsaeReadinessState.Fail, failed.State);
        Assert.Contains(failed.Items, i => i.StartsWith("LabDevice2") && i.Contains("unreadable"));
        Assert.Equal("/templates?tenant=customer-a&ca=staging", failed.Fix!.Path);
    }

    [Fact]
    public async Task Disabled_msae_or_missing_profiles_or_no_kerberos_are_reported_against_the_protocol_card()
    {
        var h = new Harness();
        var row = h.EnableMsae(kerberos: false, profiles: false);
        h.BindRealm(); h.OfferTemplate("LabDevice", "2.25.1.2.3.4");
        var r = (await h.Service.EvaluateAsync(h.Ca.Id))!;
        Assert.Equal(MsaeReadinessState.Pass, Step(r, "msae-enabled").State);
        var profiles = Step(r, "profiles");
        Assert.Equal(MsaeReadinessState.Fail, profiles.State);
        Assert.Contains("no signing profile and no certificate profile", profiles.Detail);
        Assert.Equal(MsaeReadinessState.Warn, Step(r, "auth-modes").State);
        Assert.Equal("/authorities/protocols?tenant=customer-a&ca=staging", profiles.Fix!.Path);

        row.IsEnabled = false; row.MsaeAllowUsernameToken = false;
        await h.Db.SaveChangesAsync();
        var off = (await h.Service.EvaluateAsync(h.Ca.Id))!;
        Assert.Equal(MsaeReadinessState.Fail, Step(off, "msae-enabled").State);
        Assert.Equal(MsaeReadinessState.Fail, Step(off, "auth-modes").State);
    }
}
