using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// A mutation whose target arrives in the body (issue a certificate, request one, create a
/// whitelist) cannot be scoped by the route-driven policy handler, which fails closed on it.
/// The body-target rule stands in: resolve the named thing to its CA and require the capability
/// there. Pins that a requester holding <c>cert.request</c> on one CA can request from that CA
/// and no other, that a target attached to no CA is a system matter, that a target naming
/// nothing is refused rather than widened, and that the route resolver now maps the id-only
/// routes (whitelists, CRL schedules, SSH profiles and templates) to their CA.
/// </summary>
public class BodyTargetAuthorizationTests
{
    private static readonly Guid TenantA = Guid.NewGuid();

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public CaGroupAuthorizationService Service => new(Db, NullLogger<CaGroupAuthorizationService>.Instance);
        public CaTargetResolver Resolver => new(Db);
        public Guid UserId { get; } = Guid.NewGuid();
        public CertificateAuthorityEntity CaA { get; }
        public CertificateAuthorityEntity CaB { get; }
        public SigningProfileEntity ProfileA { get; }
        public SigningProfileEntity ProfileB { get; }

        public World()
        {
            CaA = Ca("ca-a");
            CaB = Ca("ca-b");
            ProfileA = Profile(CaA);
            ProfileB = Profile(CaB);
        }

        public CertificateAuthorityEntity Ca(string label)
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = label, Label = label, TenantId = TenantA, CertificateId = Guid.NewGuid() };
            Db.CertificateAuthorities.Add(ca);
            return ca;
        }

        public SigningProfileEntity Profile(CertificateAuthorityEntity? ca)
        {
            var p = new SigningProfileEntity { Id = Guid.NewGuid(), Name = $"sp-{Guid.NewGuid():N}", IssuerId = ca?.CertificateId };
            Db.SigningProfiles.Add(p);
            return p;
        }

        public CertificateEntity Cert(SigningProfileEntity? profile, string serial)
        {
            var c = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = serial, SigningProfileId = profile?.Id };
            Db.Certificates.Add(c);
            return c;
        }

        /// <summary>Grants <paramref name="capability"/> on <paramref name="ca"/> (or at system scope when null).</summary>
        public void Grant(CertificateAuthorityEntity? ca, string capability)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"g-{Guid.NewGuid():N}", DisplayName = "g", TenantId = TenantA, CertificateAuthorityId = ca?.Id, IsSystemGroup = ca == null };
            Db.CaGroups.Add(g);
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = g.Id, UserId = UserId });
            Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = g.Id, Capability = capability });
        }

        public Task<bool> Allowed(string capability, CaTarget target, object? value)
            => BodyTargetAuthorization.IsAllowedAsync(Service, Resolver, UserId, capability, target, value);

        /// <summary>Evaluates a CA-scoped policy for a mutation on <paramref name="path"/> whose only route value is <c>id</c>.</summary>
        public async Task<bool> RouteAllowed(string capability, string path, Guid id)
        {
            var http = new DefaultHttpContext();
            http.Request.Method = HttpMethods.Put;
            http.Request.Path = path;
            http.Request.RouteValues["id"] = id.ToString();
            var handler = new CaGroupAuthorizationHandler(Service, new HttpContextAccessor { HttpContext = http }, Db, NullLogger<CaGroupAuthorizationHandler>.Instance);
            var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, UserId.ToString())], "test"));
            var context = new AuthorizationHandlerContext([new CaGroupRequirement(capability)], user, null);
            await handler.HandleAsync(context);
            return context.HasSucceeded;
        }
    }

    [Fact]
    public async Task A_requester_may_request_from_the_ca_their_signing_profile_issues_under_and_no_other()
    {
        var w = new World();
        w.Grant(w.CaA, Capabilities.CertRequest);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Allowed(Capabilities.CertRequest, CaTarget.SigningProfile, w.ProfileA.Id));
        Assert.False(await w.Allowed(Capabilities.CertRequest, CaTarget.SigningProfile, w.ProfileB.Id));
        Assert.True(await w.Allowed(Capabilities.CertRequest, CaTarget.SigningProfile, w.ProfileA.Id.ToString())); // bound as text
        Assert.False(await w.Allowed(Capabilities.CertRevoke, CaTarget.SigningProfile, w.ProfileA.Id)); // wrong capability
    }

    [Fact]
    public async Task A_target_naming_nothing_is_refused_not_widened()
    {
        var w = new World();
        w.Grant(w.CaA, Capabilities.CertRequest);
        await w.Db.SaveChangesAsync();

        Assert.False(await w.Allowed(Capabilities.CertRequest, CaTarget.SigningProfile, Guid.NewGuid()));
        Assert.False(await w.Allowed(Capabilities.CertRequest, CaTarget.SigningProfile, "not-a-guid"));
        Assert.False(await w.Allowed(Capabilities.CertRequest, CaTarget.Ca, Guid.NewGuid()));
    }

    [Fact]
    public async Task A_target_attached_to_no_ca_is_a_system_matter()
    {
        var w = new World();
        var systemProfile = w.Profile(null);
        w.Grant(w.CaA, Capabilities.CertRevoke);
        await w.Db.SaveChangesAsync();

        Assert.False(await w.Allowed(Capabilities.CertRevoke, CaTarget.SigningProfile, systemProfile.Id));
        Assert.False(await w.Allowed(Capabilities.CertRevoke, CaTarget.Ca, null)); // "no CA" on a create

        w.Grant(null, Capabilities.CertRevoke); // system scope
        await w.Db.SaveChangesAsync();
        Assert.True(await w.Allowed(Capabilities.CertRevoke, CaTarget.SigningProfile, systemProfile.Id));
        Assert.True(await w.Allowed(Capabilities.CertRevoke, CaTarget.Ca, null));
    }

    [Fact]
    public async Task Any_ca_passes_for_a_holder_anywhere_and_no_one_else()
    {
        var w = new World();
        Assert.False(await w.Allowed(Capabilities.CertView, CaTarget.AnyCa, null));

        w.Grant(w.CaB, Capabilities.CertView);
        await w.Db.SaveChangesAsync();
        Assert.True(await w.Allowed(Capabilities.CertView, CaTarget.AnyCa, null));
        Assert.False(await w.Allowed(Capabilities.CaManage, CaTarget.AnyCa, null));
    }

    [Fact]
    public async Task A_list_of_targets_needs_the_capability_on_every_ca_it_spans()
    {
        var w = new World();
        var onA = w.Cert(w.ProfileA, "0A");
        var onB = w.Cert(w.ProfileB, "0B");
        w.Grant(w.CaA, Capabilities.CertRevoke);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Allowed(Capabilities.CertRevoke, CaTarget.Serials, new List<string> { onA.SerialNumber }));
        Assert.False(await w.Allowed(Capabilities.CertRevoke, CaTarget.Serials, new List<string> { onA.SerialNumber, onB.SerialNumber }));
        Assert.False(await w.Allowed(Capabilities.CertRevoke, CaTarget.Serials, new List<string> { onA.SerialNumber, "does-not-exist" }));
        Assert.True(await w.Allowed(Capabilities.CertRevoke, CaTarget.Certificate, onA.CertificateId));

        // CRL schedule actions carry the schedule id inside an object.
        w.Db.CrlConfigurations.Add(new CrlConfigurationEntity { TaskId = Guid.NewGuid(), CaCertificateId = w.CaA.CertificateId!.Value });
        var crlOnB = new CrlConfigurationEntity { TaskId = Guid.NewGuid(), CaCertificateId = w.CaB.CertificateId!.Value };
        w.Db.CrlConfigurations.Add(crlOnB);
        await w.Db.SaveChangesAsync();
        var crlOnA = w.Db.CrlConfigurations.First(c => c.CaCertificateId == w.CaA.CertificateId);
        Assert.True(await w.Allowed(Capabilities.CertRevoke, CaTarget.CrlConfigurations, new[] { new { Id = crlOnA.TaskId, Action = "run" } }));
        Assert.False(await w.Allowed(Capabilities.CertRevoke, CaTarget.CrlConfigurations, new[] { new { Id = crlOnB.TaskId, Action = "run" } }));
    }

    [Fact]
    public async Task A_global_whitelist_in_a_bulk_list_needs_system_scope()
    {
        var w = new World();
        var scoped = new WhitelistEntity { Id = Guid.NewGuid(), Name = "a", CertificateAuthorityId = w.CaA.Id };
        var global = new WhitelistEntity { Id = Guid.NewGuid(), Name = "g", CertificateAuthorityId = null };
        w.Db.Whitelists.AddRange(scoped, global);
        w.Grant(w.CaA, Capabilities.CertRevoke);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Allowed(Capabilities.CertRevoke, CaTarget.Whitelists, new List<Guid> { scoped.Id }));
        Assert.False(await w.Allowed(Capabilities.CertRevoke, CaTarget.Whitelists, new List<Guid> { scoped.Id, global.Id }));
    }

    [Fact]
    public async Task Id_only_routes_now_resolve_to_their_ca()
    {
        var w = new World();
        var whitelist = new WhitelistEntity { Id = Guid.NewGuid(), Name = "a", CertificateAuthorityId = w.CaA.Id };
        w.Db.Whitelists.Add(whitelist);
        var crl = new CrlConfigurationEntity { TaskId = Guid.NewGuid(), CaCertificateId = w.CaA.CertificateId!.Value };
        w.Db.CrlConfigurations.Add(crl);
        var key = new SshCaKeyEntity { Id = Guid.NewGuid(), Name = "k", CertificateAuthorityId = w.CaB.Id };
        w.Db.SshCaKeys.Add(key);
        var template = new SshCertificateTemplateEntity { Id = Guid.NewGuid(), Name = "t", SshCaKeyId = key.Id, SshSigningProfileId = Guid.NewGuid(), SshCertProfileId = Guid.NewGuid() };
        w.Db.SshCertificateTemplates.Add(template);
        w.Grant(w.CaA, Capabilities.CertRevoke);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.RouteAllowed(Capabilities.CertRevoke, $"/api/v1/admin/whitelists/{whitelist.Id}", whitelist.Id));
        Assert.True(await w.RouteAllowed(Capabilities.CertRevoke, $"/api/v1/admin/crl-schedules/{crl.TaskId}", crl.TaskId));
        Assert.False(await w.RouteAllowed(Capabilities.CertRevoke, $"/api/v1/admin/ssh/templates/{template.Id}", template.Id)); // CA B
        Assert.False(await w.RouteAllowed(Capabilities.CertRevoke, $"/api/v1/admin/whitelists/{Guid.NewGuid()}", Guid.NewGuid()));
    }
}
