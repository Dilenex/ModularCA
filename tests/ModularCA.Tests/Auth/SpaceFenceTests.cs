using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// What removing the CA filter changed in the resolver's answers (design section 0, owner
/// decisions Q1 and Q2): instance roles see every space's CAs, user-level grants work where only
/// groups did, the fence is built from all four grant sources under a worn badge, and a CA label in
/// a route resolves to one CA and never falls through to "any CA".
/// </summary>
public class SpaceFenceTests
{
    private sealed class World
    {
        public ControlledUserWorld W { get; } = new();
        public Guid InstanceCa { get; } = Guid.NewGuid();

        public World()
        {
            W.Db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = InstanceCa, Name = "Ops SSH", Label = "ops-ssh", TenantId = null, IsSshCa = true });
            W.Db.SaveChanges();
        }

        public CaGroupAuthorizationService Service(Guid? badgeUser = null, Guid? badge = null)
        {
            var http = new DefaultHttpContext();
            if (badge != null)
                http.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", badgeUser.ToString()!), new Claim(AccessBadgeContext.BadgeClaim, badge.Value.ToString())], "test"));
            var accessor = new HttpContextAccessor { HttpContext = http };
            return new CaGroupAuthorizationService(W.Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor, new AccessBadgeContext(W.Db, accessor));
        }
    }

    [Fact]
    public async Task A_system_operator_and_a_system_auditor_get_every_spaces_cas()
    {
        var w = new World();
        var service = w.Service();
        foreach (var user in new[] { w.W.Operator, w.W.Auditor })
        {
            var ids = await service.GetAccessibleCaIdsAsync(user, Capabilities.CertView);
            Assert.Contains(w.W.CaA1, ids);
            Assert.Contains(w.W.CaB1, ids);
            Assert.Contains(w.InstanceCa, ids);
            Assert.Equal([w.W.CaB1], await service.GetAccessibleCaIdsAsync(user, Capabilities.CertView, w.W.TenantB));

            var effective = await service.GetEffectiveCapabilitiesAsync(user);
            Assert.Contains(effective.Cas, c => c.Id == w.W.CaB1 && c.TenantName == "B");
            Assert.Contains(effective.Cas, c => c.Id == w.W.CaA1);

            var fence = await service.GetFenceAsync(user);
            Assert.True(fence.InstanceWideFor(Capabilities.CertView));
            Assert.True(fence.For(Capabilities.CertView).Allows(w.W.TenantB));
            Assert.False(fence.IsSystemAdmin);
        }
    }

    [Fact]
    public async Task A_ca_scoped_user_grant_without_a_group_works_and_fences_to_its_space()
    {
        var w = new World();
        var holder = w.W.User("grant-holder");
        w.W.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = holder, Capability = Capabilities.CertView, CertificateAuthorityId = w.W.CaB1 });
        w.W.Db.SaveChanges();
        var service = w.Service();

        Assert.True(await service.HasCaCapabilityAsync(holder, w.W.CaB1, Capabilities.CertView));
        Assert.False(await service.HasCaCapabilityAsync(holder, w.W.CaA1, Capabilities.CertView));
        Assert.Equal([w.W.CaB1], await service.GetAccessibleCaIdsAsync(holder, Capabilities.CertView));

        var fence = await service.GetFenceAsync(holder);
        Assert.True(fence.Allows(w.W.TenantB));
        Assert.False(fence.Allows(w.W.TenantA));
        Assert.False(fence.Allows(null));
    }

    [Fact]
    public async Task Pending_requests_of_a_user_level_grants_ca_are_listed()
    {
        var w = new World();
        var caCert = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = "01", SubjectDN = "CN=b1", Issuer = "CN=b1", Pem = "x", IsCA = true };
        w.W.Db.Certificates.Add(caCert);
        w.W.Db.CertificateAuthorities.Single(c => c.Id == w.W.CaB1).CertificateId = caCert.CertificateId;
        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "b1-signing", IssuerId = caCert.CertificateId };
        w.W.Db.SigningProfiles.Add(signing);
        var csr = new CertRequestEntity { Id = Guid.NewGuid(), CSR = "x", Subject = "CN=x", Status = "Pending", KeyAlgorithm = "ECDSA", KeySize = "P-256", SignatureAlgorithm = "SHA256withECDSA", SigningProfileId = signing.Id };
        w.W.Db.CertificateRequests.Add(csr);
        var holder = w.W.User("grant-holder");
        w.W.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = holder, Capability = Capabilities.CertView, CertificateAuthorityId = w.W.CaB1 });
        w.W.Db.SaveChanges();

        var ids = await w.Service().GetAccessibleCaIdsAsync(holder, Capabilities.CertView);
        var pending = await new CsrService(w.W.Db, null!).GetPendingRequests(ids);
        Assert.Contains(pending, r => r.RequestId == csr.Id);
    }

    [Fact]
    public async Task Tenant_scoped_grants_and_roles_and_instance_ca_grants_shape_the_fence()
    {
        var w = new World();
        var tenantGrant = w.W.User("tenant-grant");
        w.W.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = tenantGrant, Capability = Capabilities.CertView, TenantId = w.W.TenantA });
        var tenantRole = w.W.User("tenant-role");
        w.W.Db.RoleAssignments.Add(new RoleAssignmentEntity { UserId = tenantRole, RoleId = w.W.Role(Capabilities.CertView).Id, TenantId = w.W.TenantB });
        var instanceGrant = w.W.User("instance-grant");
        w.W.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = instanceGrant, Capability = Capabilities.CertView, CertificateAuthorityId = w.InstanceCa });
        w.W.Db.SaveChanges();
        var service = w.Service();

        Assert.Equal([w.W.TenantA], (await service.GetFenceAsync(tenantGrant)).TenantIds);
        Assert.Equal([w.W.TenantB], (await service.GetFenceAsync(tenantRole)).TenantIds);
        var instance = await service.GetFenceAsync(instanceGrant);
        Assert.True(instance.Allows(null));
        Assert.False(instance.InstanceWide);
        Assert.Empty(instance.TenantIds);
    }

    [Fact]
    public async Task A_worn_badge_narrows_the_fence()
    {
        var w = new World();
        var user = w.W.User("two-spaces", w.W.A1Requester, w.W.B1Requester);
        var badge = new AccessBadgeEntity { UserId = user, Name = "a-only" };
        badge.Sources.Add(new AccessBadgeSourceEntity { BadgeId = badge.Id, Kind = AccessBadgeSourceKind.Group, SourceId = w.W.A1Requester.Id });
        w.W.Db.AccessBadges.Add(badge);
        w.W.Db.SaveChanges();

        Assert.Equal(2, (await w.Service().GetFenceAsync(user)).TenantIds.Count);
        var worn = await w.Service(user, badge.Id).GetFenceAsync(user);
        Assert.Equal([w.W.TenantA], worn.TenantIds);
    }

    /// <summary>
    /// A label route resolves to the one CA that has it, and a deleted CA's label is checked
    /// against that CA, never widened to "holds the capability on any CA".
    /// </summary>
    [Fact]
    public async Task A_label_route_resolves_to_one_ca_and_a_deleted_cas_label_never_falls_through()
    {
        var w = new World();
        w.W.Db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Gone", Label = "gone", TenantId = w.W.TenantA, IsDeleted = true });
        w.W.Db.SaveChanges();

        async Task<bool> Allowed(Guid user, string label)
        {
            var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.ToString())], "test")) };
            http.Request.Method = HttpMethods.Get;
            http.Request.RouteValues["label"] = label;
            var accessor = new HttpContextAccessor { HttpContext = http };
            var service = new CaGroupAuthorizationService(w.W.Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor);
            var handler = new CaGroupAuthorizationHandler(service, accessor, w.W.Db, NullLogger<CaGroupAuthorizationHandler>.Instance);
            var requirement = new CaGroupRequirement(Capabilities.CertRequest);
            var context = new AuthorizationHandlerContext([requirement], http.User, http);
            await handler.HandleAsync(context);
            return context.HasSucceeded;
        }

        Assert.True(await Allowed(w.W.Plain, "a1"));
        Assert.False(await Allowed(w.W.Plain, "b1"));
        Assert.False(await Allowed(w.W.Plain, "gone"));
    }
}
