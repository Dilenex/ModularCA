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
/// A key ceremony's routes carry the ceremony id, not a CA: the CA does not exist yet. The
/// policy handler resolves the ceremony's space instead, so a space administrator can
/// approve and execute ceremonies for their space while one from another space, or a
/// single-CA administrator, is refused. A ceremony with no space stays a system matter.
/// </summary>
public class CeremonyRouteAuthorizationTests
{
    private static readonly Guid SpaceA = Guid.NewGuid();
    private static readonly Guid SpaceB = Guid.NewGuid();

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public Guid UserId { get; } = Guid.NewGuid();

        public CaGroupEntity Group(Guid spaceId, Guid? caId = null)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"g-{Guid.NewGuid():N}", DisplayName = "g", SpaceId = spaceId, CertificateAuthorityId = caId };
            Db.CaGroups.Add(g);
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = g.Id, UserId = UserId });
            Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = g.Id, Capability = Capabilities.CaManage });
            return g;
        }

        public KeyCeremonyEntity Ceremony(Guid? spaceId)
        {
            var c = new KeyCeremonyEntity { Id = Guid.NewGuid(), OperationType = "CreateIntermediateCA", InitiatedByUserId = Guid.NewGuid(), SpaceId = spaceId, ExpiresAt = DateTime.UtcNow.AddDays(1) };
            Db.KeyCeremonies.Add(c);
            return c;
        }

        /// <summary>Evaluates the CaAdmin policy for <c>POST /api/v1/admin/ceremonies/{id}/approve</c>.</summary>
        public async Task<bool> Allowed(Guid ceremonyId)
        {
            var http = new DefaultHttpContext();
            http.Request.Method = HttpMethods.Post;
            http.Request.Path = $"/api/v1/admin/ceremonies/{ceremonyId}/approve";
            http.Request.RouteValues["id"] = ceremonyId.ToString();
            var accessor = new HttpContextAccessor { HttpContext = http };

            var service = new CaGroupAuthorizationService(Db, NullLogger<CaGroupAuthorizationService>.Instance);
            var handler = new CaGroupAuthorizationHandler(service, accessor, Db, NullLogger<CaGroupAuthorizationHandler>.Instance);
            var requirement = new CaGroupRequirement(Capabilities.CaManage);
            var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, UserId.ToString())], "test"));
            var context = new AuthorizationHandlerContext([requirement], user, null);
            await handler.HandleAsync(context);
            return context.HasSucceeded;
        }
    }

    [Fact]
    public async Task A_space_admin_passes_on_their_own_spaces_ceremony_and_not_on_anothers()
    {
        var w = new World();
        w.Group(SpaceA);
        var own = w.Ceremony(SpaceA);
        var other = w.Ceremony(SpaceB);
        await w.Db.SaveChangesAsync();

        Assert.True(await w.Allowed(own.Id));
        Assert.False(await w.Allowed(other.Id));
    }

    [Fact]
    public async Task A_single_ca_admin_in_the_space_does_not_pass()
    {
        var w = new World();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "A", Label = "ca-a", SpaceId = SpaceA };
        w.Db.CertificateAuthorities.Add(ca);
        w.Group(SpaceA, caId: ca.Id);
        var own = w.Ceremony(SpaceA);
        await w.Db.SaveChangesAsync();

        Assert.False(await w.Allowed(own.Id));
    }

    [Fact]
    public async Task A_ceremony_without_a_space_and_an_unknown_ceremony_stay_closed_to_space_admins()
    {
        var w = new World();
        w.Group(SpaceA);
        var system = w.Ceremony(null);
        await w.Db.SaveChangesAsync();

        Assert.False(await w.Allowed(system.Id));
        Assert.False(await w.Allowed(Guid.NewGuid()));
    }
}
