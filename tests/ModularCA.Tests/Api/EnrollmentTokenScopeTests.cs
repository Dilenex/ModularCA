using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// The enrollment credential list follows the console's scope on the server. A space view lists
/// the credentials scoped to that space and those bound to a CA inside it, and a CA view those
/// bound to the CA; neither ever shows a credential the caller's fence keeps from them. Before
/// 0.4.4 the endpoint took no scope and the console narrowed only under a CA scope, so every
/// space showed every credential.
/// </summary>
public sealed class EnrollmentTokenScopeTests
{
    private static Call List(params (string Name, object? Value)[] args)
        => Get("Admin.AdminEnrollmentTokenController", "GetActiveTokens", "/api/v1/admin/enrollment-tokens", args);

    /// <summary>The extra credentials of the scope matrix: one per way a credential can be placed.</summary>
    private sealed record Extra(Guid SpaceOnlyA, Guid CaBoundNoSpaceA, Guid SystemWide, Guid InstanceCa);

    private static EnrollmentTokenEntity Token(string hash, Guid? spaceId, Guid? caId)
        => new() { Id = Guid.NewGuid(), Token = hash, ExpiresAt = DateTime.UtcNow.AddDays(1), MaxUses = 1, UsesRemaining = 1, SpaceId = spaceId, CertificateAuthorityId = caId };

    private static Extra Seed(World w)
    {
        // A credential of space A bound to no CA; one bound to A's CA whose own space column was
        // never filled; one bound to nothing (system-wide); one bound to an instance CA.
        var spaceOnly = Token("hash-space-only", w.A.SpaceId, null);
        var caNoSpace = Token("hash-ca-no-space", null, w.A.CaId);
        var systemWide = Token("hash-system", null, null);
        var instance = Token("hash-instance", null, w.Instance.Root);
        w.Db.EnrollmentTokens.AddRange(spaceOnly, caNoSpace, systemWide, instance);
        w.Db.SaveChanges();
        return new Extra(spaceOnly.Id, caNoSpace.Id, systemWide.Id, instance.Id);
    }

    private static Guid SystemAdmin(World w)
        => w.User("sys-admin", w.Group("system-admin", null, null, Capabilities.AdministratorTemplate, system: true));

    private static void Shows(string body, params Guid[] ids)
    {
        foreach (var id in ids)
            Assert.True(body.Contains(id.ToString(), StringComparison.OrdinalIgnoreCase), $"missing {id}: {body}");
    }

    private static void Hides(string body, params Guid[] ids)
    {
        foreach (var id in ids)
            Assert.False(body.Contains(id.ToString(), StringComparison.OrdinalIgnoreCase), $"leaked {id}: {body}");
    }

    [Fact]
    public async Task Without_a_scope_every_credential_the_fence_admits_is_listed()
    {
        var w = new World();
        var x = Seed(w);
        var (status, body) = await SendAsync(w, SystemAdmin(w), List());
        Assert.Equal(200, status);
        Shows(body, w.A.Token, w.B.Token, x.SpaceOnlyA, x.CaBoundNoSpaceA, x.SystemWide, x.InstanceCa);
    }

    [Fact]
    public async Task A_space_view_lists_the_spaces_credentials_and_those_of_its_CAs()
    {
        var w = new World();
        var x = Seed(w);
        var (status, body) = await SendAsync(w, SystemAdmin(w), List(("spaceId", (Guid?)w.A.SpaceId)));
        Assert.Equal(200, status);
        Shows(body, w.A.Token, x.SpaceOnlyA, x.CaBoundNoSpaceA);
        Hides(body, w.B.Token, x.SystemWide, x.InstanceCa);
    }

    [Fact]
    public async Task A_CA_view_lists_only_the_credentials_bound_to_that_CA()
    {
        var w = new World();
        var x = Seed(w);
        var (status, body) = await SendAsync(w, SystemAdmin(w), List(("caId", (Guid?)w.A.CaId)));
        Assert.Equal(200, status);
        Shows(body, w.A.Token, x.CaBoundNoSpaceA);
        Hides(body, w.B.Token, x.SpaceOnlyA, x.SystemWide, x.InstanceCa);
    }

    /// <summary>The scope only narrows: naming another space opens none of it.</summary>
    [Theory]
    [InlineData("space admin")]
    [InlineData("space operator")]
    [InlineData("CA-X admin")]
    public async Task Naming_another_space_shows_none_of_its_credentials(string who)
    {
        var w = new World();
        var x = Seed(w);
        var user = w.Users[who];

        var (ownStatus, own) = await SendAsync(w, user, List(("spaceId", (Guid?)w.A.SpaceId)));
        Assert.Equal(200, ownStatus);
        Shows(own, w.A.Token);
        Hides(own, w.B.Token, x.SystemWide, x.InstanceCa);

        var (status, other) = await SendAsync(w, user, List(("spaceId", (Guid?)w.B.SpaceId)));
        Assert.True(status is 200 or 403, $"{who} answered {status}");
        Hides(other, w.A.Token, w.B.Token, x.SpaceOnlyA, x.CaBoundNoSpaceA, x.SystemWide, x.InstanceCa);
    }
}
