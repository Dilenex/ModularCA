using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// The Signing Profiles and Request Profiles lists and the SSH signing, cert and request profile
/// lists follow the console's scope on the server, by the rules the console applies client-side
/// (<c>rowsInScope</c> with <c>keepUnbound</c>, and the SSH sentence under a space scope):
/// a CA view keeps the rows of that CA and the rows that name no CA; a space view keeps the
/// signing and request profiles of the space's CAs and the unbound ones, and no SSH row at all,
/// since SSH belongs to the instance. The view is applied after the caller's fence, so it only
/// narrows.
/// </summary>
public sealed class ProfileListScopeTests
{
    private static Call SigningProfiles(params (string Name, object? Value)[] args)
        => Get("Admin.AdminSigningProfileController", "GetAll", "/api/v1/admin/signing-profiles", args);

    private static Call RequestProfiles(params (string Name, object? Value)[] args)
        => Get("Admin.AdminRequestProfileController", "GetAll", "/api/v1/admin/request-profiles", args);

    private static Call SshSigning(params (string Name, object? Value)[] args)
        => Get("Admin.AdminSshProfileController", "GetSigningProfiles", "/api/v1/admin/ssh/profiles/signing", args);

    private static Call SshCert(params (string Name, object? Value)[] args)
        => Get("Admin.AdminSshProfileController", "GetCertProfiles", "/api/v1/admin/ssh/profiles/cert", args);

    private static Call SshRequest(params (string Name, object? Value)[] args)
        => Get("Admin.AdminSshProfileController", "GetRequestProfiles", "/api/v1/admin/ssh/profiles/request", args);

    /// <summary>The extra rows: one per way a profile can be placed that the matrix world does not already hold.</summary>
    private sealed record Extra(
        Guid UnboundRequest, Guid InstanceCaRequest,
        Guid OtherSshCa, Guid UnboundSshSigning, Guid OtherSshSigning,
        Guid SshCert, Guid UnboundSshRequest, Guid OtherSshRequest);

    private static Extra Seed(World w)
    {
        var unboundRequest = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "unbound-request", CertificateAuthorityId = null };
        var instanceRequest = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "instance-request", CertificateAuthorityId = w.Instance.Root };
        w.Db.RequestProfiles.AddRange(unboundRequest, instanceRequest);

        // A second SSH CA, so a CA view has something to leave out.
        var otherCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Lab SSH", Label = "lab-ssh", SpaceId = null, IsSshCa = true, Type = "SSH", IsEnabled = true };
        w.Db.CertificateAuthorities.Add(otherCa);
        var otherKey = new SshCaKeyEntity { Id = Guid.NewGuid(), Name = "Lab SSH", KeyType = "ed25519", PublicKey = "ssh-ed25519 BBBB", PrivateKeyPath = "y", CertificateAuthorityId = otherCa.Id, IsUserCa = true, MaxValidityHours = 24, IsEnabled = true };
        w.Db.SshCaKeys.Add(otherKey);
        var unboundSigning = new SshSigningProfileEntity { Id = Guid.NewGuid(), Name = "ssh-signing-unbound", SshCaKeyId = null, SourceAddressRestrictions = "[]", DefaultExtensions = "[]" };
        var otherSigning = new SshSigningProfileEntity { Id = Guid.NewGuid(), Name = "ssh-signing-lab", SshCaKeyId = otherKey.Id, SourceAddressRestrictions = "[]", DefaultExtensions = "[]" };
        w.Db.SshSigningProfiles.AddRange(unboundSigning, otherSigning);
        var unboundSshRequest = new SshRequestProfileEntity { Id = Guid.NewGuid(), Name = "ssh-request-unbound", AllowedSshSigningProfileIds = "[]", AllowedSshCertProfileIds = "[]", CertificateAuthorityId = null };
        var otherSshRequest = new SshRequestProfileEntity { Id = Guid.NewGuid(), Name = "ssh-request-lab", AllowedSshSigningProfileIds = "[]", AllowedSshCertProfileIds = "[]", CertificateAuthorityId = otherCa.Id };
        w.Db.SshRequestProfiles.AddRange(unboundSshRequest, otherSshRequest);
        w.Db.SaveChanges();

        return new Extra(unboundRequest.Id, instanceRequest.Id, otherCa.Id, unboundSigning.Id, otherSigning.Id,
            w.Db.SshCertProfiles.Single().Id, unboundSshRequest.Id, otherSshRequest.Id);
    }

    private static Guid SystemAdmin(World w)
        => w.User("sys-admin", w.Group("system-admin", null, null, Capabilities.AdministratorTemplate, system: true));

    private static async Task<string> ListAsync(World w, Guid user, Call call)
    {
        var (status, body) = await SendAsync(w, user, call);
        Assert.Equal(200, status);
        return body;
    }

    private static void Shows(string body, params Guid[] ids)
    {
        foreach (var id in ids)
            Assert.True(body.Contains(id.ToString(), StringComparison.OrdinalIgnoreCase), $"missing {id}: {body}");
    }

    private static void Hides(string body, params Guid[] ids)
    {
        foreach (var id in ids)
            Assert.False(body.Contains(id.ToString(), StringComparison.OrdinalIgnoreCase), $"listed {id}: {body}");
    }

    // ── Request profiles ────────────────────────────────────────────────

    [Fact]
    public async Task Without_a_view_every_request_profile_the_fence_admits_is_listed()
    {
        var w = new World();
        var x = Seed(w);
        var body = await ListAsync(w, SystemAdmin(w), RequestProfiles());
        Shows(body, w.A.RequestProfile, w.B.RequestProfile, x.UnboundRequest, x.InstanceCaRequest);
    }

    [Fact]
    public async Task A_CA_view_lists_that_CAs_request_profiles_and_the_unbound_ones()
    {
        var w = new World();
        var x = Seed(w);
        var body = await ListAsync(w, SystemAdmin(w), RequestProfiles(("caId", (Guid?)w.A.CaId)));
        Shows(body, w.A.RequestProfile, x.UnboundRequest);
        Hides(body, w.B.RequestProfile, x.InstanceCaRequest);
    }

    [Fact]
    public async Task A_space_view_lists_the_request_profiles_of_its_CAs_and_the_unbound_ones()
    {
        var w = new World();
        var x = Seed(w);
        var body = await ListAsync(w, SystemAdmin(w), RequestProfiles(("spaceId", (Guid?)w.A.SpaceId)));
        Shows(body, w.A.RequestProfile, x.UnboundRequest);
        Hides(body, w.B.RequestProfile, x.InstanceCaRequest);
    }

    [Fact]
    public async Task A_CA_view_and_a_space_view_together_keep_what_is_in_both()
    {
        var w = new World();
        var x = Seed(w);
        var body = await ListAsync(w, SystemAdmin(w), RequestProfiles(("caId", (Guid?)w.B.CaId), ("spaceId", (Guid?)w.A.SpaceId)));
        Shows(body, x.UnboundRequest);
        Hides(body, w.A.RequestProfile, w.B.RequestProfile, x.InstanceCaRequest);
    }

    [Fact]
    public async Task A_request_profile_of_a_deleted_CA_is_in_no_space_view()
    {
        var w = new World();
        var x = Seed(w);
        var ca = w.Db.CertificateAuthorities.Single(c => c.Id == w.A.CaId);
        ca.IsDeleted = true;
        w.Db.SaveChanges();

        var body = await ListAsync(w, SystemAdmin(w), RequestProfiles(("spaceId", (Guid?)w.A.SpaceId)));
        Shows(body, x.UnboundRequest);
        Hides(body, w.A.RequestProfile, w.B.RequestProfile, x.InstanceCaRequest);
    }

    /// <summary>The view only narrows: naming another space, or another space's CA, opens none of it.</summary>
    [Theory]
    [InlineData("space admin")]
    [InlineData("space operator")]
    [InlineData("CA-X admin")]
    public async Task Naming_another_space_shows_none_of_its_request_profiles(string who)
    {
        var w = new World();
        var x = Seed(w);
        var user = w.Users[who];

        var unscoped = await ListAsync(w, user, RequestProfiles());
        Hides(unscoped, w.B.RequestProfile, x.InstanceCaRequest);

        foreach (var call in new[] { RequestProfiles(("spaceId", (Guid?)w.B.SpaceId)), RequestProfiles(("caId", (Guid?)w.B.CaId)) })
        {
            var (status, body) = await SendAsync(w, user, call);
            Assert.True(status is 200 or 403, $"{who} answered {status}");
            Hides(body, w.A.RequestProfile, w.B.RequestProfile, x.InstanceCaRequest);
        }

        // Its own space's view shows nothing the unscoped list did not.
        var own = await ListAsync(w, user, RequestProfiles(("spaceId", (Guid?)w.A.SpaceId)));
        Hides(own, w.B.RequestProfile, x.InstanceCaRequest);
        if (unscoped.Contains(w.A.RequestProfile.ToString(), StringComparison.OrdinalIgnoreCase))
            Shows(own, w.A.RequestProfile);
        else
            Hides(own, w.A.RequestProfile);
    }

    // ── Signing profiles ────────────────────────────────────────────────

    /// <summary>The signing profiles the matrix world does not hold: no issuer, an instance CA's, one naming its CA by the CA's id, and one whose issuer is no CA.</summary>
    private sealed record Signing(Guid Unbound, Guid InstanceCa, Guid ByCaId, Guid Orphan);

    private static Signing SeedSigning(World w)
    {
        var unbound = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "signing-unbound", IssuerId = null };
        var instance = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "signing-instance", IssuerId = w.Instance.RootCert };
        // The console resolves an issuer against a CA's certificate id or its own id; so does the view.
        var byCaId = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "signing-by-ca-id", IssuerId = w.A.CaId };
        var orphan = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "signing-orphan", IssuerId = Guid.NewGuid() };
        w.Db.SigningProfiles.AddRange(unbound, instance, byCaId, orphan);
        w.Db.SaveChanges();
        return new Signing(unbound.Id, instance.Id, byCaId.Id, orphan.Id);
    }

    [Fact]
    public async Task Without_a_view_every_signing_profile_the_fence_admits_is_listed()
    {
        var w = new World();
        var s = SeedSigning(w);
        var body = await ListAsync(w, SystemAdmin(w), SigningProfiles());
        Shows(body, w.A.SigningProfile, w.B.SigningProfile, s.Unbound, s.InstanceCa, s.ByCaId, s.Orphan);
    }

    [Fact]
    public async Task A_CA_view_lists_the_signing_profiles_that_CA_issues_and_the_ones_with_no_issuer()
    {
        var w = new World();
        var s = SeedSigning(w);
        var body = await ListAsync(w, SystemAdmin(w), SigningProfiles(("caId", (Guid?)w.A.CaId)));
        Shows(body, w.A.SigningProfile, s.ByCaId, s.Unbound);
        Hides(body, w.B.SigningProfile, s.InstanceCa, s.Orphan);

        // An instance CA has a view too.
        body = await ListAsync(w, SystemAdmin(w), SigningProfiles(("caId", (Guid?)w.Instance.Root)));
        Shows(body, s.InstanceCa, s.Unbound);
        Hides(body, w.A.SigningProfile, w.B.SigningProfile, s.ByCaId, s.Orphan);
    }

    [Fact]
    public async Task A_space_view_lists_the_signing_profiles_of_its_CAs_and_the_ones_with_no_issuer()
    {
        var w = new World();
        var s = SeedSigning(w);
        var body = await ListAsync(w, SystemAdmin(w), SigningProfiles(("spaceId", (Guid?)w.A.SpaceId)));
        Shows(body, w.A.SigningProfile, s.ByCaId, s.Unbound);
        Hides(body, w.B.SigningProfile, s.InstanceCa, s.Orphan);
    }

    [Fact]
    public async Task A_CA_view_and_a_space_view_together_keep_the_signing_profiles_in_both()
    {
        var w = new World();
        var s = SeedSigning(w);
        var body = await ListAsync(w, SystemAdmin(w), SigningProfiles(("caId", (Guid?)w.B.CaId), ("spaceId", (Guid?)w.A.SpaceId)));
        Shows(body, s.Unbound);
        Hides(body, w.A.SigningProfile, w.B.SigningProfile, s.InstanceCa, s.ByCaId, s.Orphan);
    }

    [Fact]
    public async Task A_signing_profile_of_a_deleted_CA_is_in_no_view()
    {
        var w = new World();
        var s = SeedSigning(w);
        var ca = w.Db.CertificateAuthorities.Single(c => c.Id == w.A.CaId);
        ca.IsDeleted = true;
        w.Db.SaveChanges();

        foreach (var view in new[] { ("spaceId", (object?)(Guid?)w.A.SpaceId), ("caId", (object?)(Guid?)w.A.CaId) })
        {
            var body = await ListAsync(w, SystemAdmin(w), SigningProfiles(view));
            Shows(body, s.Unbound);
            Hides(body, w.A.SigningProfile, w.B.SigningProfile, s.InstanceCa, s.ByCaId, s.Orphan);
        }
    }

    /// <summary>The view only narrows: naming another space, another space's CA or an instance CA opens none of it.</summary>
    [Theory]
    [InlineData("space admin")]
    [InlineData("space operator")]
    [InlineData("CA-X admin")]
    public async Task Naming_another_space_shows_none_of_its_signing_profiles(string who)
    {
        var w = new World();
        var s = SeedSigning(w);
        var user = w.Users[who];

        var (unscopedStatus, unscoped) = await SendAsync(w, user, SigningProfiles());
        Assert.True(unscopedStatus is 200 or 403, $"{who} answered {unscopedStatus}");
        Hides(unscoped, w.B.SigningProfile, s.InstanceCa, s.Orphan);

        foreach (var call in new[] { SigningProfiles(("spaceId", (Guid?)w.B.SpaceId)), SigningProfiles(("caId", (Guid?)w.B.CaId)), SigningProfiles(("caId", (Guid?)w.Instance.Root)) })
        {
            var (status, body) = await SendAsync(w, user, call);
            Assert.True(status is 200 or 403, $"{who} answered {status}");
            Hides(body, w.A.SigningProfile, w.B.SigningProfile, s.InstanceCa, s.ByCaId, s.Orphan);
        }

        // Its own space's view shows nothing the unscoped list did not, and all of the space's that it did.
        var (ownStatus, own) = await SendAsync(w, user, SigningProfiles(("spaceId", (Guid?)w.A.SpaceId)));
        Assert.Equal(unscopedStatus, ownStatus);
        Hides(own, w.B.SigningProfile, s.InstanceCa, s.Orphan);
        foreach (var id in new[] { w.A.SigningProfile, s.Unbound })
        {
            if (unscoped.Contains(id.ToString(), StringComparison.OrdinalIgnoreCase))
                Shows(own, id);
            else
                Hides(own, id);
        }
    }

    // ── SSH profiles ────────────────────────────────────────────────────

    [Fact]
    public async Task Without_a_view_every_SSH_profile_is_listed()
    {
        var w = new World();
        var x = Seed(w);
        var admin = SystemAdmin(w);
        Shows(await ListAsync(w, admin, SshSigning()), w.Instance.SshSigningProfile, x.UnboundSshSigning, x.OtherSshSigning);
        Shows(await ListAsync(w, admin, SshCert()), x.SshCert);
        Shows(await ListAsync(w, admin, SshRequest()), w.Instance.SshRequestProfile, x.UnboundSshRequest, x.OtherSshRequest);
    }

    [Fact]
    public async Task A_CA_view_lists_that_SSH_CAs_profiles_the_unbound_ones_and_every_cert_profile()
    {
        var w = new World();
        var x = Seed(w);
        var admin = SystemAdmin(w);
        var view = ("caId", (object?)(Guid?)w.Instance.SshCa);

        var signing = await ListAsync(w, admin, SshSigning(view));
        Shows(signing, w.Instance.SshSigningProfile, x.UnboundSshSigning);
        Hides(signing, x.OtherSshSigning);

        Shows(await ListAsync(w, admin, SshCert(view)), x.SshCert);

        var request = await ListAsync(w, admin, SshRequest(view));
        Shows(request, w.Instance.SshRequestProfile, x.UnboundSshRequest);
        Hides(request, x.OtherSshRequest);
    }

    /// <summary>An X.509 CA signs no SSH: its view keeps only what names no CA, as the console's does.</summary>
    [Fact]
    public async Task The_view_of_a_CA_that_is_not_an_SSH_CA_lists_only_the_rows_that_name_no_CA()
    {
        var w = new World();
        var x = Seed(w);
        var admin = SystemAdmin(w);
        var view = ("caId", (object?)(Guid?)w.A.CaId);

        var signing = await ListAsync(w, admin, SshSigning(view));
        Shows(signing, x.UnboundSshSigning);
        Hides(signing, w.Instance.SshSigningProfile, x.OtherSshSigning);

        Shows(await ListAsync(w, admin, SshCert(view)), x.SshCert);

        var request = await ListAsync(w, admin, SshRequest(view));
        Shows(request, x.UnboundSshRequest);
        Hides(request, w.Instance.SshRequestProfile, x.OtherSshRequest);
    }

    /// <summary>SSH belongs to the instance, so a space holds none of it: the console shows a sentence, the server an empty list.</summary>
    [Fact]
    public async Task A_space_view_lists_no_SSH_profile()
    {
        var w = new World();
        Seed(w);
        var admin = SystemAdmin(w);
        var view = ("spaceId", (object?)(Guid?)w.A.SpaceId);

        Assert.Equal("[]", await ListAsync(w, admin, SshSigning(view)));
        Assert.Equal("[]", await ListAsync(w, admin, SshCert(view)));
        Assert.Equal("[]", await ListAsync(w, admin, SshRequest(view)));
    }

    /// <summary>The view only narrows: a caller the fence shows no SSH profile gets none by naming the SSH CA.</summary>
    [Theory]
    [InlineData("space admin")]
    [InlineData("space operator")]
    [InlineData("CA-X admin")]
    public async Task Naming_the_SSH_CA_shows_a_space_user_none_of_its_profiles(string who)
    {
        var w = new World();
        var x = Seed(w);
        var user = w.Users[who];
        var view = ("caId", (object?)(Guid?)w.Instance.SshCa);

        foreach (var call in new[] { SshSigning(view), SshRequest(view), SshSigning(), SshRequest() })
        {
            var (status, body) = await SendAsync(w, user, call);
            Assert.True(status is 200 or 403, $"{who} answered {status}");
            Hides(body, w.Instance.SshSigningProfile, x.UnboundSshSigning, x.OtherSshSigning,
                w.Instance.SshRequestProfile, x.UnboundSshRequest, x.OtherSshRequest);
        }
    }
}
