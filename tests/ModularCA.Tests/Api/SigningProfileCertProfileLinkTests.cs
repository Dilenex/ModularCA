using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.SigningProfiles;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// A signing profile's allowed cert profiles, on create, update and
/// <c>PUT {id}/allowed-cert-profiles</c>: each must be visible to the caller and one the signing
/// profile's issuing CA may issue under (<c>CertProfileScope</c>), and the set endpoint fences the
/// signing profile itself. An instance-wide profile (no space, no CA) links anywhere, as issuance
/// and CA creation admit it under every CA; a profile bound to an instance CA does not.
/// </summary>
public sealed class SigningProfileCertProfileLinkTests
{
    private const string SigningProfiles = "Admin.AdminSigningProfileController";

    /// <summary>A second CA of space A, and a profile of space A bound to it.</summary>
    private static Guid ProfileOfAnotherCaOfA(World w)
    {
        var other = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "a other", Label = "a-other", SpaceId = w.A.SpaceId, Type = "Root", IsEnabled = true };
        var profile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "a-other-bound", SpaceId = w.A.SpaceId, CertificateAuthorityId = other.Id, KeyUsages = "[]", ExtendedKeyUsages = "[]" };
        w.Db.CertificateAuthorities.Add(other);
        w.Db.CertProfiles.Add(profile);
        w.Db.SaveChanges();
        return profile.Id;
    }

    private static Call SetLinks(Guid signingProfile, params Guid[] ids) => Send("PUT", SigningProfiles, "SetAllowedCertProfiles",
        $"/api/v1/admin/signing-profiles/{signingProfile}/allowed-cert-profiles", ("id", signingProfile), ("certProfileIds", ids.ToList()));

    private static List<Guid> Links(World w, Guid signingProfile)
        => w.Db.AllowedCertProfileSigningProfiles.Where(l => l.SigningProfileId == signingProfile).Select(l => l.CertProfileId).ToList();

    [Fact]
    public async Task Set_links_only_profiles_the_caller_sees_and_the_issuing_ca_may_use()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];
        var otherCaOfA = ProfileOfAnotherCaOfA(w);

        Assert.Equal(400, (await SendAsync(w, caX, SetLinks(w.A.SigningProfile, w.B.SpaceProfile))).Status);
        Assert.Equal(400, (await SendAsync(w, caX, SetLinks(w.A.SigningProfile, w.Instance.BoundProfile))).Status);
        Assert.Equal(400, (await SendAsync(w, caX, SetLinks(w.A.SigningProfile, Guid.NewGuid()))).Status);
        var (status, body) = await SendAsync(w, caX, SetLinks(w.A.SigningProfile, w.A.SpaceProfile, otherCaOfA));
        Assert.Equal(400, status);
        Assert.Contains(ErrorCodes.CertProfileOutOfScope, body);
        Assert.Empty(Links(w, w.A.SigningProfile));

        Assert.Equal(204, (await SendAsync(w, caX, SetLinks(w.A.SigningProfile, w.A.SpaceProfile, w.A.BoundProfile, w.UnboundProfile))).Status);
        Assert.Equal(new[] { w.A.SpaceProfile, w.A.BoundProfile, w.UnboundProfile }.OrderBy(i => i), Links(w, w.A.SigningProfile).OrderBy(i => i));
    }

    [Fact]
    public async Task Set_refuses_a_signing_profile_outside_the_fence_even_past_the_policy()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];

        Assert.Equal(404, (await SendAsync(w, caX, SetLinks(w.B.SigningProfile, w.UnboundProfile), skipPolicy: true)).Status);
        Assert.Empty(Links(w, w.B.SigningProfile));
    }

    [Fact]
    public async Task Create_and_update_refuse_links_out_of_the_issuing_cas_scope()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];
        var name = $"new-{Guid.NewGuid():N}";

        Call Create(Guid? issuer, params Guid[] ids) => Send("POST", SigningProfiles, "Create", "/api/v1/admin/signing-profiles",
            ("r", new CreateSigningProfileRequest { Name = name, IssuerId = issuer, AllowedCertProfileIds = ids.ToList() }));
        Call Update(params Guid[] ids) => Send("PUT", SigningProfiles, "Update", $"/api/v1/admin/signing-profiles/{w.A.SigningProfile}",
            ("id", w.A.SigningProfile), ("r", new UpdateSigningProfileRequest { Name = "a-signing", IssuerId = w.A.CaCertId, AllowedCertProfileIds = ids.ToList() }));

        Assert.Equal(400, (await SendAsync(w, caX, Create(w.A.CaCertId, w.B.SpaceProfile))).Status);
        Assert.Equal(400, (await SendAsync(w, caX, Create(w.A.CaCertId, w.Instance.BoundProfile))).Status);
        Assert.False(w.Db.SigningProfiles.Any(p => p.Name == name));
        Assert.Equal(400, (await SendAsync(w, caX, Update(w.B.BoundProfile))).Status);
        Assert.Empty(Links(w, w.A.SigningProfile));

        // An unbound signing profile has no CA: only instance-wide profiles fit it.
        var systemAdmin = w.User("system-admin", w.Group("system-admin", null, null, Capabilities.AdministratorTemplate, system: true));
        Assert.Equal(400, (await SendAsync(w, systemAdmin, Create(null, w.A.SpaceProfile))).Status);
        Assert.Equal(201, (await SendAsync(w, systemAdmin, Create(null, w.UnboundProfile))).Status);

        Assert.Equal(204, (await SendAsync(w, caX, Update(w.A.BoundProfile, w.UnboundProfile))).Status);
        Assert.Equal(2, Links(w, w.A.SigningProfile).Count);
    }
}
