using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// Deleting a signing, certificate or request profile is fenced as updating it is: a profile of
/// another space is not found (404) and stays, even for a caller the policy let through, while
/// the caller's own space's profile is deleted.
/// </summary>
public sealed class ProfileDeleteFenceTests
{
    private const string Signing = "Admin.AdminSigningProfileController";
    private const string Cert = "Admin.AdminCertProfileController";
    private const string Request = "Admin.AdminRequestProfileController";

    [Theory]
    [InlineData("space admin")]
    [InlineData("CA-X admin")]
    public async Task A_signing_profile_of_another_space_is_not_found(string kind)
    {
        var w = new World();
        var user = w.Users[kind];
        Call Delete(Guid id) => Send("DELETE", Signing, "Delete", $"/api/v1/admin/signing-profiles/{id}", ("id", id));

        Assert.Equal(404, (await SendAsync(w, user, Delete(w.B.SigningProfile), skipPolicy: true)).Status);
        Assert.Contains(w.Db.SigningProfiles, p => p.Id == w.B.SigningProfile);

        var own = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "a-spare", IssuerId = w.A.CaCertId };
        w.Db.SigningProfiles.Add(own);
        w.Db.SaveChanges();
        Assert.Equal(204, (await SendAsync(w, user, Delete(own.Id), skipPolicy: true)).Status);
        Assert.DoesNotContain(w.Db.SigningProfiles, p => p.Id == own.Id);
    }

    [Fact]
    public async Task A_cert_profile_of_another_space_is_not_found()
    {
        var w = new World();
        var user = w.Users["space admin"];
        Call Delete(Guid id) => Send("DELETE", Cert, "Delete", $"/api/v1/admin/cert-profiles/{id}",
            ("id", id), ("mfaToken", w.StepUp(user, StepUpOps.DeleteCertProfile, id)));

        Assert.Equal(404, (await SendAsync(w, user, Delete(w.B.BoundProfile), skipPolicy: true)).Status);
        Assert.Contains(w.Db.CertProfiles, p => p.Id == w.B.BoundProfile);

        var own = new CertProfileEntity { Id = Guid.NewGuid(), Name = "a-spare", SpaceId = w.A.SpaceId, KeyUsages = "[]", ExtendedKeyUsages = "[]" };
        w.Db.CertProfiles.Add(own);
        w.Db.SaveChanges();
        Assert.Equal(204, (await SendAsync(w, user, Delete(own.Id), skipPolicy: true)).Status);
        Assert.DoesNotContain(w.Db.CertProfiles, p => p.Id == own.Id);
    }

    [Fact]
    public async Task A_request_profile_of_another_space_is_not_found()
    {
        var w = new World();
        var user = w.Users["space admin"];
        Call Delete(Guid id) => Send("DELETE", Request, "Delete", $"/api/v1/admin/request-profiles/{id}",
            ("id", id), ("mfaToken", w.StepUp(user, StepUpOps.DeleteRequestProfile, id)));

        Assert.Equal(404, (await SendAsync(w, user, Delete(w.B.RequestProfile), skipPolicy: true)).Status);
        Assert.Contains(w.Db.RequestProfiles, p => p.Id == w.B.RequestProfile);

        Assert.Equal(204, (await SendAsync(w, user, Delete(w.A.RequestProfile), skipPolicy: true)).Status);
        Assert.DoesNotContain(w.Db.RequestProfiles, p => p.Id == w.A.RequestProfile);
    }
}
