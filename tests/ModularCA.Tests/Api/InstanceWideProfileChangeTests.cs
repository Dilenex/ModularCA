using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Models.SigningProfiles;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// An instance-wide certificate profile (no space, no CA), an unbound signing profile and an
/// unbound request profile apply to every space, so updating or deleting one needs the capability
/// creating one needs, at system scope: a space admin is refused with 403 even past the policy and
/// the row is unchanged, while their own space's and CA's profiles stay theirs to change, and a
/// system admin may change the instance-wide ones.
/// </summary>
public sealed class InstanceWideProfileChangeTests
{
    private const string Cert = "Admin.AdminCertProfileController";
    private const string Signing = "Admin.AdminSigningProfileController";
    private const string Request = "Admin.AdminRequestProfileController";

    private static Guid SystemAdmin(World w)
        => w.User($"system-admin-{Guid.NewGuid():N}", w.Group($"system-admin-{Guid.NewGuid():N}", null, null, Capabilities.AdministratorTemplate, system: true));

    [Fact]
    public async Task An_instance_wide_cert_profile_needs_system_scope_to_update_or_delete()
    {
        var w = new World();
        var spaceAdmin = w.Users["space admin"];
        Call Update(Guid user, Guid id, string name) => Send("PUT", Cert, "Update", $"/api/v1/admin/cert-profiles/{id}",
            ("id", id), ("request", new UpdateCertProfileRequest { Name = name, KeyUsages = "[]", ExtendedKeyUsages = "[]" }),
            ("mfaToken", w.StepUp(user, StepUpOps.UpdateCertProfile, id)));
        Call Delete(Guid user, Guid id) => Send("DELETE", Cert, "Delete", $"/api/v1/admin/cert-profiles/{id}",
            ("id", id), ("mfaToken", w.StepUp(user, StepUpOps.DeleteCertProfile, id)));

        Assert.Equal(403, (await SendAsync(w, spaceAdmin, Update(spaceAdmin, w.UnboundProfile, "renamed"), skipPolicy: true)).Status);
        Assert.Equal(403, (await SendAsync(w, spaceAdmin, Delete(spaceAdmin, w.UnboundProfile), skipPolicy: true)).Status);
        Assert.Equal("unbound", w.Db.CertProfiles.Single(p => p.Id == w.UnboundProfile).Name);

        var own = new CertProfileEntity { Id = Guid.NewGuid(), Name = "a-own", SpaceId = w.A.SpaceId, KeyUsages = "[]", ExtendedKeyUsages = "[]" };
        w.Db.CertProfiles.Add(own);
        w.Db.SaveChanges();
        Assert.Equal(204, (await SendAsync(w, spaceAdmin, Update(spaceAdmin, own.Id, "a-own-renamed"), skipPolicy: true)).Status);
        Assert.Equal(204, (await SendAsync(w, spaceAdmin, Delete(spaceAdmin, own.Id), skipPolicy: true)).Status);

        var admin = SystemAdmin(w);
        Assert.Equal(204, (await SendAsync(w, admin, Update(admin, w.UnboundProfile, "renamed"))).Status);
        Assert.Equal(204, (await SendAsync(w, admin, Delete(admin, w.UnboundProfile))).Status);
    }

    [Fact]
    public async Task An_unbound_signing_profile_needs_system_scope_to_update_delete_or_relink()
    {
        var w = new World();
        var spaceAdmin = w.Users["space admin"];
        var unbound = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "unbound-signing" };
        w.Db.SigningProfiles.Add(unbound);
        w.Db.SaveChanges();
        Call Update(Guid id, string name, Guid? issuer) => Send("PUT", Signing, "Update", $"/api/v1/admin/signing-profiles/{id}",
            ("id", id), ("r", new UpdateSigningProfileRequest { Name = name, IssuerId = issuer }));
        Call Links(Guid id) => Send("PUT", Signing, "SetAllowedCertProfiles", $"/api/v1/admin/signing-profiles/{id}/allowed-cert-profiles",
            ("id", id), ("certProfileIds", new List<Guid> { w.UnboundProfile }));
        Call Delete(Guid id) => Send("DELETE", Signing, "Delete", $"/api/v1/admin/signing-profiles/{id}", ("id", id));

        Assert.Equal(403, (await SendAsync(w, spaceAdmin, Update(unbound.Id, "renamed", null), skipPolicy: true)).Status);
        Assert.Equal(403, (await SendAsync(w, spaceAdmin, Links(unbound.Id), skipPolicy: true)).Status);
        Assert.Equal(403, (await SendAsync(w, spaceAdmin, Delete(unbound.Id), skipPolicy: true)).Status);
        Assert.Equal("unbound-signing", w.Db.SigningProfiles.Single(p => p.Id == unbound.Id).Name);

        Assert.Equal(204, (await SendAsync(w, spaceAdmin, Update(w.A.SigningProfile, "a-signing-renamed", w.A.CaCertId), skipPolicy: true)).Status);

        var admin = SystemAdmin(w);
        Assert.Equal(204, (await SendAsync(w, admin, Update(unbound.Id, "renamed", null))).Status);
        Assert.Equal(204, (await SendAsync(w, admin, Delete(unbound.Id))).Status);
    }

    [Fact]
    public async Task An_unbound_request_profile_needs_system_scope_to_update_or_delete()
    {
        var w = new World();
        var spaceAdmin = w.Users["space admin"];
        var unbound = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "unbound-request" };
        w.Db.RequestProfiles.Add(unbound);
        w.Db.SaveChanges();
        Call Update(Guid user, Guid id, string name, Guid? caId) => Send("PUT", Request, "Update", $"/api/v1/admin/request-profiles/{id}",
            ("id", id), ("request", new UpdateRequestProfileRequest { Name = name, CertificateAuthorityId = caId }),
            ("mfaToken", w.StepUp(user, StepUpOps.UpdateRequestProfile, id)));
        Call Delete(Guid user, Guid id) => Send("DELETE", Request, "Delete", $"/api/v1/admin/request-profiles/{id}",
            ("id", id), ("mfaToken", w.StepUp(user, StepUpOps.DeleteRequestProfile, id)));

        Assert.Equal(403, (await SendAsync(w, spaceAdmin, Update(spaceAdmin, unbound.Id, "renamed", null), skipPolicy: true)).Status);
        Assert.Equal(403, (await SendAsync(w, spaceAdmin, Delete(spaceAdmin, unbound.Id), skipPolicy: true)).Status);
        Assert.Equal("unbound-request", w.Db.RequestProfiles.Single(p => p.Id == unbound.Id).Name);

        Assert.Equal(200, (await SendAsync(w, spaceAdmin, Update(spaceAdmin, w.A.RequestProfile, "a-request-renamed", w.A.CaId), skipPolicy: true)).Status);
        Assert.Equal(204, (await SendAsync(w, spaceAdmin, Delete(spaceAdmin, w.A.RequestProfile), skipPolicy: true)).Status);

        var admin = SystemAdmin(w);
        Assert.Equal(200, (await SendAsync(w, admin, Update(admin, unbound.Id, "renamed", null))).Status);
        Assert.Equal(204, (await SendAsync(w, admin, Delete(admin, unbound.Id))).Status);
    }
}
