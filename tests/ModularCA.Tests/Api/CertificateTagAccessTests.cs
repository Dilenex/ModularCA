using ModularCA.Shared.Entities;
using ModularCA.Tests.Roles;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// Adding and removing a certificate tag need manage access to that certificate
/// (<c>CertificateAccessEvaluator.CanManageCertificate</c>), as export does. The CaOperator policy
/// resolves the CA through the certificate's signing profile, which can name another CA than the
/// one that issued it, so it alone does not pin the certificate down.
/// </summary>
public sealed class CertificateTagAccessTests
{
    private const string Certificates = "Admin.AdminCertificateController";

    /// <summary>
    /// A certificate issued by B's CA whose signing profile is A's (the profile was rebound after
    /// issuance): the policy resolves A's CA, which A's CA admin operates.
    /// </summary>
    private static CertificateEntity IssuedByBUnderAsProfile(World w)
    {
        var id = Guid.NewGuid();
        var cert = new CertificateEntity
        {
            CertificateId = id, SerialNumber = id.ToString("N")[..16].ToUpperInvariant(), SubjectDN = "CN=b.rebound", Issuer = "CN=b root",
            Pem = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----", NotBefore = DateTime.UtcNow.AddDays(-1),
            NotAfter = DateTime.UtcNow.AddYears(1), IssuerCertificateId = w.B.CaCertId, SigningProfileId = w.A.SigningProfile,
        };
        w.Db.Certificates.Add(cert);
        w.Db.SaveChanges();
        return cert;
    }

    private static Guid Tag(World w, Guid certificateId)
    {
        var tag = new CertificateTagEntity { CertificateId = certificateId, Key = "service", Value = "nginx" };
        w.Db.CertificateTags.Add(tag);
        w.Db.SaveChanges();
        return tag.Id;
    }

    private static object TagBody(string key, string value)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.CertificateTagRequest"))!;
        body.GetType().GetProperty("Key")!.SetValue(body, key);
        body.GetType().GetProperty("Value")!.SetValue(body, value);
        return body;
    }

    private static Call Delete(string serial, Guid tagId) => Send("DELETE", Certificates, "RemoveCertificateTag",
        $"/api/v1/admin/certificates/{serial}/tags/{tagId}", ("serial", serial), ("tagId", tagId));

    private static Call Add(string serial, string key) => Send("POST", Certificates, "AddCertificateTag",
        $"/api/v1/admin/certificates/{serial}/tags", ("serial", serial), ("request", TagBody(key, "x")));

    [Fact]
    public async Task A_tag_on_a_certificate_the_caller_cannot_manage_is_neither_removed_nor_added()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];
        var foreign = IssuedByBUnderAsProfile(w);
        var tagId = Tag(w, foreign.CertificateId);

        Assert.Equal(404, (await SendAsync(w, caX, Delete(foreign.SerialNumber, tagId))).Status);
        Assert.Equal(404, (await SendAsync(w, caX, Add(foreign.SerialNumber, "owner"))).Status);
        Assert.True(w.Db.CertificateTags.Any(t => t.Id == tagId));
        Assert.False(w.Db.CertificateTags.Any(t => t.CertificateId == foreign.CertificateId && t.Key == "owner"));

        // Without the policy too: the action itself refuses B's own leaf.
        var bTag = Tag(w, w.B.Cert);
        Assert.Equal(404, (await SendAsync(w, caX, Delete(w.B.CertSerial, bTag), skipPolicy: true)).Status);
        Assert.True(w.Db.CertificateTags.Any(t => t.Id == bTag));
    }

    [Fact]
    public async Task A_tag_on_a_certificate_the_caller_manages_is_added_and_removed()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];

        Assert.Equal(201, (await SendAsync(w, caX, Add(w.A.CertSerial, "owner"))).Status);
        var tagId = w.Db.CertificateTags.Single(t => t.CertificateId == w.A.Cert && t.Key == "owner").Id;
        Assert.Equal(204, (await SendAsync(w, caX, Delete(w.A.CertSerial, tagId))).Status);
        Assert.False(w.Db.CertificateTags.Any(t => t.Id == tagId));
    }
}
