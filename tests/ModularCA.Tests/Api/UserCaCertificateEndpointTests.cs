using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The user portal's <c>/api/v1/user/authorities/{serial}</c> and <c>/{serial}/file</c> serve the
/// certificates of CAs the caller can see, and nothing else. The file endpoint used to refuse every
/// CA certificate, so a space-scoped caller always got 404 and an instance-wide caller could fetch
/// leaf certificates through it; the details endpoint served any certificate to an instance-wide caller.
/// </summary>
public sealed class UserCaCertificateEndpointTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.User.UserCaController";

    private sealed record World(CertificateEntity CaCert, CertificateEntity Leaf, CertificateEntity OtherSpaceCaCert, Guid Space);

    private static CertificateEntity Entity(X509Certificate2 cert, bool isCa) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = cert.SerialNumber,
        Pem = cert.ExportCertificatePem(),
        SubjectDN = cert.Subject,
        Issuer = cert.Issuer,
        NotBefore = cert.NotBefore.ToUniversalTime(),
        NotAfter = cert.NotAfter.ToUniversalTime(),
        IsCA = isCa,
    };

    private static X509Certificate2 SelfSignedCa(string cn)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(cn, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static World Seed(ModularCADbContext db)
    {
        using var root = SelfSignedCa("CN=Portal Root");
        using var other = SelfSignedCa("CN=Other Space Root");
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=portal-leaf.example", leafKey, HashAlgorithmName.SHA256);
        using var leaf = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), new byte[] { 7, 7 });

        var space = Guid.NewGuid();
        var caCert = Entity(root, isCa: true);
        var otherCert = Entity(other, isCa: true);
        var leafCert = Entity(leaf, isCa: false);
        leafCert.IssuerCertificateId = caCert.CertificateId;
        db.Certificates.AddRange(caCert, otherCert, leafCert);
        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Portal", Label = "portal", SpaceId = space, CertificateId = caCert.CertificateId },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Other", Label = "other", SpaceId = Guid.NewGuid(), CertificateId = otherCert.CertificateId });
        db.SaveChanges();
        return new World(caCert, leafCert, otherCert, space);
    }

    private static object Controller(ModularCADbContext db, SpaceFence fence)
    {
        var controller = (ControllerBase)Activator.CreateInstance(ApiAssembly.TypeNamed(ControllerName), new CertificateStore(db), db)!;
        var http = new DefaultHttpContext();
        http.Request.Headers.Accept = "application/x-pem-file";
        SpaceFence.Store(http, fence);
        controller.ControllerContext = new ControllerContext { HttpContext = http };
        return controller;
    }

    private static SpaceFence InstanceWide() => SpaceFence.Of([], instanceScope: true, isSystemAdmin: true);

    private static SpaceFence InSpace(Guid space) => SpaceFence.Of([space], instanceScope: false);

    private static async Task<IActionResult> FileAsync(object controller, string serial)
        => await (Task<IActionResult>)controller.GetType().GetMethod("GetCertificate")!.Invoke(controller, [serial])!;

    private static async Task<ActionResult<CertificateInfoModel>> InfoAsync(object controller, string serial)
        => await (Task<ActionResult<CertificateInfoModel>>)controller.GetType().GetMethod("GetCertificateInfo")!.Invoke(controller, [serial])!;

    [Fact]
    public async Task A_space_caller_downloads_the_certificate_of_a_ca_in_their_space()
    {
        using var db = InMemoryDbContextFactory.Create();
        var w = Seed(db);

        var file = Assert.IsType<FileContentResult>(await FileAsync(Controller(db, InSpace(w.Space)), w.CaCert.SerialNumber));

        Assert.Equal("application/x-pem-file", file.ContentType);
        Assert.Equal(w.CaCert.Pem, System.Text.Encoding.UTF8.GetString(file.FileContents));
    }

    [Fact]
    public async Task A_space_caller_gets_404_for_a_leaf_and_for_another_spaces_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var w = Seed(db);
        var controller = Controller(db, InSpace(w.Space));

        Assert.IsType<NotFoundResult>(await FileAsync(controller, w.Leaf.SerialNumber));
        Assert.IsType<NotFoundResult>(await FileAsync(controller, w.OtherSpaceCaCert.SerialNumber));
        Assert.IsType<NotFoundResult>((await InfoAsync(controller, w.Leaf.SerialNumber)).Result);
        Assert.IsType<NotFoundResult>((await InfoAsync(controller, w.OtherSpaceCaCert.SerialNumber)).Result);
    }

    [Fact]
    public async Task A_space_caller_gets_details_of_a_ca_in_their_space()
    {
        using var db = InMemoryDbContextFactory.Create();
        var w = Seed(db);

        var ok = Assert.IsType<OkObjectResult>((await InfoAsync(Controller(db, InSpace(w.Space)), w.CaCert.SerialNumber)).Result);
        Assert.Equal(w.CaCert.CertificateId, Assert.IsType<CertificateInfoModel>(ok.Value).CertificateId);
    }

    [Fact]
    public async Task An_instance_wide_caller_downloads_any_ca_certificate_as_pem_or_der()
    {
        using var db = InMemoryDbContextFactory.Create();
        var w = Seed(db);

        Assert.IsType<FileContentResult>(await FileAsync(Controller(db, InstanceWide()), w.OtherSpaceCaCert.SerialNumber));

        var der = Controller(db, InstanceWide());
        ((ControllerBase)der).HttpContext.Request.Headers.Accept = "application/pkix-cert";
        var file = Assert.IsType<FileContentResult>(await FileAsync(der, w.CaCert.SerialNumber));
        using var parsed = X509CertificateLoader.LoadCertificate(file.FileContents);
        Assert.Equal(w.CaCert.SerialNumber, parsed.SerialNumber);
    }

    [Fact]
    public async Task An_instance_wide_caller_cannot_fetch_a_leaf_through_the_authorities_route()
    {
        using var db = InMemoryDbContextFactory.Create();
        var w = Seed(db);
        var controller = Controller(db, InstanceWide());

        Assert.IsType<NotFoundResult>(await FileAsync(controller, w.Leaf.SerialNumber));
        Assert.IsType<NotFoundResult>((await InfoAsync(controller, w.Leaf.SerialNumber)).Result);
    }

    [Fact]
    public async Task An_instance_wide_caller_gets_details_of_any_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var w = Seed(db);

        Assert.IsType<OkObjectResult>((await InfoAsync(Controller(db, InstanceWide()), w.OtherSpaceCaCert.SerialNumber)).Result);
    }
}
