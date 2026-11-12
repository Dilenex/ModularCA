using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>POST /api/v1/admin/certificates/{serial}/export</c> exports the public certificate as PEM,
/// DER or PKCS#7, with the issuer chain when asked. It used to answer 400 for every format once the
/// caller was authorised, and never read <c>IncludeChain</c>. PKCS#12 is refused with the reason:
/// the admin export never carries a private key.
/// </summary>
public sealed class AdminCertificateExportTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminCertificateController";
    private const string RequestName = "ModularCA.API.Controllers.v1.Admin.CertExportRequest";
    private const string Token = "export-step-up";

    private static readonly Guid Operator = Guid.NewGuid();

    private sealed record Pki(CertificateEntity Root, CertificateEntity Intermediate, CertificateEntity Leaf);

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

    private static X509Certificate2 CaCert(string cn, X509Certificate2? issuer, byte[] serial)
    {
        var from = DateTimeOffset.UtcNow.AddDays(-1);
        var to = issuer != null ? new DateTimeOffset(issuer.NotAfter) : DateTimeOffset.UtcNow.AddYears(1);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(cn, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return issuer == null
            ? req.CreateSelfSigned(from, to)
            : req.Create(issuer, from, to, serial).CopyWithPrivateKey(key);
    }

    private static Pki Seed(ModularCADbContext db)
    {
        using var root = CaCert("CN=Export Root", null, [0]);
        using var intermediate = CaCert("CN=Export Intermediate", root, [1, 2]);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=export-leaf.example", leafKey, HashAlgorithmName.SHA256);
        using var leaf = leafReq.Create(intermediate, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), new byte[] { 3, 4 });

        var rootEntity = Entity(root, isCa: true);
        var intEntity = Entity(intermediate, isCa: true);
        intEntity.IssuerCertificateId = rootEntity.CertificateId;
        var leafEntity = Entity(leaf, isCa: false);
        leafEntity.IssuerCertificateId = intEntity.CertificateId;
        db.Certificates.AddRange(rootEntity, intEntity, leafEntity);
        var rootCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Export Root", Label = "export-root", CertificateId = rootEntity.CertificateId };
        db.CertificateAuthorities.AddRange(rootCa,
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Export Int", Label = "export-int", CertificateId = intEntity.CertificateId, ParentCaId = rootCa.Id });
        db.SaveChanges();
        return new Pki(rootEntity, intEntity, leafEntity);
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class AccessStub(bool canManage) : ICertificateAccessEvaluator
    {
        public bool CanViewCertificate(Guid userId, Guid certificateId) => true;
        public bool CanManageCertificate(Guid userId, Guid certificateId) => canManage;
    }

    private static (object Controller, IDistributedCache Cache) NewController(ModularCADbContext db, bool canManage = true)
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed(ControllerName),
            new CertificateStore(db), new CurrentUserStub(Operator), new AccessStub(canManage), db, cache,
            new RecordingAlertService(), null, new RecordingAuditService(), null)!;
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", Operator.ToString())], "test")),
            },
        };
        return (controller, cache);
    }

    private static async Task<IActionResult> ExportAsync(ModularCADbContext db, string serial, string format,
        bool? includeChain = null, string? password = null, bool canManage = true, bool stepUp = true)
    {
        var (controller, cache) = NewController(db, canManage);
        if (stepUp)
            cache.SetString($"mfa-stepup:{Operator}:{StepUpOps.ExportCert}:{serial}", Token);
        var request = Activator.CreateInstance(ApiAssembly.TypeNamed(RequestName))!;
        request.GetType().GetProperty("Format")!.SetValue(request, format);
        request.GetType().GetProperty("IncludeChain")!.SetValue(request, includeChain);
        request.GetType().GetProperty("Password")!.SetValue(request, password);
        return await (Task<IActionResult>)controller.GetType().GetMethod("ExportCertificate")!
            .Invoke(controller, [serial, request, Token])!;
    }

    private static string ErrorOf(IActionResult result)
    {
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        return JsonDocument.Parse(JsonSerializer.Serialize(bad.Value)).RootElement.GetProperty("error").GetString()!;
    }

    private static X509Certificate2Collection Pkcs7Certificates(byte[] der)
    {
        var cms = new System.Security.Cryptography.Pkcs.SignedCms();
        cms.Decode(der);
        return cms.Certificates;
    }

    [Fact]
    public async Task Pem_without_the_chain_is_the_certificate_alone()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        var file = Assert.IsType<FileContentResult>(await ExportAsync(db, pki.Leaf.SerialNumber, "pem"));

        Assert.Equal("application/x-pem-file", file.ContentType);
        Assert.Equal(pki.Leaf.Pem.Trim() + "\n", Encoding.UTF8.GetString(file.FileContents));
        Assert.EndsWith(".pem", file.FileDownloadName);
    }

    [Fact]
    public async Task Pem_with_the_chain_carries_the_issuers_as_the_chain_download_does()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        var file = Assert.IsType<FileContentResult>(await ExportAsync(db, pki.Leaf.SerialNumber, "PEM", includeChain: true));

        Assert.Equal(pki.Leaf.Pem.Trim() + "\n" + pki.Intermediate.Pem.Trim() + "\n", Encoding.UTF8.GetString(file.FileContents));
    }

    [Fact]
    public async Task Der_is_the_encoded_certificate()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        var file = Assert.IsType<FileContentResult>(await ExportAsync(db, pki.Leaf.SerialNumber, "der"));

        Assert.Equal("application/pkix-cert", file.ContentType);
        using var parsed = X509CertificateLoader.LoadCertificate(file.FileContents);
        Assert.Equal(pki.Leaf.SerialNumber, parsed.SerialNumber);
    }

    [Fact]
    public async Task Der_with_the_chain_is_refused_because_der_holds_one_certificate()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        Assert.Contains("PKCS#7", ErrorOf(await ExportAsync(db, pki.Leaf.SerialNumber, "der", includeChain: true)));
    }

    [Fact]
    public async Task Pkcs7_with_the_chain_carries_the_certificate_and_its_issuers()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        var file = Assert.IsType<FileContentResult>(await ExportAsync(db, pki.Leaf.SerialNumber, "pkcs7", includeChain: true));

        Assert.Equal("application/pkcs7-mime", file.ContentType);
        Assert.EndsWith(".p7b", file.FileDownloadName);
        var serials = Pkcs7Certificates(file.FileContents).Select(c => c.SerialNumber).ToList();
        Assert.Equal([pki.Leaf.SerialNumber, pki.Intermediate.SerialNumber], serials);
    }

    [Fact]
    public async Task Pkcs7_without_the_chain_carries_the_certificate_alone()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        var file = Assert.IsType<FileContentResult>(await ExportAsync(db, pki.Leaf.SerialNumber, "p7b"));

        Assert.Equal([pki.Leaf.SerialNumber], Pkcs7Certificates(file.FileContents).Select(c => c.SerialNumber).ToList());
    }

    [Theory]
    [InlineData("pfx")]
    [InlineData("pkcs12")]
    [InlineData("p12")]
    public async Task Pkcs12_is_refused_with_the_reason(string format)
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        var error = ErrorOf(await ExportAsync(db, pki.Leaf.SerialNumber, format, password: "secret"));

        Assert.Contains("private key", error);
        Assert.Contains("User Portal", error);
    }

    [Fact]
    public async Task An_unknown_format_is_refused_naming_the_supported_ones()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        var error = ErrorOf(await ExportAsync(db, pki.Leaf.SerialNumber, "jks"));

        Assert.Contains("pem", error);
        Assert.Contains("der", error);
        Assert.Contains("pkcs7", error);
    }

    [Fact]
    public async Task The_existing_guards_still_apply()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = Seed(db);

        Assert.Equal(403, Assert.IsType<ObjectResult>(await ExportAsync(db, pki.Leaf.SerialNumber, "pem", stepUp: false)).StatusCode);
        Assert.IsType<NotFoundObjectResult>(await ExportAsync(db, pki.Leaf.SerialNumber, "pem", canManage: false));
        Assert.IsType<NotFoundObjectResult>(await ExportAsync(db, pki.Intermediate.SerialNumber, "pem"));
    }
}
