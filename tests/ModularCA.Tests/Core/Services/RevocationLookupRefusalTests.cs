using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Revocation;
using ModularCA.Tests.Api;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The revocation service refuses a certificate it cannot find with
/// <see cref="ResourceNotFoundException"/> (404, <see cref="ErrorCodes.ResourceNotFound"/>) and a
/// serial that matches certificates of more than one issuer with
/// <see cref="ResourceConflictException"/> (409, <see cref="ErrorCodes.CertificateSerialAmbiguous"/>).
/// Both were bare <see cref="InvalidOperationException"/>s, which reached the global handler as a
/// 500 on every path without a catch of its own.
/// </summary>
public sealed class RevocationLookupRefusalTests
{
    private sealed class NoCrls : ICrlService
    {
        public Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult("");
        public Task<string> GenerateDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult("");
        public Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<string?> GetLatestDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<CrlBlob?> GetLatestCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
        public Task<CrlBlob?> GetLatestDeltaCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
    }

    /// <summary>A revocation service that refuses every call as the real one refuses a certificate deleted under it.</summary>
    private sealed class VanishedCertificates : ICertificateRevocationService
    {
        public int Calls { get; private set; }

        private Task<RevocationResult> Gone(Guid? id)
        {
            Calls++;
            throw new ResourceNotFoundException("Certificate", "Certificate not found.", id?.ToString());
        }

        public Task<RevocationResult> RevokeCertificateAsync(Guid? certificateId, string? certificateSerialNumber, RevocationReason reason, DateTime? invalidityDate = null) => Gone(certificateId);
        [Obsolete("Not used by these tests.")]
        public Task ReissueCertificateAsync(Guid certificateId, DateTime notBefore, DateTime notAfter) => throw new NotSupportedException();
        public Task<RevocationResult> HoldCertificateAsync(Guid? certificateId, string? certificateSerialNumber) => Gone(certificateId);
        public Task<RevocationResult> UnholdCertificateAsync(Guid? certificateId, string? certificateSerialNumber) => Gone(certificateId);
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static CertificateRevocationService Service(ModularCADbContext db) => new(db,
        DispatchProxy.Create<IKeystoreCertificates, SpaceIsolationMatrixTests.NoOpProxy>(),
        DispatchProxy.Create<ICertificateStore, SpaceIsolationMatrixTests.NoOpProxy>(),
        new NoopNotificationService(), new NoCrls(), NullLogger<CertificateRevocationService>.Instance);

    private static CertificateEntity Leaf(ModularCADbContext db, string serial, string issuer = "CN=Lookup CA")
    {
        var leaf = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = serial, SubjectDN = "CN=lookup.example", Issuer = issuer,
            Pem = "x", IsCA = false,
            NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(30),
        };
        db.Certificates.Add(leaf);
        db.SaveChanges();
        return leaf;
    }

    /// <summary>Runs <paramref name="refusal"/> through <c>RequestValidationMiddleware</c> and returns the status and body it answers with.</summary>
    private static async Task<(int Status, JsonElement Body)> AnsweredAsync(Exception refusal)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Middleware.RequestValidationMiddleware");
        var logger = typeof(NullLogger<>).MakeGenericType(type).GetField("Instance")!.GetValue(null);
        RequestDelegate next = _ => throw refusal;
        var middleware = Activator.CreateInstance(type, next, logger)!;
        var http = new DefaultHttpContext();
        http.Response.Body = new MemoryStream();

        await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [http])!;

        http.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(http.Response.Body);
        return (http.Response.StatusCode, body.RootElement.Clone());
    }

    // ── The service ──────────────────────────────────────────────────────

    /// <summary>Revoke, hold and release of an unknown certificate ID are refused as not found, and the middleware answers 404.</summary>
    [Theory]
    [InlineData("revoke")]
    [InlineData("hold")]
    [InlineData("unhold")]
    public async Task An_unknown_certificate_id_is_refused_404(string operation)
    {
        using var db = InMemoryDbContextFactory.Create();
        var service = Service(db);
        var id = Guid.NewGuid();

        var refusal = await Assert.ThrowsAsync<ResourceNotFoundException>(() => operation switch
        {
            "revoke" => service.RevokeCertificateAsync(id, null, RevocationReason.KeyCompromise),
            "hold" => service.HoldCertificateAsync(id, null),
            _ => service.UnholdCertificateAsync(id, null),
        });

        Assert.Equal(404, refusal.Status);
        Assert.Equal(ErrorCodes.ResourceNotFound, refusal.Code);
        Assert.Equal(id.ToString(), refusal.Identifier);
        var (status, body) = await AnsweredAsync(refusal);
        Assert.Equal(404, status);
        Assert.Equal(ErrorCodes.ResourceNotFound, body.GetProperty("code").GetString());
        Assert.Equal("Certificate", body.GetProperty("resourceKind").GetString());
    }

    /// <summary>An unknown serial is refused as not found.</summary>
    [Fact]
    public async Task An_unknown_serial_is_refused_404()
    {
        using var db = InMemoryDbContextFactory.Create();

        var refusal = await Assert.ThrowsAsync<ResourceNotFoundException>(() =>
            Service(db).RevokeCertificateAsync(null, "0DEAD1", RevocationReason.KeyCompromise));

        Assert.Equal("0DEAD1", refusal.Identifier);
    }

    /// <summary>
    /// A serial two issuers both used is refused with 409 and the ambiguous-serial code, and neither
    /// certificate is touched.
    /// </summary>
    [Theory]
    [InlineData("revoke")]
    [InlineData("hold")]
    [InlineData("unhold")]
    public async Task An_ambiguous_serial_is_refused_409_and_changes_nothing(string operation)
    {
        using var db = InMemoryDbContextFactory.Create();
        var first = Leaf(db, "0AB1", "CN=First CA");
        var second = Leaf(db, "0AB1", "CN=Second CA");
        var service = Service(db);

        var refusal = await Assert.ThrowsAsync<ResourceConflictException>(() => operation switch
        {
            "revoke" => service.RevokeCertificateAsync(null, "0AB1", RevocationReason.KeyCompromise),
            "hold" => service.HoldCertificateAsync(null, "0AB1"),
            _ => service.UnholdCertificateAsync(null, "0AB1"),
        });

        Assert.Equal(409, refusal.Status);
        Assert.Equal(ErrorCodes.CertificateSerialAmbiguous, refusal.Code);
        Assert.Contains("certificate ID", refusal.Message);
        var (status, body) = await AnsweredAsync(refusal);
        Assert.Equal(409, status);
        Assert.Equal(ErrorCodes.CertificateSerialAmbiguous, body.GetProperty("code").GetString());
        db.ChangeTracker.Clear();
        Assert.False(db.Certificates.Single(c => c.CertificateId == first.CertificateId).Revoked);
        Assert.False(db.Certificates.Single(c => c.CertificateId == second.CertificateId).Revoked);
    }

    /// <summary>A call with neither an ID nor a serial is refused as a bad request, not a 500.</summary>
    [Fact]
    public async Task Neither_an_id_nor_a_serial_is_refused_400()
    {
        using var db = InMemoryDbContextFactory.Create();

        var refusal = await Assert.ThrowsAsync<InvalidRequestException>(() =>
            Service(db).RevokeCertificateAsync(null, " ", RevocationReason.KeyCompromise));

        Assert.Equal(400, refusal.Status);
        Assert.Equal(ErrorCodes.RequestInvalid, refusal.Code);
    }

    // ── Callers with a catch of their own ────────────────────────────────

    /// <summary>
    /// Bulk revoke reports a certificate deleted between its lookup and the revoke as
    /// <c>not_found</c> and skips it; it used to count it as a failure.
    /// </summary>
    [Fact]
    public async Task Bulk_revoke_skips_a_certificate_gone_before_the_revoke_as_not_found()
    {
        using var db = InMemoryDbContextFactory.Create();
        Leaf(db, "0AC1");
        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.RevokeCert}", "token");
        var revocations = new VanishedCertificates();
        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminRevocationController"),
            revocations, new CurrentUserStub(actor), new RecordingAuditService(), cache, new RecordingAlertService(), db, null)!;
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", actor.ToString())], "test")) };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
        controller.ControllerContext = new ControllerContext { HttpContext = http };

        var request = new BulkRevokeRequest { SerialNumbers = ["0AC1"], Reason = RevocationReason.KeyCompromise };
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("BulkRevoke")!.Invoke(controller, [request, "token"])!;

        var body = JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value)).RootElement;
        Assert.Equal(1, revocations.Calls);
        Assert.Equal(0, body.GetProperty("failed").GetInt32());
        Assert.Equal(1, body.GetProperty("skipped").GetInt32());
        Assert.Equal("not_found", body.GetProperty("results")[0].GetProperty("status").GetString());
    }

    private sealed class OneCertificateStore(CertificateEntity cert) : ICertificateStore
    {
        public Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber)
            => Task.FromResult(serialNumber != cert.SerialNumber ? null : new CertificateInfoModel
            {
                CertificateId = cert.CertificateId, SerialNumber = cert.SerialNumber, SubjectDN = cert.SubjectDN, Issuer = cert.Issuer,
                RevocationReason = string.Empty,
            });
        public Task SaveCertificateAsync(byte[] certificateBytes, CertificateInfoModel info, byte[]? encryptedPrivateKey = null) => throw new NotSupportedException();
        public Task<IEnumerable<CertificateInfoModel>> ListAsync() => throw new NotSupportedException();
        public Task<List<CertificateInfoModel>> GetAllCertificatesAsync() => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateByIdAsync(Guid id) => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateBySerialNumberAsync(string serialNumber) => throw new NotSupportedException();
        public Task<byte[]?> GetRawCertificateAsync(string serialNumber) => throw new NotSupportedException();
    }

    private sealed class OwnsEverything : ICertificateAccessEvaluator
    {
        public bool CanViewCertificate(Guid userId, Guid certificateId) => true;
        public bool CanManageCertificate(Guid userId, Guid certificateId) => true;
    }

    /// <summary>
    /// The user portal answers a certificate deleted between the ownership check and the revoke
    /// with 404, as it answers a missing one; it used to turn the service's refusal into a 400.
    /// </summary>
    [Fact]
    public async Task The_user_portal_answers_a_certificate_gone_before_the_revoke_with_404()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db, "0AD1");
        var owner = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        cache.SetString($"mfa-stepup:{owner}:{StepUpOps.RevokeSelfCert}:0AD1", "token");
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.User.UserCertificateController");
        var revocations = new VanishedCertificates();
        var controller = (ControllerBase)Activator.CreateInstance(type,
            new OneCertificateStore(leaf), new CurrentUserStub(owner), new OwnsEverything(), null,
            revocations, db, new RecordingAuditService(), cache)!;
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", owner.ToString())], "test")) },
        };
        var requestType = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.User.UserCertRevokeRequest");
        var request = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("Reason")!.SetValue(request, RevocationReason.KeyCompromise);

        var result = await (Task<IActionResult>)type.GetMethod("RevokeOwnCertificate")!.Invoke(controller, ["0AD1", request, "token"])!;

        Assert.Equal(1, revocations.Calls);
        Assert.IsType<NotFoundResult>(result);
    }
}
