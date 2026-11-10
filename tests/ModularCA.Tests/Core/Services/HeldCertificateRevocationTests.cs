using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Revocation;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Api;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A certificate on hold can be revoked permanently without being released first, as RFC 5280
/// §5.3.1 allows; a permanent revocation stays permanent. Revoking a held certificate used to throw
/// "already revoked", so the only way to a permanent reason was a release, which reinstated the
/// certificate as good on the CRL and OCSP in between.
/// </summary>
public sealed class HeldCertificateRevocationTests
{
    /// <summary>Records the CA certificates a CRL is regenerated for.</summary>
    private sealed class RecordingCrls : ICrlService
    {
        public List<Guid> Generated { get; } = [];
        public Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
        {
            Generated.Add(caCertificateId);
            return Task.FromResult("");
        }
        public Task<string> GenerateDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult("");
        public Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<string?> GetLatestDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<CrlBlob?> GetLatestCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
        public Task<CrlBlob?> GetLatestDeltaCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
    }

    private static readonly Guid IssuerId = Guid.NewGuid();

    private static CertificateRevocationService Service(ModularCADbContext db, RecordingCrls crls) => new(db,
        DispatchProxy.Create<IKeystoreCertificates, SpaceIsolationMatrixTests.NoOpProxy>(),
        DispatchProxy.Create<ICertificateStore, SpaceIsolationMatrixTests.NoOpProxy>(),
        new NoopNotificationService(), crls, NullLogger<CertificateRevocationService>.Instance);

    private static CertificateEntity Leaf(ModularCADbContext db, string serial = "0A0B")
    {
        var leaf = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = serial, SubjectDN = "CN=held.example", Issuer = "CN=Hold CA",
            Pem = "x", IsCA = false, IssuerCertificateId = IssuerId,
            NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(30),
        };
        db.Certificates.Add(leaf);
        db.SaveChanges();
        return leaf;
    }

    /// <summary>Puts <paramref name="leaf"/> on hold as of <paramref name="heldAt"/>, as the hold endpoint leaves it.</summary>
    private static void HoldAt(ModularCADbContext db, CertificateEntity leaf, DateTime heldAt)
    {
        leaf.Revoked = true;
        leaf.RevocationReason = nameof(RevocationReason.CertificateHold);
        leaf.RevocationDate = heldAt;
        db.SaveChanges();
    }

    private static CertificateEntity Reload(ModularCADbContext db, Guid id)
    {
        db.ChangeTracker.Clear();
        return db.Certificates.Single(c => c.CertificateId == id);
    }

    [Fact]
    public async Task A_held_certificate_is_revoked_permanently_without_a_release()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        var crls = new RecordingCrls();
        await Service(db, crls).HoldCertificateAsync(leaf.CertificateId, null);
        var heldAt = Reload(db, leaf.CertificateId).RevocationDate!.Value;
        crls.Generated.Clear();

        var result = await Service(db, crls).RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.KeyCompromise);

        var row = Reload(db, leaf.CertificateId);
        Assert.True(row.Revoked);
        Assert.Equal(nameof(RevocationReason.KeyCompromise), row.RevocationReason);
        Assert.True(row.RevocationDate >= heldAt);
        Assert.Equal(result.EffectiveAt, row.RevocationDate);
        Assert.Equal(heldAt, row.InvalidityDate);
        Assert.Equal("Revoked", result.NewStatus);
        Assert.Equal(RevocationReason.KeyCompromise, result.Reason);
        Assert.Equal(RevocationReason.CertificateHold, result.PreviousReason);
        Assert.Equal([IssuerId], crls.Generated);
    }

    [Fact]
    public async Task The_revocation_date_moves_to_the_permanent_revocation_so_the_delta_crl_carries_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        var heldAt = DateTime.UtcNow.AddDays(-3);
        HoldAt(db, leaf, heldAt);

        var before = DateTime.UtcNow;
        await Service(db, new RecordingCrls()).RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.Superseded);

        var row = Reload(db, leaf.CertificateId);
        Assert.True(row.RevocationDate >= before);
        Assert.Equal(heldAt, row.InvalidityDate);
    }

    [Fact]
    public async Task A_given_invalidity_date_wins_over_the_hold_date()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        HoldAt(db, leaf, DateTime.UtcNow.AddDays(-3));
        var compromisedAt = DateTime.UtcNow.AddDays(-10);

        await Service(db, new RecordingCrls()).RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.KeyCompromise, compromisedAt);

        Assert.Equal(compromisedAt.ToUniversalTime(), Reload(db, leaf.CertificateId).InvalidityDate);
    }

    [Fact]
    public async Task Revoking_a_held_certificate_revokes_its_mtls_credential()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        db.MtlsCredentials.Add(new MtlsCredentialEntity { UserId = Guid.NewGuid(), CertificateId = leaf.CertificateId, SerialNumber = leaf.SerialNumber, Thumbprint = "t" });
        db.SaveChanges();
        await Service(db, new RecordingCrls()).HoldCertificateAsync(leaf.CertificateId, null);
        Assert.False(db.MtlsCredentials.AsEnumerable().Single().IsRevoked);

        await Service(db, new RecordingCrls()).RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.CessationOfOperation);

        db.ChangeTracker.Clear();
        Assert.True(db.MtlsCredentials.Single().IsRevoked);
    }

    [Fact]
    public async Task A_held_certificate_cannot_be_held_again_through_revoke()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        var heldAt = DateTime.UtcNow.AddDays(-1);
        HoldAt(db, leaf, heldAt);

        await Assert.ThrowsAsync<CertificateRevocationStateException>(() =>
            Service(db, new RecordingCrls()).RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.CertificateHold));

        var row = Reload(db, leaf.CertificateId);
        Assert.Equal(nameof(RevocationReason.CertificateHold), row.RevocationReason);
        Assert.Equal(heldAt, row.RevocationDate);
    }

    [Fact]
    public async Task A_permanent_revocation_stays_permanent()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        var service = Service(db, new RecordingCrls());
        await service.HoldCertificateAsync(leaf.CertificateId, null);
        await service.RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.KeyCompromise);

        await Assert.ThrowsAsync<CertificateRevocationStateException>(() => service.HoldCertificateAsync(leaf.CertificateId, null));
        await Assert.ThrowsAsync<CertificateRevocationStateException>(() => service.UnholdCertificateAsync(leaf.CertificateId, null));
        await Assert.ThrowsAsync<CertificateRevocationStateException>(() =>
            service.RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.CertificateHold));
        await Assert.ThrowsAsync<CertificateRevocationStateException>(() =>
            service.RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.Superseded));

        Assert.Equal(nameof(RevocationReason.KeyCompromise), Reload(db, leaf.CertificateId).RevocationReason);
    }

    [Fact]
    public async Task A_release_still_clears_a_hold()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        HoldAt(db, leaf, DateTime.UtcNow.AddDays(-1));

        await Service(db, new RecordingCrls()).UnholdCertificateAsync(leaf.CertificateId, null);

        var row = Reload(db, leaf.CertificateId);
        Assert.False(row.Revoked);
        Assert.Null(row.RevocationReason);
        Assert.Null(row.RevocationDate);
    }

    // ── The admin endpoint ───────────────────────────────────────────────

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    [Fact]
    public async Task The_admin_revoke_endpoint_revokes_a_held_certificate_and_audits_the_previous_hold()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        HoldAt(db, leaf, DateTime.UtcNow.AddDays(-1));
        var actor = Guid.NewGuid();
        var audit = new RecordingAuditService();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.RevokeCert}:{leaf.CertificateId}", "token");
        var crls = new RecordingCrls();

        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminRevocationController"),
            Service(db, crls), new CurrentUserStub(actor), audit, cache, new RecordingAlertService(), db, null)!;
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", actor.ToString())], "test")) };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
        controller.ControllerContext = new ControllerContext { HttpContext = http };

        var request = new RevokeCertificateRequestByCertId { CertificateId = leaf.CertificateId, Reason = RevocationReason.KeyCompromise };
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("RevokeByCertId")!
            .Invoke(controller, [leaf.CertificateId, request, "token"])!;

        var body = JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value)).RootElement;
        Assert.Equal("KeyCompromise", body.GetProperty("reason").GetString());
        Assert.Equal("CertificateHold", body.GetProperty("previousReason").GetString());
        Assert.Equal(nameof(RevocationReason.KeyCompromise), Reload(db, leaf.CertificateId).RevocationReason);
        var entry = Assert.Single(audit.Entries, e => e.Action == AuditActionType.CertificateRevoked);
        Assert.Contains("\"PreviousReason\":6", JsonSerializer.Serialize(entry.Details));
        Assert.Equal([IssuerId], crls.Generated);
    }

    // ── The refusals are 409, not 500 ────────────────────────────────────

    /// <summary>
    /// A refusal caused by the certificate's revocation state is a
    /// <see cref="CertificateRevocationStateException"/>, which the request-validation middleware
    /// answers 409 with its code; a bare InvalidOperationException reached the global handler as a 500.
    /// </summary>
    [Fact]
    public async Task A_revocation_state_refusal_is_answered_409_with_its_code()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db);
        var service = Service(db, new RecordingCrls());
        await service.RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.KeyCompromise);
        var refusal = await Assert.ThrowsAsync<CertificateRevocationStateException>(() =>
            service.RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.Superseded));
        Assert.Equal(nameof(RevocationReason.KeyCompromise), refusal.CurrentReason);

        var type = ApiAssembly.TypeNamed("ModularCA.API.Middleware.RequestValidationMiddleware");
        var logger = typeof(NullLogger<>).MakeGenericType(type).GetField("Instance")!.GetValue(null);
        RequestDelegate next = _ => throw refusal;
        var middleware = Activator.CreateInstance(type, next, logger)!;
        var http = new DefaultHttpContext();
        http.Response.Body = new MemoryStream();

        await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [http])!;

        Assert.Equal(409, http.Response.StatusCode);
        http.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(http.Response.Body);
        Assert.Equal(ErrorCodes.CertificateRevocationState, body.RootElement.GetProperty("code").GetString());
        Assert.Contains("already revoked", body.RootElement.GetProperty("detail").GetString());
    }

    // ── Bulk revoke ──────────────────────────────────────────────────────

    private static async Task<JsonElement> BulkRevokeAsync(ModularCADbContext db, RecordingAuditService audit, RevocationReason reason, params string[] serials)
    {
        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.RevokeCert}", "token");
        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminRevocationController"),
            Service(db, new RecordingCrls()), new CurrentUserStub(actor), audit, cache, new RecordingAlertService(), db, null)!;
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", actor.ToString())], "test")) };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
        controller.ControllerContext = new ControllerContext { HttpContext = http };

        var request = new BulkRevokeRequest { SerialNumbers = [.. serials], Reason = reason };
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("BulkRevoke")!.Invoke(controller, [request, "token"])!;
        return JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value)).RootElement;
    }

    private static JsonElement EntryOf(JsonElement body, string serial) => body.GetProperty("results").EnumerateArray()
        .Single(r => r.GetProperty("serialNumber").GetString() == serial);

    /// <summary>
    /// Bulk revoke makes a hold permanent with the batch's reason, as the single revoke does; it
    /// used to skip a held certificate as already revoked. A permanent revocation is still skipped.
    /// </summary>
    [Fact]
    public async Task Bulk_revoke_makes_a_hold_permanent_and_skips_a_permanent_revocation()
    {
        using var db = InMemoryDbContextFactory.Create();
        var held = Leaf(db, "0A01");
        HoldAt(db, held, DateTime.UtcNow.AddDays(-1));
        var gone = Leaf(db, "0A02");
        gone.Revoked = true;
        gone.RevocationReason = nameof(RevocationReason.Superseded);
        gone.RevocationDate = DateTime.UtcNow.AddDays(-2);
        db.SaveChanges();
        var live = Leaf(db, "0A03");
        var audit = new RecordingAuditService();

        var body = await BulkRevokeAsync(db, audit, RevocationReason.KeyCompromise, "0A01", "0A02", "0A03");

        Assert.Equal(2, body.GetProperty("revoked").GetInt32());
        Assert.Equal(1, body.GetProperty("skipped").GetInt32());
        Assert.Equal("revoked", EntryOf(body, "0A01").GetProperty("status").GetString());
        Assert.Equal("CertificateHold", EntryOf(body, "0A01").GetProperty("previousReason").GetString());
        Assert.Equal("already_revoked", EntryOf(body, "0A02").GetProperty("status").GetString());
        Assert.Equal("revoked", EntryOf(body, "0A03").GetProperty("status").GetString());
        Assert.Equal(nameof(RevocationReason.KeyCompromise), Reload(db, held.CertificateId).RevocationReason);
        Assert.Equal(nameof(RevocationReason.Superseded), Reload(db, gone.CertificateId).RevocationReason);
        Assert.Equal(nameof(RevocationReason.KeyCompromise), Reload(db, live.CertificateId).RevocationReason);
        Assert.Contains(audit.Entries, e => e.Action == AuditActionType.CertificateRevoked && e.TargetId == "0A01"
            && JsonSerializer.Serialize(e.Details).Contains("\"PreviousReason\":6"));
    }

    /// <summary>Bulk revoke with Certificate Hold leaves a held certificate as it is, reported as already held.</summary>
    [Fact]
    public async Task Bulk_hold_of_a_held_certificate_is_skipped_as_already_held()
    {
        using var db = InMemoryDbContextFactory.Create();
        var held = Leaf(db, "0A04");
        var heldAt = DateTime.UtcNow.AddDays(-1);
        HoldAt(db, held, heldAt);

        var body = await BulkRevokeAsync(db, new RecordingAuditService(), RevocationReason.CertificateHold, "0A04");

        Assert.Equal("already_held", EntryOf(body, "0A04").GetProperty("status").GetString());
        Assert.Equal(0, body.GetProperty("failed").GetInt32());
        Assert.Equal(heldAt, Reload(db, held.CertificateId).RevocationDate);
    }

    // ── The user portal and the infrastructure API ───────────────────────

    /// <summary>A certificate store over the test database, for the controllers that look certificates up by serial.</summary>
    private sealed class DbCertificateStore(ModularCADbContext db) : ICertificateStore
    {
        public Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber)
        {
            var c = db.Certificates.AsNoTracking().SingleOrDefault(x => x.SerialNumber == serialNumber);
            return Task.FromResult(c == null ? null : new CertificateInfoModel
            {
                CertificateId = c.CertificateId, SerialNumber = c.SerialNumber, SubjectDN = c.SubjectDN, Issuer = c.Issuer,
                IsCA = c.IsCA, Revoked = c.Revoked, RevocationReason = c.RevocationReason ?? string.Empty,
            });
        }
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

    private static async Task<IActionResult> UserRevokeAsync(ModularCADbContext db, string serial, RevocationReason reason)
    {
        var owner = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        cache.SetString($"mfa-stepup:{owner}:{StepUpOps.RevokeSelfCert}:{serial}", "token");
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.User.UserCertificateController");
        var controller = (ControllerBase)Activator.CreateInstance(type,
            new DbCertificateStore(db), new CurrentUserStub(owner), new OwnsEverything(), null,
            Service(db, new RecordingCrls()), db, new RecordingAuditService(), cache)!;
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", owner.ToString())], "test")) },
        };
        var requestType = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.User.UserCertRevokeRequest");
        var request = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("Reason")!.SetValue(request, reason);
        return await (Task<IActionResult>)type.GetMethod("RevokeOwnCertificate")!.Invoke(controller, [serial, request, "token"])!;
    }

    /// <summary>The owner can revoke permanently a certificate an administrator put on hold; they used to be told it was already revoked.</summary>
    [Fact]
    public async Task The_user_portal_revokes_a_held_certificate_permanently()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db, "0B01");
        HoldAt(db, leaf, DateTime.UtcNow.AddDays(-1));

        var result = await UserRevokeAsync(db, "0B01", RevocationReason.KeyCompromise);

        var body = JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value)).RootElement;
        Assert.Equal("KeyCompromise", body.GetProperty("reason").GetString());
        Assert.Equal("CertificateHold", body.GetProperty("previousReason").GetString());
        Assert.Equal(nameof(RevocationReason.KeyCompromise), Reload(db, leaf.CertificateId).RevocationReason);
    }

    /// <summary>A permanently revoked certificate is refused with 409 and the revocation-state code.</summary>
    [Fact]
    public async Task The_user_portal_refuses_a_permanently_revoked_certificate_with_409()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db, "0B02");
        await Service(db, new RecordingCrls()).RevokeCertificateAsync(leaf.CertificateId, null, RevocationReason.Superseded);

        var result = await UserRevokeAsync(db, "0B02", RevocationReason.KeyCompromise);

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        Assert.Contains(ErrorCodes.CertificateRevocationState, JsonSerializer.Serialize(conflict.Value));
        Assert.Equal(nameof(RevocationReason.Superseded), Reload(db, leaf.CertificateId).RevocationReason);
    }

    private static async Task<JsonElement> InfraRevokeAsync(ModularCADbContext db, string serial, string? reason)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraController");
        var requestType = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraRevokeCertificateRequest");
        var request = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("Reason")!.SetValue(request, reason);
        var controller = Activator.CreateInstance(type, null, null, new DbCertificateStore(db), Service(db, new RecordingCrls()), null, null, null, db, new SystemConfig())!;
        var result = await (Task<IActionResult>)type.GetMethod("RevokeCertificate")!.Invoke(controller, [serial, request])!;
        return JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value)).RootElement;
    }

    /// <summary>The infrastructure API's revoke makes a hold permanent; it used to answer "already revoked" and change nothing.</summary>
    [Fact]
    public async Task The_infra_api_revokes_a_held_certificate_permanently()
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db, "0C01");
        HoldAt(db, leaf, DateTime.UtcNow.AddDays(-1));

        var body = await InfraRevokeAsync(db, "0C01", "keyCompromise");

        Assert.Equal("KeyCompromise", body.GetProperty("revocationReason").GetString());
        Assert.Equal("CertificateHold", body.GetProperty("previousReason").GetString());
        Assert.Equal(nameof(RevocationReason.KeyCompromise), Reload(db, leaf.CertificateId).RevocationReason);
    }

    /// <summary>The infrastructure API stays idempotent: a repeat on a permanent revocation, or a hold of a held certificate, changes nothing.</summary>
    [Theory]
    [InlineData(nameof(RevocationReason.Superseded), "keyCompromise", "Certificate was already revoked.")]
    [InlineData(nameof(RevocationReason.CertificateHold), "certificateHold", "Certificate is already on hold.")]
    public async Task The_infra_api_leaves_a_final_or_repeated_state_as_it_is(string stored, string asked, string message)
    {
        using var db = InMemoryDbContextFactory.Create();
        var leaf = Leaf(db, "0C02");
        var at = DateTime.UtcNow.AddDays(-1);
        leaf.Revoked = true;
        leaf.RevocationReason = stored;
        leaf.RevocationDate = at;
        db.SaveChanges();

        var body = await InfraRevokeAsync(db, "0C02", asked);

        Assert.Equal(message, body.GetProperty("message").GetString());
        var row = Reload(db, leaf.CertificateId);
        Assert.Equal(stored, row.RevocationReason);
        Assert.Equal(at, row.RevocationDate);
    }
}
