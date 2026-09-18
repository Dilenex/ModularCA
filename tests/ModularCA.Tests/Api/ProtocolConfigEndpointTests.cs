using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives the real <c>AdminProtocolConfigController</c> over an in-memory database and asserts
/// the three rules live testing produced: SCEP cannot be enabled on a non-RSA authority, a
/// configuration that cannot work carries an advisory saying so, and a protocol disabled
/// system-wide is not listed as configured.
/// </summary>
/// <remarks>
/// The test project does not reference ModularCA.API (it is the host, not a library), so the
/// controller is loaded from its build output and invoked by reflection the way the role tests
/// load it. That keeps the assertions on the endpoint itself rather than on a helper the
/// endpoint might stop calling.
/// </remarks>
public sealed class ProtocolConfigEndpointTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminProtocolConfigController";
    private const string RequestName = "ModularCA.API.Controllers.v1.Admin.ProtocolConfigUpdateRequest";

    private static readonly Guid Operator = Guid.NewGuid();

    // ---- fixtures -------------------------------------------------------------------------

    private static string RsaCaPem()
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test RSA CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return cert.ExportCertificatePem();
    }

    private static string EcdsaCaPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test EC CA", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return cert.ExportCertificatePem();
    }

    private static Guid SeedCa(ModularCADbContext db, string pem, params string[] configuredProtocols)
    {
        var cert = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            Pem = pem,
            SubjectDN = "CN=Test CA",
            Issuer = "CN=Test CA",
            IsCA = true,
        };
        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(),
            Name = "Test CA",
            Label = "test-ca",
            TenantId = Guid.NewGuid(),
            CertificateId = cert.CertificateId,
            Certificate = cert,
        };
        db.Certificates.Add(cert);
        db.CertificateAuthorities.Add(ca);
        foreach (var protocol in configuredProtocols)
            db.CaProtocolConfigs.Add(new CaProtocolConfigEntity { CaId = ca.Id, Protocol = protocol, IsEnabled = true });
        db.SaveChanges();
        return ca.Id;
    }

    // ---- reflection plumbing --------------------------------------------------------------

    private static object NewController(ModularCADbContext db, IFeatureFlagService flags, IDistributedCache cache)
        => Activator.CreateInstance(
            ApiAssembly.TypeNamed(ControllerName),
            db,
            new RecordingAuditService(),
            new CurrentUserStub(Operator),
            cache,
            new List<IEnrollmentProtocol>(),
            flags)!;

    private static void GiveHttpContext(object controller)
    {
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", Operator.ToString()) }, "test")),
        };
        var property = controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!;
        property.SetValue(controller, new ControllerContext { HttpContext = http });
    }

    private static async Task<IActionResult> GetByCaAsync(object controller, Guid caId)
        => await (Task<IActionResult>)controller.GetType().GetMethod("GetByCa")!.Invoke(controller, new object[] { caId })!;

    private static async Task<IActionResult> UpsertAsync(object controller, Guid caId, string protocol, bool enabled, string? mfaToken)
    {
        var request = Activator.CreateInstance(ApiAssembly.TypeNamed(RequestName))!;
        request.GetType().GetProperty("Enabled")!.SetValue(request, enabled);
        var method = controller.GetType().GetMethod("Upsert")!;
        return await (Task<IActionResult>)method.Invoke(controller, new object?[] { caId, protocol, request, mfaToken })!;
    }

    /// <summary>Seeds the step-up token the endpoint demands, under the key the validator builds.</summary>
    private static string SeedStepUp(IDistributedCache cache, Guid caId)
    {
        var token = "step-up-token";
        cache.SetString($"mfa-stepup:{Operator}:{StepUpOps.UpdateProtocolConfig}:{caId}", token);
        return token;
    }

    private static JsonElement Rows(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        var json = JsonSerializer.Serialize(ok.Value, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        return JsonDocument.Parse(json).RootElement;
    }

    private static string ErrorOf(IActionResult result)
    {
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var json = JsonSerializer.Serialize(bad.Value, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        return JsonDocument.Parse(json).RootElement.GetProperty("error").GetString()!;
    }

    // ---- 1. SCEP cannot be enabled on a non-RSA CA -----------------------------------------

    [Fact]
    public async Task Enabling_scep_on_an_elliptic_curve_authority_is_refused_and_says_why()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, EcdsaCaPem());
        var cache = new StubCache();
        var controller = NewController(db, new FlagStub("SCEP.Enabled"), cache);
        GiveHttpContext(controller);

        var result = await UpsertAsync(controller, caId, "SCEP", enabled: true, SeedStepUp(cache, caId));

        var error = ErrorOf(result);
        Assert.Contains("ECDSA", error);
        Assert.Contains("RSA", error);
        Assert.Empty(db.CaProtocolConfigs.ToList());
    }

    [Fact]
    public async Task Enabling_scep_on_an_rsa_authority_still_works()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, RsaCaPem());
        var cache = new StubCache();
        var controller = NewController(db, new FlagStub("SCEP.Enabled"), cache);
        GiveHttpContext(controller);

        var result = await UpsertAsync(controller, caId, "SCEP", enabled: true, SeedStepUp(cache, caId));

        Assert.IsType<OkObjectResult>(result);
        Assert.True(db.CaProtocolConfigs.Single().IsEnabled);
    }

    [Fact]
    public async Task An_existing_scep_row_on_a_non_rsa_authority_can_still_be_turned_off()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, EcdsaCaPem(), "SCEP");
        var cache = new StubCache();
        var controller = NewController(db, new FlagStub("SCEP.Enabled"), cache);
        GiveHttpContext(controller);

        var result = await UpsertAsync(controller, caId, "SCEP", enabled: false, SeedStepUp(cache, caId));

        Assert.IsType<OkObjectResult>(result);
        // The row survives — this is about enabling, not migrating.
        Assert.False(db.CaProtocolConfigs.Single().IsEnabled);
    }

    // ---- 2. the advisory on the listing ----------------------------------------------------

    [Fact]
    public async Task A_listed_scep_row_on_a_non_rsa_authority_carries_an_advisory()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, EcdsaCaPem(), "SCEP", "EST");
        var controller = NewController(db, new FlagStub("SCEP.Enabled", "EST.Enabled"), new StubCache());

        var rows = Rows(await GetByCaAsync(controller, caId));

        var scep = rows.EnumerateArray().Single(r => r.GetProperty("protocol").GetString() == "SCEP");
        var advisory = Assert.Single(scep.GetProperty("advisories").EnumerateArray().ToList());
        Assert.Equal(ProtocolCompatibility.ScepRequiresRsaKey, advisory.GetProperty("reason").GetString());
        Assert.Contains("ECDSA", advisory.GetProperty("message").GetString()!);

        // A protocol with nothing wrong with it carries an empty list, not an advisory.
        var est = rows.EnumerateArray().Single(r => r.GetProperty("protocol").GetString() == "EST");
        Assert.Empty(est.GetProperty("advisories").EnumerateArray().ToList());
    }

    [Fact]
    public async Task The_same_row_on_an_rsa_authority_carries_none()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, RsaCaPem(), "SCEP");
        var controller = NewController(db, new FlagStub("SCEP.Enabled"), new StubCache());

        var rows = Rows(await GetByCaAsync(controller, caId));

        var scep = rows.EnumerateArray().Single(r => r.GetProperty("protocol").GetString() == "SCEP");
        Assert.Empty(scep.GetProperty("advisories").EnumerateArray().ToList());
    }

    // ---- 3. a protocol disabled system-wide is not listed -----------------------------------

    [Fact]
    public async Task A_protocol_disabled_system_wide_is_not_listed_as_configured()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, RsaCaPem(), "SCEP", "EST", "ACME");
        // Only EST is served by this deployment.
        var controller = NewController(db, new FlagStub("EST.Enabled"), new StubCache());

        var rows = Rows(await GetByCaAsync(controller, caId));

        Assert.Equal(new[] { "EST" }, rows.EnumerateArray().Select(r => r.GetProperty("protocol").GetString()).ToArray());
        // Nothing was deleted: turning the flag back on restores the configuration as it was.
        Assert.Equal(3, db.CaProtocolConfigs.Count());
    }

    [Fact]
    public async Task Every_protocol_disabled_leaves_an_empty_listing()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, RsaCaPem(), "SCEP", "EST");
        var controller = NewController(db, new FlagStub(), new StubCache());

        var rows = Rows(await GetByCaAsync(controller, caId));

        Assert.Empty(rows.EnumerateArray().ToList());
        Assert.Equal(2, db.CaProtocolConfigs.Count());
    }

    [Fact]
    public async Task The_ca_hierarchy_leaves_out_protocols_this_system_does_not_serve()
    {
        // The CA detail page's "Protocol Configurations" section reads the hierarchy feed, so the
        // same protocol must not reappear there after being filtered out of the protocol page.
        using var db = InMemoryDbContextFactory.Create();
        var caId = SeedCa(db, RsaCaPem(), "SCEP", "EST");
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminCaController");
        // Only the database, the flags and the HTTP context are reached by GetHierarchy; the rest
        // of the controller's dependencies are not touched on this path.
        var controller = Activator.CreateInstance(
            type, null, null, db, null, null, null, null, null, null, new FlagStub("EST.Enabled"))!;
        GiveHttpContext(controller);

        var result = await (Task<IActionResult>)type.GetMethod("GetHierarchy")!.Invoke(controller, null)!;

        var json = JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        var ca = JsonDocument.Parse(json).RootElement.EnumerateArray().Single(c => c.GetProperty("id").GetGuid() == caId);
        Assert.Equal(
            new[] { "EST" },
            ca.GetProperty("protocolConfigs").EnumerateArray().Select(p => p.GetProperty("protocol").GetString()).ToArray());
    }

    // ---- stubs -----------------------------------------------------------------------------

    /// <summary>A feature flag service whose enabled flags are exactly the names it was given.</summary>
    private sealed class FlagStub(params string[] enabled) : IFeatureFlagService
    {
        private readonly HashSet<string> _enabled = new(enabled, StringComparer.OrdinalIgnoreCase);
        public bool IsEnabled(string flagName) => _enabled.Contains(flagName);
        public string? GetValue(string flagName) => null;
        public (bool Enabled, string? Value)? Get(string flagName) => (IsEnabled(flagName), null);
        public void InvalidateCache() { }
    }

    /// <summary>The authenticated operator the endpoint audits under.</summary>
    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>An in-process distributed cache, enough to hold one step-up token.</summary>
    private sealed class StubCache : IDistributedCache
    {
        private readonly Dictionary<string, byte[]> _entries = new();
        public byte[]? Get(string key) => _entries.TryGetValue(key, out var v) ? v : null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) => _entries.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) { Remove(key); return Task.CompletedTask; }
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _entries[key] = value;
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        { Set(key, value, options); return Task.CompletedTask; }
    }
}
