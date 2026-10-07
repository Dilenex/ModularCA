using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>PUT /api/v1/admin/config/mtls</c>: a list left out of the body keeps its value, an empty
/// list clears it, so the console can remove the last Required Path or Trusted CA Cert Path. The
/// assertions read the in-memory configuration the action changes; writing config.yaml is not
/// exercised (the controller has no <c>EnvVarConfigOverlay</c> here, so the persist step fails).
/// </summary>
public sealed class MtlsConfigUpdateTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "sysadmin" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static SystemConfig Configured()
    {
        var config = new SystemConfig();
        config.Mtls.Enabled = true;
        config.Mtls.AuthSubdomain = "mtls.example";
        config.Mtls.RequiredPaths = ["/api/v1/admin"];
        config.Mtls.TrustedCaCertPaths = ["/etc/modularca/client-ca.pem"];
        return config;
    }

    private static object Controller(SystemConfig config)
    {
        var controller = (ControllerBase)Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "AdminConfigController"),
            config, null, new RecordingAuditService(), new CurrentUserStub(Guid.NewGuid()),
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new RecordingAlertService(), null, null, null, null)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    private static object Body(List<string>? required, List<string>? trusted)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "MtlsUpdateRequest"))!;
        body.GetType().GetProperty("Enabled")!.SetValue(body, true);
        body.GetType().GetProperty("RequiredPaths")!.SetValue(body, required);
        body.GetType().GetProperty("TrustedCaCertPaths")!.SetValue(body, trusted);
        return body;
    }

    private static Task<IActionResult> Put(object controller, object body)
        => (Task<IActionResult>)controller.GetType().GetMethod("UpdateMtls")!.Invoke(controller, [body])!;

    [Fact]
    public async Task An_empty_list_clears_and_an_absent_one_keeps()
    {
        var config = Configured();

        await Put(Controller(config), Body(null, null));
        Assert.Equal(["/api/v1/admin"], config.Mtls.RequiredPaths);
        Assert.Equal(["/etc/modularca/client-ca.pem"], config.Mtls.TrustedCaCertPaths);

        await Put(Controller(config), Body([], null));
        Assert.Empty(config.Mtls.RequiredPaths);
        Assert.Equal(["/etc/modularca/client-ca.pem"], config.Mtls.TrustedCaCertPaths);

        await Put(Controller(config), Body(null, []));
        Assert.Empty(config.Mtls.TrustedCaCertPaths);
    }

    /// <summary>A listed trust anchor that does not load is still refused, and nothing changes.</summary>
    [Fact]
    public async Task A_missing_anchor_is_refused_before_anything_changes()
    {
        var config = Configured();

        var result = await Put(Controller(config), Body([], [Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}.pem")]));

        Assert.Equal(400, Assert.IsAssignableFrom<ObjectResult>(result).StatusCode);
        Assert.Equal(["/api/v1/admin"], config.Mtls.RequiredPaths);
        Assert.Equal(["/etc/modularca/client-ca.pem"], config.Mtls.TrustedCaCertPaths);
    }
}
