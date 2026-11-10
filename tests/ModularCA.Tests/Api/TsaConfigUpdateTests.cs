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
/// <c>PUT /api/v1/admin/config/tsa</c>: a dotted OID is taken, an empty one restores the default,
/// and anything else is refused before the configuration changes. The assertions read the
/// in-memory configuration; writing it out is not exercised (no <c>EnvVarConfigOverlay</c> here).
/// </summary>
public sealed class TsaConfigUpdateTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "sysadmin" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static object Controller(SystemConfig config)
    {
        var controller = (ControllerBase)Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "AdminConfigController"),
            config, null, new RecordingAuditService(), new CurrentUserStub(Guid.NewGuid()),
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new RecordingAlertService(), null, null, null, null, null)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    private static Task<IActionResult> Put(SystemConfig config, string? policyOid)
    {
        var controller = Controller(config);
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "TsaUpdateRequest"))!;
        body.GetType().GetProperty("PolicyOid")!.SetValue(body, policyOid);
        return (Task<IActionResult>)controller.GetType().GetMethod("UpdateTsa")!.Invoke(controller, [body])!;
    }

    [Fact]
    public async Task A_dotted_oid_is_taken_and_an_empty_one_restores_the_default()
    {
        var config = new SystemConfig();

        await Put(config, " 1.3.6.1.4.1.99999.7.1 ");
        Assert.Equal("1.3.6.1.4.1.99999.7.1", config.Tsa.PolicyOid);

        await Put(config, "");
        Assert.Equal(TsaConfig.DefaultPolicyOid, config.Tsa.PolicyOid);
    }

    [Theory]
    [InlineData("my policy")]
    [InlineData("1.3.6.1.4.1.66874.1.5.")]
    [InlineData("3.1.2")]
    public async Task A_value_that_is_not_an_oid_is_refused_before_anything_changes(string policyOid)
    {
        var config = new SystemConfig();

        var result = await Put(config, policyOid);

        Assert.Equal(400, Assert.IsAssignableFrom<ObjectResult>(result).StatusCode);
        Assert.Equal(TsaConfig.DefaultPolicyOid, config.Tsa.PolicyOid);
    }
}
