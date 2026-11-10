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
/// <c>PUT /api/v1/admin/config/http</c> and <c>/security</c> and the trusted proxy CIDRs: an entry
/// that does not parse is refused with 400 and the entry named, an empty value clears the list,
/// and neither save may leave BehindReverseProxy on with no proxy named, since startup refuses
/// both. The assertions read the in-memory configuration; writing config.yaml is not exercised.
/// </summary>
public sealed class TrustedProxyConfigUpdateTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "sysadmin" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static SystemConfig Configured(bool behindProxy, string cidrs)
    {
        var config = new SystemConfig();
        config.Security.BehindReverseProxy = behindProxy;
        config.Http.TrustedProxyCidrs = cidrs;
        return config;
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

    private static Task<IActionResult> PutHttp(object controller, string? cidrs)
        => (Task<IActionResult>)controller.GetType().GetMethod("UpdateHttp")!.Invoke(controller,
            [new HttpConfig { Port = 8080, TrustedProxyCidrs = cidrs! }])!;

    private static Task<IActionResult> PutSecurity(object controller, bool behindProxy)
        => (Task<IActionResult>)controller.GetType().GetMethod("UpdateSecurity")!.Invoke(controller,
            [new SecurityUpdateRequest { BehindReverseProxy = behindProxy }])!;

    private static string Error(IActionResult result)
    {
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        return (string)bad.Value!.GetType().GetProperty("error")!.GetValue(bad.Value)!;
    }

    [Fact]
    public async Task A_malformed_entry_is_refused_and_named()
    {
        var config = Configured(behindProxy: false, "10.0.1.0/24");

        var result = await PutHttp(Controller(config), "10.0.1.0/24, 10.0.2.7");

        Assert.Contains("10.0.2.7", Error(result));
        Assert.Equal("10.0.1.0/24", config.Http.TrustedProxyCidrs);
    }

    [Fact]
    public async Task An_empty_value_clears_the_list()
    {
        var config = Configured(behindProxy: false, "10.0.1.0/24");

        await PutHttp(Controller(config), "");

        Assert.Equal("", config.Http.TrustedProxyCidrs);
    }

    [Fact]
    public async Task Clearing_the_list_behind_a_proxy_is_refused()
    {
        var config = Configured(behindProxy: true, "10.0.1.0/24");

        var result = await PutHttp(Controller(config), " ");

        Assert.Contains("TrustedProxyCidrs", Error(result));
        Assert.Equal("10.0.1.0/24", config.Http.TrustedProxyCidrs);
    }

    [Fact]
    public async Task Turning_proxy_mode_on_with_no_proxy_named_is_refused()
    {
        var config = Configured(behindProxy: false, "");

        var result = await PutSecurity(Controller(config), behindProxy: true);

        Assert.Contains("Save the trusted proxy CIDRs first", Error(result));
        Assert.False(config.Security.BehindReverseProxy);
    }

    /// <summary>
    /// A save that fails for an unexpected reason answers with a generic message and the
    /// correlation id, not the exception's message, which can name paths and hosts. Here the
    /// file write fails because the harness has no environment overlay.
    /// </summary>
    [Fact]
    public async Task A_failed_save_does_not_echo_the_exception_message()
    {
        var config = Configured(behindProxy: false, "");
        var controller = Controller(config);
        ((ControllerBase)controller).HttpContext.TraceIdentifier = "trace-42";

        var result = Assert.IsAssignableFrom<ObjectResult>(await PutHttp(controller, ""));

        Assert.Equal(500, result.StatusCode);
        var body = result.Value!;
        Assert.Null(body.GetType().GetProperty("details"));
        Assert.Equal("trace-42", body.GetType().GetProperty("correlationId")!.GetValue(body));
        var error = (string)body.GetType().GetProperty("error")!.GetValue(body)!;
        Assert.Contains("trace-42", error);
        Assert.DoesNotContain("Object reference", error);
    }

    [Fact]
    public async Task Turning_proxy_mode_on_with_a_proxy_named_is_accepted()
    {
        var config = Configured(behindProxy: false, "10.0.1.5/32");

        await PutSecurity(Controller(config), behindProxy: true);

        Assert.True(config.Security.BehindReverseProxy);
    }
}
