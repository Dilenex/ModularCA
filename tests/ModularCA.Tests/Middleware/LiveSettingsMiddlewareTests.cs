using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Channels;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// A setting the console marks Live is read when a request arrives, not when the middleware was
/// built: each test builds the middleware once, changes the configuration it was given the way a
/// settings endpoint does, and expects the next request to be treated by the new value.
/// </summary>
public class LiveSettingsMiddlewareTests
{
    private const string Ns = "ModularCA.API.Middleware.";

    private sealed class Pipeline(object middleware)
    {
        public int Reached;

        public async Task<HttpContext> Send(HttpContext context)
        {
            await (Task)middleware.GetType().GetMethod("InvokeAsync")!.Invoke(middleware, [context])!;
            return context;
        }
    }

    private static Pipeline Build(string type, params object[] dependencies)
    {
        Pipeline? pipeline = null;
        RequestDelegate next = _ => { pipeline!.Reached++; return Task.CompletedTask; };
        pipeline = new Pipeline(Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + type), [next, .. dependencies])!);
        return pipeline;
    }

    private static DefaultHttpContext Request(string path, string remoteIp = "10.0.0.2", bool https = false, string host = "ca.example.test")
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Scheme = https ? "https" : "http";
        context.Request.Host = new HostString(host);
        context.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
        return context;
    }

    // ---- Security.BindJwtToIp ------------------------------------------------------------------

    private static DefaultHttpContext BoundTo(string tokenIp, string remoteIp)
    {
        var context = Request("/api/v1/admin/users", remoteIp);
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("ip", tokenIp), new Claim("sub", Guid.NewGuid().ToString())], "test"));
        return context;
    }

    [Fact]
    public async Task Jwt_ip_binding_follows_the_mode_as_it_is_saved()
    {
        var config = new SystemConfig();
        var pipeline = Build("JwtIpBindingMiddleware", config, new ServiceCollection().BuildServiceProvider());

        // Off at start: a token bound to another address passes.
        await pipeline.Send(BoundTo("10.0.0.1", "10.0.0.2"));
        Assert.Equal(1, pipeline.Reached);

        config.Security.BindJwtToIp = JwtIpBindingMode.Exact;
        var refused = await pipeline.Send(BoundTo("10.0.0.1", "10.0.0.2"));
        Assert.Equal(401, refused.Response.StatusCode);
        Assert.Equal(1, pipeline.Reached);
        await pipeline.Send(BoundTo("10.0.0.1", "10.0.0.1"));
        Assert.Equal(2, pipeline.Reached);

        config.Security.BindJwtToIp = JwtIpBindingMode.Subnet24;
        await pipeline.Send(BoundTo("10.0.0.1", "10.0.0.2"));
        Assert.Equal(3, pipeline.Reached);

        config.Security.BindJwtToIp = JwtIpBindingMode.Off;
        await pipeline.Send(BoundTo("10.0.0.1", "192.0.2.9"));
        Assert.Equal(4, pipeline.Reached);
    }

    // ---- IpWhitelist.Enabled -------------------------------------------------------------------

    private sealed class DenyEverything : IWhitelistService
    {
        public int Evaluations;
        public bool HasSnapshot => true;
        public bool IsWarm => true;
        public Task ReloadAsync(CancellationToken ct = default) => Task.CompletedTask;
        public WhitelistDecision Evaluate(string path, IPAddress? remoteIp) { Evaluations++; return WhitelistDecision.Deny; }
        public Task<List<WhitelistEntity>> GetAllAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<WhitelistEntity?> GetByIdAsync(Guid id, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<WhitelistEntity> CreateAsync(WhitelistEntity entity, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<WhitelistEntity?> UpdateAsync(Guid id, WhitelistEntity updates, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<bool> DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotSupportedException();
    }

    [Fact]
    public async Task The_ip_whitelist_switch_is_read_on_every_request()
    {
        var config = new SystemConfig { IpWhitelist = { Enabled = false } };
        var rules = new DenyEverything();
        var pipeline = Build("IpWhitelistMiddleware", config, rules);

        // Off at start: nothing is evaluated.
        await pipeline.Send(Request("/api/v1/acme/directory"));
        Assert.Equal((1, 0), (pipeline.Reached, rules.Evaluations));

        config.IpWhitelist.Enabled = true;
        var blocked = await pipeline.Send(Request("/api/v1/acme/directory"));
        Assert.Equal(403, blocked.Response.StatusCode);
        Assert.True(blocked.Items.ContainsKey("IpWhitelistBlocked"));
        Assert.Equal((1, 1), (pipeline.Reached, rules.Evaluations));

        config.IpWhitelist.Enabled = false;
        await pipeline.Send(Request("/api/v1/acme/directory"));
        Assert.Equal((2, 1), (pipeline.Reached, rules.Evaluations));
    }

    // ---- NetworkAudit.* ------------------------------------------------------------------------

    /// <summary>
    /// How many rows the middleware has queued for the audit database for <paramref name="path"/>.
    /// Nothing drains the queue in a test run, so what is on it is taken off into
    /// <paramref name="seen"/> and counted there.
    /// </summary>
    private static int Queued(List<AuditNetworkEntity> seen, string path)
    {
        var channel = (Channel<AuditNetworkEntity>)typeof(AuditNetworkDrainService)
            .GetField("_channel", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
        while (channel.Reader.TryRead(out var row))
            seen.Add(row);
        return seen.Count(row => row.RequestPath == path);
    }

    [Fact]
    public async Task Network_audit_follows_its_settings_as_they_are_saved()
    {
        var config = new SystemConfig { NetworkAudit = { Enabled = false } };
        var pipeline = Build("RequestAuditMiddleware", config);
        var admin = $"/api/v1/admin/live-{Guid.NewGuid():N}";
        var other = $"/assets/live-{Guid.NewGuid():N}.js";
        var seen = new List<AuditNetworkEntity>();

        // Off at start: nothing is recorded.
        await pipeline.Send(Request(admin));
        Assert.Equal(0, Queued(seen, admin));

        config.NetworkAudit.Enabled = true;
        await pipeline.Send(Request(admin));
        await pipeline.Send(Request(other));
        Assert.Equal((1, 0), (Queued(seen, admin), Queued(seen, other)));

        config.NetworkAudit.LogAllRequests = true;
        await pipeline.Send(Request(other));
        Assert.Equal((1, 1), (Queued(seen, admin), Queued(seen, other)));

        // The endpoint replaces the list; the middleware must not hold the one it started with.
        config.NetworkAudit.ExcludePaths = ["/api/v1/admin/live-"];
        await pipeline.Send(Request(admin));
        Assert.Equal((1, 1), (Queued(seen, admin), Queued(seen, other)));

        config.NetworkAudit.Enabled = false;
        await pipeline.Send(Request(other));
        Assert.Equal((1, 1), (Queued(seen, admin), Queued(seen, other)));
        Assert.Equal(6, pipeline.Reached);
    }

    // ---- Mtls.RequiredPaths --------------------------------------------------------------------

    [Fact]
    public async Task Mtls_required_paths_are_read_on_every_request()
    {
        var config = new SystemConfig { Mtls = { Enabled = true } };
        var pipeline = Build("MtlsMiddleware", config);

        await pipeline.Send(Request("/api/v1/admin/users"));
        Assert.Equal(1, pipeline.Reached);

        // The endpoint replaces the list; the middleware must not hold the one it started with.
        config.Mtls.RequiredPaths = ["/api/v1/admin"];
        var refused = await pipeline.Send(Request("/api/v1/admin/users"));
        Assert.Equal(403, refused.Response.StatusCode);
        await pipeline.Send(Request("/api/v1/public/info"));
        Assert.Equal(2, pipeline.Reached);

        config.Mtls.RequiredPaths = [];
        await pipeline.Send(Request("/api/v1/admin/users"));
        Assert.Equal(3, pipeline.Reached);
    }

    /// <summary>
    /// Whether mTLS is on still waits for a restart, because the listener's handshake does: a
    /// process that started without it asks nobody for a certificate, so demanding one on a path
    /// would refuse every request to it.
    /// </summary>
    [Fact]
    public async Task Mtls_turned_on_after_start_demands_no_certificate_until_the_restart()
    {
        var config = new SystemConfig { Mtls = { Enabled = false } };
        var pipeline = Build("MtlsMiddleware", config);

        config.Mtls.Enabled = true;
        config.Mtls.RequiredPaths = ["/api/v1/admin"];
        await pipeline.Send(Request("/api/v1/admin/users"));

        Assert.Equal(1, pipeline.Reached);
    }

    // ---- Http.Hsts.* ---------------------------------------------------------------------------

    private static string Hsts(HttpContext context) => context.Response.Headers.StrictTransportSecurity.ToString();

    [Fact]
    public async Task The_hsts_header_follows_its_settings_as_they_are_saved()
    {
        var config = new SystemConfig();
        var pipeline = Build("HstsHeaderMiddleware", config);

        Assert.Equal("max-age=31536000; includeSubDomains", Hsts(await pipeline.Send(Request("/admin", https: true))));

        config.Http.Hsts.MaxAgeSeconds = 86400;
        config.Http.Hsts.IncludeSubDomains = false;
        config.Http.Hsts.Preload = true;
        Assert.Equal("max-age=86400; preload", Hsts(await pipeline.Send(Request("/admin", https: true))));

        config.Http.Hsts = new HstsConfig { MaxAgeSeconds = 0 };
        Assert.Equal("max-age=0; includeSubDomains", Hsts(await pipeline.Send(Request("/admin", https: true))));
        Assert.Equal(3, pipeline.Reached);
    }

    /// <summary>Where ASP.NET Core's HSTS middleware, which this one replaces, set nothing.</summary>
    [Theory]
    [InlineData(false, "ca.example.test")]
    [InlineData(true, "localhost")]
    [InlineData(true, "LOCALHOST")]
    [InlineData(true, "127.0.0.1")]
    [InlineData(true, "[::1]")]
    public async Task The_hsts_header_is_not_set_over_plain_http_or_for_a_loopback_name(bool https, string host)
    {
        var pipeline = Build("HstsHeaderMiddleware", new SystemConfig());

        var context = await pipeline.Send(Request("/admin", https: https, host: host));

        Assert.Equal(string.Empty, Hsts(context));
        Assert.Equal(1, pipeline.Reached);
    }

    // ---- Http.EnableCors, Http.CorsOrigins -----------------------------------------------------

    private static (Func<bool> Active, Func<CorsPolicy?> Policy) CorsProvider(SystemConfig config)
    {
        var type = ApiAssembly.TypeNamed(Ns + "SettingsCorsPolicyProvider");
        var provider = (ICorsPolicyProvider)Activator.CreateInstance(type, config)!;
        return (
            () => (bool)type.GetProperty("Active")!.GetValue(provider)!,
            () => provider.GetPolicyAsync(new DefaultHttpContext(), null).GetAwaiter().GetResult());
    }

    [Fact]
    public void The_cors_policy_follows_the_switch_and_the_origins_as_they_are_saved()
    {
        var config = new SystemConfig();
        var (active, policy) = CorsProvider(config);

        // Off at start, and on with no origin: no policy, so the request skips the CORS middleware.
        Assert.False(active());
        Assert.Null(policy());
        config.Http.EnableCors = true;
        Assert.False(active());
        Assert.Null(policy());

        config.Http.CorsOrigins = "https://app.example.test, https://ops.example.test";
        Assert.True(active());
        var first = policy()!;
        Assert.Equal(["https://app.example.test", "https://ops.example.test"], first.Origins);
        Assert.False(first.SupportsCredentials);
        Assert.False(first.AllowAnyOrigin);
        Assert.Contains("PATCH", first.Methods);
        Assert.Contains("DPoP", first.Headers);
        // Built once for a list, not per request.
        Assert.Same(first, policy());

        config.Http.CorsOrigins = "https://new.example.test";
        Assert.Equal(["https://new.example.test"], policy()!.Origins);

        config.Http.EnableCors = false;
        Assert.False(active());
        Assert.Null(policy());
    }

    /// <summary>A list a start would have refused allows nothing, rather than everything.</summary>
    [Theory]
    [InlineData("*")]
    [InlineData("https://app.example.test, *")]
    [InlineData("http://app.example.test")]
    [InlineData("not an origin")]
    public void An_origin_list_that_breaks_the_startup_rules_gives_no_cors_policy(string origins)
    {
        var config = new SystemConfig { Http = { EnableCors = true, CorsOrigins = origins } };
        var (active, policy) = CorsProvider(config);

        Assert.False(active());
        Assert.Null(policy());
    }
}
