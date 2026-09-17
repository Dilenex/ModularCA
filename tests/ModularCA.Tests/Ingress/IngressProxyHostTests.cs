using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.Ingress;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// A node stood in for by a Kestrel host on a loopback port: answers the health probe,
/// echoes what it received on every other path, and on <c>/kerberos</c> challenges with
/// <c>WWW-Authenticate: Negotiate</c> until an <c>Authorization</c> header arrives, which it
/// echoes back in a response header. Every request it sees is recorded.
/// </summary>
internal sealed class StubNode : IAsyncDisposable
{
    private readonly WebApplication _app;

    public string Name { get; }
    public Uri Address { get; }
    public List<string> Paths { get; } = new();

    private StubNode(string name, WebApplication app, Uri address)
    {
        Name = name;
        _app = app;
        Address = address;
    }

    public static async Task<StubNode> StartAsync(string name)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();
        StubNode? self = null;

        app.MapGet("/health/live", () => Results.Json(new { status = "healthy" }));
        app.Map("/kerberos", (HttpContext context) =>
        {
            self!.Paths.Add(context.Request.Path);
            if (context.Request.Headers.TryGetValue("Authorization", out var authorization))
            {
                context.Response.Headers["X-Echo-Authorization"] = authorization.ToString();
                return Results.Text("ok");
            }
            context.Response.Headers.WWWAuthenticate = "Negotiate";
            return Results.StatusCode(StatusCodes.Status401Unauthorized);
        });
        app.Map("/{**path}", (HttpContext context) =>
        {
            self!.Paths.Add(context.Request.Path);
            return Results.Json(new
            {
                node = name,
                path = context.Request.Path.Value,
                host = context.Request.Host.Value,
                forwardedHost = context.Request.Headers["X-Forwarded-Host"].ToString(),
                forwardedProto = context.Request.Headers["X-Forwarded-Proto"].ToString(),
                forwardedFor = context.Request.Headers["X-Forwarded-For"].ToString(),
                authorization = context.Request.Headers["Authorization"].ToString(),
            });
        });

        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        self = new StubNode(name, app, new Uri(address.Replace("[::1]", "127.0.0.1")));
        return self;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>
/// The real ingress wiring from the API (<c>IngressHosting.AddIngress</c> and
/// <c>UseIngress</c>, loaded by reflection) hosted on two loopback listeners, one standing
/// for the HTTPS listener and one for the plain-HTTP listener, in front of stub nodes, with
/// a local endpoint behind the branch standing for this process's own roles.
/// </summary>
internal sealed class IngressHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    public int SecurePort { get; }
    public int PlainPort { get; }
    public IngressRouteTableService Table { get; }

    private IngressHost(WebApplication app, int securePort, int plainPort, IngressRouteTableService table)
    {
        _app = app;
        SecurePort = securePort;
        PlainPort = plainPort;
        Table = table;
    }

    /// <summary>A free loopback port; released before use, so a race is possible but unlikely.</summary>
    public static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public static async Task<IngressHost> StartAsync(IngressConfig config)
    {
        var securePort = FreePort();
        var plainPort = FreePort();
        var table = new IngressRouteTableService(config, () => Array.Empty<TenantHostnameUpstream>(), TimeSpan.FromMinutes(5));
        table.LoadNow();
        var trust = Activator.CreateInstance(IngressApi.TrustPolicy, null, false)!;

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Listen(IPAddress.Loopback, securePort);
            k.Listen(IPAddress.Loopback, plainPort);
        });
        IngressApi.Call(IngressApi.Hosting, "AddIngress", builder.Services, config, table, trust);

        var app = builder.Build();
        IngressApi.Call(IngressApi.Hosting, "UseIngress", app, table, plainPort);
        app.UseRouting();
        app.Map("/{**path}", (HttpContext context) => Results.Text("local:" + context.Request.Host.Host));

        await app.StartAsync();
        return new IngressHost(app, securePort, plainPort, table);
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>
/// The ingress in front of stub nodes: a host with an upstream is proxied with the forwarded
/// headers added and the Kerberos headers untouched in both directions; a host without one
/// is served locally; a plain-HTTP arrival reaches the node's plain listener when the route
/// names one; a node that fails its probes is answered 503 with a body naming the host.
/// </summary>
public sealed class IngressProxyHostTests : IAsyncLifetime
{
    private StubNode _secure = null!;
    private StubNode _plain = null!;
    private IngressHost _ingress = null!;
    private int _closedPort;
    private readonly HttpClient _client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });

    public async Task InitializeAsync()
    {
        _secure = await StubNode.StartAsync("secure");
        _plain = await StubNode.StartAsync("plain");
        _closedPort = IngressHost.FreePort();
        var config = new IngressConfig
        {
            HealthCheckIntervalSeconds = 1,
            HealthCheckTimeoutSeconds = 1,
            Routes =
            {
                new IngressRouteConfig { Host = "both.test", Upstream = _secure.Address.ToString(), PlainHttpUpstream = _plain.Address.ToString() },
                new IngressRouteConfig { Host = "one.test", Upstream = _secure.Address.ToString() },
                new IngressRouteConfig { Host = "down.test", Upstream = $"http://127.0.0.1:{_closedPort}" },
            },
        };
        _ingress = await IngressHost.StartAsync(config);
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _ingress.DisposeAsync();
        await _secure.DisposeAsync();
        await _plain.DisposeAsync();
    }

    private HttpRequestMessage Request(int port, string host, string path, HttpMethod? method = null)
    {
        var request = new HttpRequestMessage(method ?? HttpMethod.Get, $"http://127.0.0.1:{port}{path}");
        request.Headers.Host = host;
        return request;
    }

    private static async Task<JsonElement> JsonOf(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    [Fact]
    public async Task A_host_with_an_upstream_is_proxied_with_the_forwarded_headers_added()
    {
        var response = await _client.SendAsync(Request(_ingress.SecurePort, "one.test", "/acme/directory"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await JsonOf(response);
        Assert.Equal("secure", body.GetProperty("node").GetString());
        Assert.Equal("/acme/directory", body.GetProperty("path").GetString());
        Assert.Equal("one.test", body.GetProperty("forwardedHost").GetString());
        Assert.Equal("http", body.GetProperty("forwardedProto").GetString());
        Assert.Equal("127.0.0.1", body.GetProperty("forwardedFor").GetString());
    }

    [Fact]
    public async Task A_host_with_no_upstream_is_served_locally_and_no_node_sees_it()
    {
        var before = _secure.Paths.Count + _plain.Paths.Count;
        var response = await _client.SendAsync(Request(_ingress.SecurePort, "public.test", "/api/v1/version"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("local:public.test", await response.Content.ReadAsStringAsync());
        Assert.Equal(before, _secure.Paths.Count + _plain.Paths.Count);
    }

    [Fact]
    public async Task The_negotiate_authorization_header_reaches_the_node_untouched()
    {
        const string token = "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw==";
        var request = Request(_ingress.SecurePort, "one.test", "/kerberos");
        request.Headers.Authorization = AuthenticationHeaderValue.Parse(token);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(token, response.Headers.GetValues("X-Echo-Authorization").Single());
    }

    [Fact]
    public async Task The_www_authenticate_challenge_comes_back_through_the_ingress_untouched()
    {
        var response = await _client.SendAsync(Request(_ingress.SecurePort, "one.test", "/kerberos"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Negotiate", challenge.Scheme);
        Assert.Null(challenge.Parameter);
    }

    [Fact]
    public async Task A_plain_http_arrival_goes_to_the_plain_listener_of_the_node_when_the_route_names_one()
    {
        var plain = await JsonOf(await _client.SendAsync(Request(_ingress.PlainPort, "both.test", "/crl/tenant.crl")));
        var secure = await JsonOf(await _client.SendAsync(Request(_ingress.SecurePort, "both.test", "/crl/tenant.crl")));
        var noPlain = await JsonOf(await _client.SendAsync(Request(_ingress.PlainPort, "one.test", "/crl/tenant.crl")));

        Assert.Equal("plain", plain.GetProperty("node").GetString());
        Assert.Equal("secure", secure.GetProperty("node").GetString());
        Assert.Equal("secure", noPlain.GetProperty("node").GetString());
        Assert.Equal("both.test", plain.GetProperty("forwardedHost").GetString());
    }

    [Fact]
    public async Task A_node_that_fails_its_probes_is_answered_503_with_a_body_naming_the_host()
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        HttpResponseMessage? response = null;
        while (DateTime.UtcNow < deadline)
        {
            response = await _client.SendAsync(Request(_ingress.SecurePort, "down.test", "/ocsp"));
            if (response.StatusCode == HttpStatusCode.ServiceUnavailable && response.Content.Headers.ContentType?.MediaType == "application/json")
                break;
            await Task.Delay(250);
        }

        Assert.NotNull(response);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response!.StatusCode);
        var body = await JsonOf(response);
        Assert.Equal("down.test", body.GetProperty("host").GetString());
        Assert.Contains("down.test", body.GetProperty("error").GetString());
        Assert.Contains("health", body.GetProperty("error").GetString());
        Assert.Equal("10", response.Headers.RetryAfter!.Delta is { } d ? ((int)d.TotalSeconds).ToString() : response.Headers.RetryAfter.ToString());
    }
}
