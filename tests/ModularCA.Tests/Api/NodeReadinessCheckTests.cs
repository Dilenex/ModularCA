using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.ProxyProtocol;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Ingress;
using ModularCA.Tests.Roles;
using Xunit;
using IPNetwork = System.Net.IPNetwork;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>--role node --check-ready</c>, the node container's health command
/// (<c>NodeReadinessCheck</c>, loaded from the built API by reflection): the listener it asks is
/// found from <c>config.yaml</c>, a wildcard bind reached over loopback; it answers 0 when the
/// node's <c>/health/live</c> answers 200, and 1 for a 503 or a closed port, while
/// <c>--live</c> asks <c>/health</c> and so passes for a node that is up but not ready. On real
/// Kestrel listeners with a self-signed certificate: with the PROXY protocol required on the
/// HTTPS listener it uses the plain-HTTP listener, or, when loopback is a trusted proxy, sends a
/// v2 LOCAL header; it never connects where the node would close it. With
/// <c>Health.LoopbackPort</c> set it asks the loopback-only health listener
/// (<c>HealthListener</c>), which serves the health paths and answers 404 for every other, and
/// so succeeds with the PROXY protocol on both main listeners. The built binary is run as a
/// container manager would run it. In the EnvVars collection because the check applies the
/// environment overlay, which <c>MODULARCA__HEALTH__LOOPBACKPORT</c> tests set.
/// </summary>
[Collection(ModularCA.Tests.TestUtils.EnvVarsCollection.Name)]
public sealed class NodeReadinessCheckTests : IDisposable
{
    private readonly string _configDir = Path.Combine(Path.GetTempPath(), "mca-nodeready-" + Guid.NewGuid().ToString("N"));

    /// <summary>Creates the configuration directory each test writes its <c>config.yaml</c> into.</summary>
    public NodeReadinessCheckTests() => Directory.CreateDirectory(_configDir);

    /// <summary>Removes the configuration directory.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_configDir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static Type Check => ApiAssembly.TypeNamed("ModularCA.API.Startup.NodeReadinessCheck");

    // ── Listener resolution ─────────────────────────────────────────────

    [Theory]
    [InlineData("0.0.0.0", "127.0.0.1")]
    [InlineData("*", "127.0.0.1")]
    [InlineData("[::]", "127.0.0.1")]
    [InlineData("::", "::1")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("127.0.0.5", "127.0.0.5")]
    [InlineData("::1", "::1")]
    [InlineData("[::1]", "::1")]
    [InlineData("10.0.0.5", null)]
    [InlineData("2001:db8::5", null)]
    [InlineData("not-an-address", null)]
    public void A_wildcard_bind_is_reached_over_loopback_and_another_address_not_at_all(string listen, string? expected)
    {
        var address = (IPAddress?)Check.GetMethod("LoopbackFor", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, [listen]);

        Assert.Equal(expected, address?.ToString());
    }

    [Fact]
    public void The_default_settings_probe_https_on_loopback_at_the_https_port()
    {
        var target = Resolve(new SystemConfig(), "Node", out _);

        Assert.NotNull(target);
        Assert.Equal(("https", "127.0.0.1", 8443, false), Describe(target!));
    }

    [Fact]
    public void The_first_usable_address_of_the_list_is_used()
    {
        var config = new SystemConfig();
        config.Https.ListenAddress = "10.0.0.5, ::1, 127.0.0.1";
        config.Https.Port = 9443;

        Assert.Equal(("https", "::1", 9443, false), Describe(Resolve(config, "Node", out _)!));
    }

    [Fact]
    public void A_list_of_other_addresses_alone_is_refused_with_the_fix()
    {
        var config = new SystemConfig();
        config.Https.ListenAddress = "10.0.0.5,192.168.1.9";

        var target = Resolve(config, "Node", out var reason);

        Assert.Null(target);
        Assert.Contains("Https.ListenAddress", reason);
        Assert.Contains("127.0.0.1", reason);
    }

    [Fact]
    public void Https_taking_PROXY_from_elsewhere_falls_back_to_plain_http_where_this_process_opens_it()
    {
        var config = ProxyConfig(https: true, http: false, trusted: "10.100.105.22/32");

        Assert.Equal(("http", "127.0.0.1", 8080, false), Describe(Resolve(config, "Node", out _)!));
        Assert.Equal(("http", "127.0.0.1", 8080, false), Describe(Resolve(config, "Ingress", out _)!));

        // The control role alone opens no plain-HTTP listener, and the HTTPS one would close the probe.
        Assert.Null(Resolve(config, "Control", out var reason));
        Assert.Contains("Http.ProxyProtocolTrustedCidrs", reason);
        config.Http.Port = 0;
        Assert.Null(Resolve(config, "Node", out _));
    }

    [Fact]
    public void A_PROXY_listener_that_trusts_loopback_is_asked_with_a_local_header()
    {
        var config = ProxyConfig(https: true, http: true, trusted: "10.100.105.22/32,127.0.0.1/32");

        Assert.Equal(("https", "127.0.0.1", 8443, true), Describe(Resolve(config, "Node", out _)!));
    }

    [Fact]
    public void A_listener_without_PROXY_is_preferred_to_a_local_header()
    {
        var config = ProxyConfig(https: false, http: true, trusted: "127.0.0.0/8");

        Assert.Equal(("https", "127.0.0.1", 8443, false), Describe(Resolve(config, "Node", out _)!));
    }

    [Fact]
    public void Both_listeners_taking_PROXY_from_elsewhere_is_refused_without_trusting_loopback()
    {
        var config = ProxyConfig(https: true, http: true, trusted: "10.100.105.22/32");

        var target = Resolve(config, "Node", out var reason);

        Assert.Null(target);
        Assert.Contains("Both listeners take the PROXY protocol", reason);
        Assert.Contains("127.0.0.1 is not in Http.ProxyProtocolTrustedCidrs", reason);
    }

    [Fact]
    public void The_health_port_is_preferred_to_every_main_listener_and_is_plain_http_on_loopback()
    {
        var plain = new SystemConfig();
        plain.Health.LoopbackPort = 8081;
        Assert.Equal(("http", "127.0.0.1", 8081, false), Describe(Resolve(plain, "Node", out _)!));

        // Whatever the main listeners take, and wherever they are bound, and for the control role
        // alone, which opens no plain-HTTP listener.
        var proxied = ProxyConfig(https: true, http: true, trusted: "10.100.105.22/32");
        proxied.Health.LoopbackPort = 8081;
        proxied.Https.ListenAddress = "10.0.0.5";
        Assert.Equal(("http", "127.0.0.1", 8081, false), Describe(Resolve(proxied, "Control", out _)!));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65536)]
    public void A_health_port_that_is_no_port_is_refused(int port)
    {
        var config = new SystemConfig();
        config.Health.LoopbackPort = port;

        Assert.Null(Resolve(config, "Node", out var reason));
        Assert.Contains("Health.LoopbackPort", reason);
    }

    [Fact]
    public void Both_listeners_on_PROXY_name_the_health_port_as_the_fix()
    {
        Resolve(ProxyConfig(https: true, http: true, trusted: "10.100.105.22/32"), "Node", out var reason);

        Assert.Contains("Health.LoopbackPort", reason);
    }

    [Theory]
    [InlineData("/health", true)]
    [InlineData("/health/live", true)]
    [InlineData("/health/ready", true)]
    [InlineData("/HEALTH/Live", true)]
    [InlineData("/", false)]
    [InlineData("/healthz", false)]
    [InlineData("/health/other", false)]
    [InlineData("/health/live/", false)]
    [InlineData("/api/v1/admin/users", false)]
    [InlineData("/metrics", false)]
    public void The_health_port_serves_the_three_health_paths_only(string path, bool served)
    {
        var listener = ApiAssembly.TypeNamed("ModularCA.API.Startup.HealthListener");
        var isHealth = (bool)listener.GetMethod("IsHealthPath", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, [new PathString(path)])!;

        Assert.Equal(served, isHealth);
    }

    [Fact]
    public void The_local_header_is_a_v2_LOCAL_with_no_address_block_that_the_node_reads_as_one()
    {
        var header = ((ReadOnlyMemory<byte>)Check.GetProperty("ProxyV2LocalHeader", BindingFlags.Public | BindingFlags.Static)!.GetValue(null)!).ToArray();

        var parsed = ProxyProtocolParser.Parse(new System.Buffers.ReadOnlySequence<byte>(header));

        Assert.Equal(ProxyHeaderStatus.Complete, parsed.Status);
        Assert.Equal(header.Length, parsed.HeaderLength);
        Assert.Equal(2, parsed.Version);
        Assert.Equal(ProxyCommand.Local, parsed.Command);
        Assert.Null(parsed.Source);
    }

    // ── Against real Kestrel listeners ──────────────────────────────────

    [Fact]
    public async Task A_healthy_node_is_ready_and_alive_over_https_with_a_self_signed_certificate()
    {
        await using var node = await TestNode.StartAsync();
        WriteConfig(node);

        var (ready, readyOutput) = await RunAsync();
        Assert.True(ready == 0, readyOutput);
        Assert.Contains($"ready: https://127.0.0.1:{node.HttpsPort}/health/live answered 200 (healthy)", readyOutput);

        var (alive, aliveOutput) = await RunAsync("--live");
        Assert.True(alive == 0, aliveOutput);
        Assert.Contains($"alive: https://127.0.0.1:{node.HttpsPort}/health answered 200", aliveOutput);
    }

    [Fact]
    public async Task A_node_answering_503_is_not_ready_but_is_alive()
    {
        await using var node = await TestNode.StartAsync();
        node.LiveStatus = StatusCodes.Status503ServiceUnavailable;
        WriteConfig(node);

        var (ready, readyOutput) = await RunAsync();
        Assert.True(ready == 1, readyOutput);
        Assert.Contains("not ready:", readyOutput);
        Assert.Contains("answered 503 (unhealthy)", readyOutput);

        var (alive, aliveOutput) = await RunAsync("--live");
        Assert.True(alive == 0, aliveOutput);
    }

    [Fact]
    public async Task A_closed_port_is_neither_ready_nor_alive()
    {
        WriteConfig(IngressHost.FreePort(), IngressHost.FreePort());

        var (ready, readyOutput) = await RunAsync();
        Assert.True(ready == 1, readyOutput);
        Assert.Contains("not ready:", readyOutput);

        var (alive, aliveOutput) = await RunAsync("--live");
        Assert.True(alive == 1, aliveOutput);
        Assert.Contains("not alive:", aliveOutput);
    }

    [Fact]
    public async Task With_PROXY_required_on_https_from_another_proxy_the_probe_asks_plain_http_and_never_the_https_listener()
    {
        await using var node = await TestNode.StartAsync(httpsProxy: true, trusted: [IPNetwork.Parse("10.99.0.0/16")]);
        WriteConfig(node, httpsProxy: true, trusted: "10.99.0.0/16");

        var (code, output) = await RunAsync();

        Assert.True(code == 0, output);
        Assert.Contains($"http://127.0.0.1:{node.HttpPort}/health/live answered 200", output);
        Assert.Equal(0, node.RequestsOn(node.HttpsPort));
        Assert.Equal(1, node.RequestsOn(node.HttpPort));
    }

    [Fact]
    public async Task With_PROXY_required_on_https_and_loopback_trusted_the_probe_sends_a_local_header_and_keeps_its_own_address()
    {
        await using var node = await TestNode.StartAsync(httpsProxy: true, httpProxy: true, trusted: [IPNetwork.Parse("127.0.0.0/8")]);
        WriteConfig(node, httpsProxy: true, httpProxy: true, trusted: "127.0.0.0/8");

        var (code, output) = await RunAsync();

        Assert.True(code == 0, output);
        Assert.Contains($"https://127.0.0.1:{node.HttpsPort}/health/live answered 200", output);
        Assert.Contains("PROXY v2 LOCAL", output);
        var seen = Assert.Single(node.Seen);
        Assert.Equal(node.HttpsPort, seen.LocalPort);
        Assert.True(seen.Proxied, "the request came through the PROXY listener");
        Assert.Equal("127.0.0.1", seen.RemoteIp);
    }

    [Fact]
    public async Task With_PROXY_required_on_every_listener_from_another_proxy_the_probe_does_not_connect()
    {
        await using var node = await TestNode.StartAsync(httpsProxy: true, httpProxy: true, trusted: [IPNetwork.Parse("10.99.0.0/16")]);
        WriteConfig(node, httpsProxy: true, httpProxy: true, trusted: "10.99.0.0/16");

        var (code, output) = await RunAsync();

        Assert.True(code == 1, output);
        Assert.Contains("Http.ProxyProtocolTrustedCidrs", output);
        Assert.Empty(node.Seen);
    }

    [Fact]
    public async Task The_health_port_answers_the_health_paths_and_404_for_everything_else_before_the_app_sees_it()
    {
        await using var node = await TestNode.StartAsync(withHealthPort: true);
        using var client = new HttpClient();
        var health = $"http://127.0.0.1:{node.HealthPort}";

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"{health}/health")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"{health}/health/live")).StatusCode);
        // Reaches the application, which still asks for its token: the port opens nothing.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync($"{health}/health/ready")).StatusCode);
        Assert.Equal(3, node.RequestsOn(node.HealthPort));

        foreach (var path in new[] { "/", "/public/", "/api/v1/admin/users", "/acme/default/directory", "/metrics", "/health/other", "/healthz" })
            Assert.True((await client.GetAsync(health + path)).StatusCode == HttpStatusCode.NotFound, path);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync($"{health}/health/live", new StringContent("x"))).StatusCode);
        Assert.Equal(3, node.RequestsOn(node.HealthPort));

        // The gate is the health port's alone: the main plain-HTTP listener serves other paths as before.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"http://127.0.0.1:{node.HttpPort}/other")).StatusCode);
    }

    [Fact]
    public async Task With_PROXY_on_both_main_listeners_from_another_proxy_the_probe_succeeds_through_the_health_port()
    {
        await using var node = await TestNode.StartAsync(httpsProxy: true, httpProxy: true, trusted: [IPNetwork.Parse("10.99.0.0/16")], withHealthPort: true);
        WriteConfig(node, httpsProxy: true, httpProxy: true, trusted: "10.99.0.0/16", healthPort: node.HealthPort);

        var (ready, readyOutput) = await RunAsync();
        Assert.True(ready == 0, readyOutput);
        Assert.Contains($"ready: http://127.0.0.1:{node.HealthPort}/health/live answered 200", readyOutput);

        var (alive, aliveOutput) = await RunAsync("--live");
        Assert.True(alive == 0, aliveOutput);

        var seen = node.Seen;
        Assert.Equal(2, seen.Count);
        Assert.All(seen, s =>
        {
            Assert.Equal(node.HealthPort, s.LocalPort);
            Assert.False(s.Proxied);
            Assert.Equal("127.0.0.1", s.RemoteIp);
        });
    }

    [Fact]
    public async Task The_health_port_from_the_environment_is_the_one_the_probe_asks()
    {
        await using var node = await TestNode.StartAsync(httpsProxy: true, httpProxy: true, trusted: [IPNetwork.Parse("10.99.0.0/16")], withHealthPort: true);
        WriteConfig(node, httpsProxy: true, httpProxy: true, trusted: "10.99.0.0/16");
        const string variable = "MODULARCA__HEALTH__LOOPBACKPORT";
        var original = Environment.GetEnvironmentVariable(variable);
        Environment.SetEnvironmentVariable(variable, node.HealthPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        try
        {
            var (code, output) = await RunAsync();

            Assert.True(code == 0, output);
            Assert.Contains($"http://127.0.0.1:{node.HealthPort}/health/live", output);
            Assert.DoesNotContain("[INF]", output);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, original);
        }
    }

    [Fact]
    public async Task An_unconfigured_node_is_not_ready()
    {
        var (code, output) = await RunAsync();

        Assert.True(code == 1, output);
        Assert.Contains("config.yaml does not exist", output);
    }

    [Fact]
    public async Task The_binary_answers_zero_for_a_healthy_node_and_one_once_it_stops_and_writes_nothing()
    {
        var node = await TestNode.StartAsync();
        try
        {
            WriteConfig(node);
            var before = Directory.GetFileSystemEntries(_configDir, "*", SearchOption.AllDirectories).Order().ToList();

            var (ready, readyOutput) = RunApi("--role", "node", "--check-ready", "--config-dir", _configDir);
            Assert.True(ready == 0, readyOutput);
            Assert.Contains("ready:", readyOutput);
            var (alive, aliveOutput) = RunApi("--role", "node", "--check-ready", "--live", "--config-dir", _configDir);
            Assert.True(alive == 0, aliveOutput);

            Assert.Equal(before, Directory.GetFileSystemEntries(_configDir, "*", SearchOption.AllDirectories).Order().ToList());
        }
        finally
        {
            await node.DisposeAsync();
        }

        var (down, downOutput) = RunApi("--role", "node", "--check-ready", "--config-dir", _configDir);
        Assert.True(down == 1, downOutput);
        Assert.Contains("not ready", downOutput);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// <summary>Calls <c>ResolveTarget</c> with the named role set.</summary>
    private static object? Resolve(SystemConfig config, string roles, out string? reason)
    {
        var role = Enum.Parse(ApiAssembly.TypeNamed("ModularCA.API.Startup.ProcessRole"), roles);
        object?[] args = [config, role, null];
        var target = Check.GetMethod("ResolveTarget", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, args);
        reason = (string?)args[2];
        if (target == null)
            Assert.False(string.IsNullOrWhiteSpace(reason), "a refused target says why");
        return target;
    }

    /// <summary>The target's scheme, address, port and whether it sends a PROXY header.</summary>
    private static (string, string, int, bool) Describe(object target)
    {
        var type = target.GetType();
        return ((string)type.GetProperty("Scheme")!.GetValue(target)!,
            type.GetProperty("Address")!.GetValue(target)!.ToString()!,
            (int)type.GetProperty("Port")!.GetValue(target)!,
            (bool)type.GetProperty("SendsProxyHeader")!.GetValue(target)!);
    }

    private static SystemConfig ProxyConfig(bool https, bool http, string trusted)
    {
        var config = new SystemConfig();
        config.Https.ProxyProtocol = https;
        config.Http.ProxyProtocol = http;
        config.Http.ProxyProtocolTrustedCidrs = trusted;
        return config;
    }

    private void WriteConfig(TestNode node, bool httpsProxy = false, bool httpProxy = false, string trusted = "", int healthPort = 0)
        => WriteConfig(node.HttpsPort, node.HttpPort, httpsProxy, httpProxy, trusted, healthPort);

    /// <summary>Writes the node's <c>config.yaml</c>: a wildcard bind, as the pod has, the two ports, and the health port when given.</summary>
    private void WriteConfig(int httpsPort, int httpPort, bool httpsProxy = false, bool httpProxy = false, string trusted = "", int healthPort = 0)
    {
        File.WriteAllText(Path.Combine(_configDir, "config.yaml"),
            (healthPort > 0 ? $"Health:\n  LoopbackPort: {healthPort}\n" : string.Empty)
            + "Https:\n"
            + "  ListenAddress: \"0.0.0.0\"\n"
            + $"  Port: {httpsPort}\n"
            + $"  ProxyProtocol: {(httpsProxy ? "true" : "false")}\n"
            + "Http:\n"
            + $"  Port: {httpPort}\n"
            + $"  ProxyProtocol: {(httpProxy ? "true" : "false")}\n"
            + $"  ProxyProtocolTrustedCidrs: \"{trusted}\"\n");
    }

    /// <summary>Runs <c>NodeReadinessCheck.RunAsync</c> from the built API with <c>--role node</c> and this test's directory.</summary>
    private async Task<(int Code, string Output)> RunAsync(params string[] extra)
    {
        string[] args = ["--role", "node", "--check-ready", .. extra, "--config-dir", _configDir];
        using var output = new StringWriter();
        using var error = new StringWriter();
        Task<int> task;
        try
        {
            task = (Task<int>)Check.GetMethod("RunAsync", BindingFlags.Public | BindingFlags.Static)!
                .Invoke(null, [args, AppContext.BaseDirectory, output, error, TimeSpan.FromSeconds(10)])!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
        var code = await task;
        return (code, output.ToString() + error);
    }

    /// <summary>Runs the built API with <paramref name="args"/> and returns its exit code and combined output.</summary>
    private (int Code, string Output) RunApi(params string[] args)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = _configDir,
        };
        start.ArgumentList.Add(ApiAssembly.Instance.Location);
        foreach (var arg in args)
            start.ArgumentList.Add(arg);
        foreach (var name in start.Environment.Keys.Where(k => k.StartsWith("MODULARCA", StringComparison.OrdinalIgnoreCase)).ToList())
            start.Environment.Remove(name);
        start.Environment["DOTNET_ENVIRONMENT"] = "Production";

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail("ModularCA.API did not exit within 120 s: " + string.Join(' ', args));
        }
        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    /// <summary>One request the test node answered: the listener port, the peer and whether it came through a PROXY header.</summary>
    private sealed record SeenRequest(int LocalPort, string? RemoteIp, bool Proxied, string Path);

    /// <summary>
    /// A stand-in for the node on real Kestrel listeners on loopback, where the probe reaches the pod's
    /// wildcard bind: HTTPS under a self-signed certificate for another name and plain HTTP, either
    /// taking the PROXY protocol through the API's own <c>ProxyProtocolHosting</c>, and, when
    /// asked, the loopback-only health port opened and gated by the API's own
    /// <c>HealthListener</c>; with <c>/health</c> always 200, <c>/health/live</c> answering
    /// <see cref="LiveStatus"/>, <c>/health/ready</c> 401 as without a token, and every other
    /// path 200.
    /// </summary>
    private sealed class TestNode : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly X509Certificate2 _certificate;
        private readonly List<SeenRequest> _seen = [];

        private TestNode(WebApplication app, X509Certificate2 certificate, int httpsPort, int httpPort, int healthPort)
        {
            _app = app;
            _certificate = certificate;
            HttpsPort = httpsPort;
            HttpPort = httpPort;
            HealthPort = healthPort;
        }

        public int HttpsPort { get; }
        public int HttpPort { get; }

        /// <summary>The loopback-only health port, 0 when the node has none.</summary>
        public int HealthPort { get; }

        /// <summary>What <c>/health/live</c> answers.</summary>
        public int LiveStatus { get; set; } = StatusCodes.Status200OK;

        public IReadOnlyList<SeenRequest> Seen
        {
            get { lock (_seen) return _seen.ToList(); }
        }

        public int RequestsOn(int port) => Seen.Count(s => s.LocalPort == port);

        public static async Task<TestNode> StartAsync(bool httpsProxy = false, bool httpProxy = false, IPNetwork[]? trusted = null, bool withHealthPort = false)
        {
            var certificate = SelfSigned("node.example");
            var httpsPort = IngressHost.FreePort();
            var httpPort = IngressHost.FreePort();
            var healthPort = withHealthPort ? IngressHost.FreePort() : 0;
            var listener = ApiAssembly.TypeNamed("ModularCA.API.Startup.HealthListener");
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(k =>
            {
                k.Listen(IPAddress.Loopback, httpsPort, listen =>
                {
                    if (httpsProxy)
                        UseProxyProtocol(listen, trusted!, "test HTTPS");
                    listen.UseHttps(new TlsHandshakeCallbackOptions
                    {
                        OnConnection = _ => ValueTask.FromResult(new SslServerAuthenticationOptions { ServerCertificate = certificate }),
                    });
                });
                k.Listen(IPAddress.Loopback, httpPort, listen =>
                {
                    if (httpProxy)
                        UseProxyProtocol(listen, trusted!, "test HTTP");
                });
                // As startup opens it: HealthListener.Listen, whatever the main listeners take.
                if (healthPort > 0)
                    Invoke(listener, "Listen", k, healthPort);
            });
            var app = builder.Build();
            var node = new TestNode(app, certificate, httpsPort, httpPort, healthPort);
            // As startup gates it: first of all.
            if (healthPort > 0)
                Invoke(listener, "UseHealthPortGate", app, healthPort);
            app.Run(async context =>
            {
                var remote = context.Connection.RemoteIpAddress;
                lock (node._seen)
                {
                    node._seen.Add(new SeenRequest(context.Connection.LocalPort,
                        remote is { IsIPv4MappedToIPv6: true } ? remote.MapToIPv4().ToString() : remote?.ToString(),
                        context.Features.Get<ProxyProtocolFeature>() != null,
                        context.Request.Path));
                }
                var path = context.Request.Path.Value;
                if (path == "/health")
                {
                    await context.Response.WriteAsJsonAsync(new { status = "healthy", roles = new[] { "enrollment", "validation", "control" } });
                }
                else if (path == "/health/live")
                {
                    context.Response.StatusCode = node.LiveStatus;
                    await context.Response.WriteAsJsonAsync(new { status = node.LiveStatus == 200 ? "healthy" : "unhealthy" });
                }
                else if (path == "/health/ready")
                {
                    // As the real endpoint answers without its SystemAuditor token.
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                }
                else
                {
                    // Every other path is served: a 404 can only come from the health port's gate.
                    await context.Response.WriteAsync("app");
                }
            });
            await app.StartAsync();
            return node;
        }

        public async ValueTask DisposeAsync()
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
            _certificate.Dispose();
        }

        private static void UseProxyProtocol(ListenOptions listen, IPNetwork[] trusted, string name)
            => Invoke(ApiAssembly.TypeNamed("ModularCA.API.ProxyProtocol.ProxyProtocolHosting"), "UseProxyProtocol", listen, trusted, name, TimeSpan.FromSeconds(2));

        /// <summary>Calls a public static method of the API, unwrapping what it throws.</summary>
        private static void Invoke(Type type, string method, params object?[] args)
        {
            try
            {
                type.GetMethod(method, BindingFlags.Public | BindingFlags.Static)!.Invoke(null, args);
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }
        }

        /// <summary>A self-signed server certificate for another name, through PKCS#12 so SChannel accepts its key.</summary>
        private static X509Certificate2 SelfSigned(string name)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(name);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
            using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
            return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
        }
    }
}
