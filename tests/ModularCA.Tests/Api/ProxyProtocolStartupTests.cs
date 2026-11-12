using System.Text.RegularExpressions;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The PROXY protocol settings: off by default, kept on this host and applied at restart; a
/// listener taking the protocol with no trusted proxy, an entry that does not parse, or one
/// that trusts every address stops the start; and startup wires the middleware ahead of TLS on
/// each listener that takes it and keeps the forwarded-headers step off those connections.
/// </summary>
public class ProxyProtocolStartupTests
{
    [Fact]
    public void A_standalone_install_takes_no_PROXY_header_anywhere()
    {
        var config = new SystemConfig();

        Assert.False(config.Https.ProxyProtocol);
        Assert.False(config.Http.ProxyProtocol);
        Assert.Equal(string.Empty, config.Http.ProxyProtocolTrustedCidrs);
        Assert.Null(ConfigInputRules.ProxyProtocolError(config.Https.ProxyProtocol, config.Http.ProxyProtocol, config.Http.ProxyProtocolTrustedCidrs));
    }

    [Theory]
    [InlineData("Https_ProxyProtocol")]
    [InlineData("Http_ProxyProtocol")]
    [InlineData("Http_ProxyProtocolTrustedCidrs")]
    public void The_settings_describe_this_host_and_apply_at_restart(string key)
    {
        var definition = SettingsCatalog.Find(key);

        Assert.NotNull(definition);
        Assert.Equal(SettingClass.HostLocal, definition!.Class);
        Assert.Equal(SettingReload.Restart, definition.Reload);
        Assert.False(definition.StoredInDatabase);
    }

    [Theory]
    [InlineData(true, false, null, "Https.ProxyProtocol is on")]
    [InlineData(false, true, "", "Http.ProxyProtocol is on")]
    [InlineData(true, true, "  ", "Https.ProxyProtocol and Http.ProxyProtocol are on")]
    public void A_listener_taking_PROXY_with_no_trusted_proxy_stops_the_start(bool https, bool http, string? cidrs, string names)
    {
        var error = ConfigInputRules.ProxyProtocolError(https, http, cidrs);

        Assert.NotNull(error);
        Assert.Contains(names, error);
        Assert.Contains("Http.ProxyProtocolTrustedCidrs names no proxy", error);
        // The X-Forwarded-For list is not a substitute, and the message says so.
        Assert.Contains("Do not use Http.TrustedProxyCidrs", error);
    }

    [Theory]
    [InlineData("10.100.105.22", "10.100.105.22")]
    [InlineData("10.100.105.22/32, proxy.example/32", "proxy.example/32")]
    [InlineData("10.100.105.0/16", "10.100.105.0/16")]
    public void An_entry_that_does_not_parse_stops_the_start_even_with_the_protocol_off(string cidrs, string named)
    {
        var error = ConfigInputRules.ProxyProtocolError(false, false, cidrs);

        Assert.NotNull(error);
        Assert.Contains(named, error);
        Assert.Contains("Http.ProxyProtocolTrustedCidrs", error);
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("10.100.105.22/32,::/0")]
    public void A_list_that_trusts_every_address_stops_the_start(string cidrs)
    {
        var error = ConfigInputRules.ProxyProtocolError(true, false, cidrs);

        Assert.NotNull(error);
        Assert.Contains("trusts every address", error);
    }

    [Theory]
    [InlineData(true, false, "10.100.105.22/32")]
    [InlineData(false, true, "10.100.105.0/24,2001:db8::/64")]
    [InlineData(true, true, "127.0.0.1/32")]
    [InlineData(false, false, "10.100.105.22/32")]
    public void A_listener_with_its_proxy_named_starts(bool https, bool http, string cidrs)
    {
        Assert.Null(ConfigInputRules.ProxyProtocolError(https, http, cidrs));
    }

    [Fact]
    public void The_two_trusted_lists_are_independent()
    {
        // Naming the passthrough proxy for PROXY does not make it an X-Forwarded-For hop, and the
        // reverse: turning on one never satisfies the other's check.
        Assert.NotNull(ConfigInputRules.ReverseProxyError(behindReverseProxy: true, trustedProxyCidrs: ""));
        Assert.NotNull(ConfigInputRules.ProxyProtocolError(true, true, trustedCidrs: ""));
        var config = new HttpConfig { ProxyProtocolTrustedCidrs = "10.100.105.22/32" };
        Assert.Equal(string.Empty, config.TrustedProxyCidrs);
    }

    [Fact]
    public void Startup_refuses_a_bad_PROXY_configuration_before_any_listener_is_bound()
    {
        var startup = Startup();
        var check = startup.IndexOf("ConfigInputRules.ProxyProtocolError(config.Https.ProxyProtocol, config.Http.ProxyProtocol, config.Http.ProxyProtocolTrustedCidrs)", StringComparison.Ordinal);
        Assert.True(check > 0, "startup does not check the PROXY protocol settings");
        var exit = startup.IndexOf("Environment.Exit(1);", check, StringComparison.Ordinal);
        Assert.True(exit > check && exit - check < 600, "the PROXY protocol check does not stop the start");
        Assert.True(check < startup.IndexOf("builder.WebHost.ConfigureKestrel(", StringComparison.Ordinal), "the PROXY protocol check comes after a listener is configured");
    }

    [Fact]
    public void Startup_reads_the_header_before_TLS_on_every_listener_that_takes_it()
    {
        var startup = Startup();

        // The HTTPS listener and the setup wizard's: the PROXY middleware, then UseHttps.
        foreach (var name in new[] { "$\"HTTPS {listenOptions.EndPoint}\"", "$\"setup HTTPS :{port}\"" })
        {
            var proxy = startup.IndexOf(name, StringComparison.Ordinal);
            Assert.True(proxy > 0, $"no PROXY middleware on the {name} listener");
            var https = startup.IndexOf("listenOptions.UseHttps(", proxy, StringComparison.Ordinal);
            Assert.True(https > proxy && https - proxy < 400, $"UseHttps does not follow the PROXY middleware on the {name} listener");
        }

        Assert.Contains("$\"HTTP {listenOptions.EndPoint}\"", startup);
        Assert.Matches(new Regex(@"options\.ListenAnyIP\(httpPort, configureHttp\)"), startup);
    }

    [Fact]
    public void Startup_keeps_forwarded_headers_off_PROXY_connections()
    {
        var startup = Startup();

        Assert.Contains("ProxyProtocolHosting.UseForwardedHeadersUnlessProxyProtocol(app, forwardedOptions);", startup);
        Assert.DoesNotMatch(new Regex(@"app\.UseForwardedHeaders\("), startup);
    }

    private static string Startup()
        => File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.API", "StartModularCA.cs")).Replace("\r\n", "\n");

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
