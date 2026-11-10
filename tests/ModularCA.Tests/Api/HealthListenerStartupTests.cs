using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>Health.LoopbackPort</c>, the loopback-only health listener: off by default, kept on this
/// host and applied at restart; a value that is not a port, or that is the HTTPS, plain-HTTP or
/// signer port, stops the start before any listener is bound; and startup opens it on
/// <c>127.0.0.1</c> with no PROXY middleware, gates it first in the pipeline, and keeps the
/// ingress branch off it.
/// </summary>
public class HealthListenerStartupTests
{
    [Fact]
    public void The_health_listener_is_off_by_default_and_a_per_host_restart_setting()
    {
        Assert.Equal(0, new SystemConfig().Health.LoopbackPort);
        Assert.Null(ConfigInputRules.HealthLoopbackPortError(new SystemConfig()));

        var definition = SettingsCatalog.Find("Health_LoopbackPort");
        Assert.NotNull(definition);
        Assert.Equal(SettingClass.HostLocal, definition!.Class);
        Assert.Equal(SettingReload.Restart, definition.Reload);
        Assert.False(definition.StoredInDatabase);
    }

    [Fact]
    public void A_port_of_its_own_starts()
    {
        var config = new SystemConfig();
        config.Health.LoopbackPort = 8081;

        Assert.Null(ConfigInputRules.HealthLoopbackPortError(config));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(int.MaxValue)]
    public void A_value_that_is_not_a_port_stops_the_start(int port)
    {
        var config = new SystemConfig();
        config.Health.LoopbackPort = port;

        var error = ConfigInputRules.HealthLoopbackPortError(config);

        Assert.NotNull(error);
        Assert.Contains("is not a port", error);
        Assert.Contains(EnvVarConfigOverlay.HealthLoopbackPortVariable, error);
    }

    [Fact]
    public void The_https_or_plain_http_port_stops_the_start()
    {
        var config = new SystemConfig();
        config.Health.LoopbackPort = config.Https.Port;
        Assert.Contains("Https.Port", ConfigInputRules.HealthLoopbackPortError(config));

        config.Health.LoopbackPort = config.Http.Port;
        Assert.Contains("Http.Port", ConfigInputRules.HealthLoopbackPortError(config));

        // With the plain-HTTP listener off, its port is free.
        config.Http.Port = 0;
        config.Health.LoopbackPort = 8080;
        Assert.Null(ConfigInputRules.HealthLoopbackPortError(config));
    }

    [Fact]
    public void The_signers_port_stops_the_start_where_the_signer_shares_loopback()
    {
        var config = new SystemConfig();
        config.Health.LoopbackPort = 8446;
        Assert.Contains("Signer.Listen", ConfigInputRules.HealthLoopbackPortError(config));

        config.Signer.Listen = "127.0.0.1:9446";
        config.Signer.Mode = SignerConfig.RemoteMode;
        config.Signer.Endpoint = "https://127.0.0.1:8446";
        Assert.Contains("Signer.Endpoint", ConfigInputRules.HealthLoopbackPortError(config));
        config.Signer.Endpoint = "https://localhost:8446";
        Assert.Contains("Signer.Endpoint", ConfigInputRules.HealthLoopbackPortError(config));

        // A signer on another host uses its own loopback, not this one's.
        config.Signer.Endpoint = "https://signer.example:8446";
        Assert.Null(ConfigInputRules.HealthLoopbackPortError(config));
    }

    [Fact]
    public void Startup_refuses_a_bad_health_port_before_any_listener_is_bound()
    {
        var startup = Startup();
        var check = startup.IndexOf("ConfigInputRules.HealthLoopbackPortError(config)", StringComparison.Ordinal);
        Assert.True(check > 0, "startup does not check Health.LoopbackPort");
        var exit = startup.IndexOf("Environment.Exit(1);", check, StringComparison.Ordinal);
        Assert.True(exit > check && exit - check < 600, "the health port check does not stop the start");
        Assert.True(check < startup.IndexOf("builder.WebHost.ConfigureKestrel(", StringComparison.Ordinal), "the health port check comes after a listener is configured");
        // After the environment overlay, so MODULARCA__HEALTH__LOOPBACKPORT is checked too.
        Assert.True(startup.IndexOf("envOverlay.Apply(config);", StringComparison.Ordinal) < check);
    }

    [Fact]
    public void Startup_opens_the_health_port_on_loopback_without_PROXY_and_gates_it_first()
    {
        var startup = Startup();

        // Opened through HealthListener.Listen, which takes no PROXY middleware.
        var listen = startup.IndexOf("HealthListener.Listen(options,", StringComparison.Ordinal);
        Assert.True(listen > 0, "startup does not open the health listener");
        Assert.DoesNotContain("UseProxyProtocol", startup.Substring(listen, 300));

        // The gate before the exception handler, the first step of the pipeline.
        var gate = startup.IndexOf("HealthListener.UseHealthPortGate(app, healthLoopbackPort);", StringComparison.Ordinal);
        Assert.True(gate > 0, "startup does not gate the health port");
        Assert.True(gate < startup.IndexOf("app.UseExceptionHandler(", StringComparison.Ordinal), "the health port gate is not the first step");

        // The ingress branch never takes a request from the health port.
        Assert.Contains("!ModularCA.API.Startup.HealthListener.ArrivedOnHealthPort(context, healthLoopbackPort)", startup);
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
