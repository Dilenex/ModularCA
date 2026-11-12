using System.Globalization;
using YamlDotNet.RepresentationModel;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// The compose file's healthcheck for the node, read from the file: the node's own exec check
/// (<c>--role node --check-ready --live</c>, since the image has no <c>curl</c>), asking the
/// loopback-only health port the service sets in its environment and publishes nowhere, at the
/// intervals the pod's probes use.
/// </summary>
public sealed class ComposeFileTests
{
    [Fact]
    public void The_node_has_a_healthcheck_that_asks_whether_it_is_alive()
    {
        var check = (YamlMappingNode)Service("modularca")["healthcheck"];
        var test = ((YamlSequenceNode)check["test"]).Children.Select(c => c.ToString()).ToList();

        // Exec form, the node's role and the node's liveness check: no shell, no curl.
        Assert.Equal(["CMD", "/opt/modularca/ModularCA.API", "--role", "node", "--check-ready", "--live"], test);

        // Each run starts a .NET process: give it time, and do not run it every few seconds.
        Assert.True(Seconds(check["timeout"].ToString()) >= 10, "timeout");
        Assert.True(Seconds(check["interval"].ToString()) >= 30, "interval");
        Assert.Equal("3", check["retries"].ToString());
        // The start period covers Schema.WaitSeconds (900 s by default), as the pod's startup probe does.
        Assert.True(Seconds(check["start_period"].ToString()) >= 900, "start_period");
    }

    [Fact]
    public void The_node_has_a_loopback_health_port_of_its_own_that_nothing_publishes()
    {
        var service = Service("modularca");
        var environment = (YamlMappingNode)service["environment"];
        Assert.True(environment.Children.TryGetValue(new YamlScalarNode("MODULARCA__HEALTH__LOOPBACKPORT"), out var value), "the node has no health port");
        var port = int.Parse(value!.ToString(), CultureInfo.InvariantCulture);
        Assert.InRange(port, 1, 65535);

        // The same port the pod uses, so the deploy guide describes one health port.
        var pod = new YamlStream();
        using (var reader = new StringReader(Read("deploy/container/modularca-pod.yaml")))
            pod.Load(reader);
        var node = ((YamlSequenceNode)((YamlMappingNode)((YamlMappingNode)pod.Documents[0].RootNode)["spec"])["containers"])
            .Children.Cast<YamlMappingNode>().Single(c => c["name"].ToString() == "node");
        var podPort = ((YamlSequenceNode)node["env"]).Children.Cast<YamlMappingNode>()
            .Single(e => e["name"].ToString() == "MODULARCA__HEALTH__LOOPBACKPORT")["value"].ToString();
        Assert.Equal(podPort, value.ToString());

        // Not a main listener, and on neither side of any published mapping.
        var mappings = ((YamlSequenceNode)service["ports"]).Children.Select(p => p.ToString()).ToList();
        Assert.Equal(["8443:8443", "8080:8080"], mappings);
        Assert.DoesNotContain(mappings.SelectMany(m => m.Split(':')), side => side == value.ToString());
    }

    /// <summary>A compose duration of whole seconds or minutes (<c>30s</c>, <c>16m</c>), in seconds.</summary>
    private static int Seconds(string duration)
    {
        var number = int.Parse(duration[..^1], CultureInfo.InvariantCulture);
        return duration[^1] switch
        {
            's' => number,
            'm' => number * 60,
            _ => throw new FormatException($"'{duration}' is not a duration in seconds or minutes"),
        };
    }

    /// <summary>The named service's mapping in <c>deploy/compose/compose.yaml</c>.</summary>
    private static YamlMappingNode Service(string name)
    {
        var stream = new YamlStream();
        using var reader = new StringReader(Read("deploy/compose/compose.yaml"));
        stream.Load(reader);
        return (YamlMappingNode)((YamlMappingNode)((YamlMappingNode)stream.Documents[0].RootNode)["services"])[name];
    }

    private static string Read(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar)));
    }
}
