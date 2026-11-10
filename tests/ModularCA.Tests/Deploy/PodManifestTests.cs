using YamlDotNet.RepresentationModel;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// The pod manifest's security division, read from the file: the signer reads its settings from
/// its own volume, which the node never mounts; the node never mounts the keystores; the init
/// containers fill the signer's directory, create its identity and apply the node's, in that
/// order and each with <c>--signer-dir</c>, the last with both volumes read-write so it can clean
/// the signer's files out of the node's; the signer's probes are <c>--check-ready</c> on the
/// same directory, the node's <c>--role node --check-ready --live</c>, which ask the node's
/// loopback-only health port, set in its environment and published by nothing; and the image
/// has the directory the volume is mounted on, owner-only.
/// </summary>
public sealed class PodManifestTests
{
    private const string SignerDir = "/opt/modularca/signer";

    [Fact]
    public void The_signer_reads_its_own_volume_and_the_node_cannot_mount_it_or_the_keystores()
    {
        var pod = Pod();
        var signer = Container(pod, "containers", "signer");
        var node = Container(pod, "containers", "node");

        Assert.Equal(["--role", "signer", "--signer-dir", SignerDir], Strings(signer, "args"));
        var signerMounts = Mounts(signer);
        Assert.Equal(SignerDir, signerMounts["signer-config"]);
        Assert.DoesNotContain("config", signerMounts.Keys);
        Assert.Contains("keystores", signerMounts.Keys);

        var nodeMounts = Mounts(node);
        Assert.Contains("config", nodeMounts.Keys);
        Assert.DoesNotContain("signer-config", nodeMounts.Keys);
        Assert.DoesNotContain("keystores", nodeMounts.Keys);
    }

    [Fact]
    public void The_init_containers_fill_the_signers_directory_then_its_identity_then_the_nodes()
    {
        var pod = Pod();
        var init = ((YamlSequenceNode)pod["initContainers"]).Children.Cast<YamlMappingNode>().ToList();
        Assert.Equal(["bootstrap", "signer-dir", "signer-init", "node-identity"], init.Select(c => c["name"].ToString()));

        var fill = Strings(init[1], "args");
        Assert.Equal(["--role", "signer", "--signer-dir", SignerDir, "--migrate-signer-dir"], fill);
        Assert.Equal("true", ((YamlMappingNode)((YamlSequenceNode)init[1]["volumeMounts"]).Children
            .Cast<YamlMappingNode>().Single(m => m["name"].ToString() == "config"))["readOnly"].ToString());

        Assert.Equal(["--role", "signer", "--signer-dir", SignerDir, "--init-identity"], Strings(init[2], "args"));
        Assert.Equal([SignerDir], Mounts(init[2]).Values);

        Assert.Equal(["--role", "signer", "--signer-dir", SignerDir, "--issue-node-identity", "--apply", "/opt/modularca/config/config.yaml"],
            Strings(init[3], "args"));
        Assert.Equal(["config", "signer-config"], Mounts(init[3]).Keys.Order());
        // node-identity writes both halves and then removes the signer's files from config, so
        // both of its mounts are read-write.
        Assert.All(((YamlSequenceNode)init[3]["volumeMounts"]).Children.Cast<YamlMappingNode>(),
            m => Assert.False(m.Children.TryGetValue(new YamlScalarNode("readOnly"), out var ro) && ro.ToString() == "true"));
    }

    [Fact]
    public void The_signers_probes_check_the_signer_it_runs()
    {
        var signer = Container(Pod(), "containers", "signer");
        foreach (var probe in new[] { "startupProbe", "livenessProbe" })
        {
            var command = ((YamlSequenceNode)((YamlMappingNode)((YamlMappingNode)signer[probe])["exec"])["command"]).Children.Select(c => c.ToString()).ToList();
            Assert.Equal(["/opt/modularca/ModularCA.API", "--role", "signer", "--signer-dir", SignerDir, "--check-ready"], command);
        }
    }

    [Fact]
    public void The_node_has_a_loopback_health_port_of_its_own_that_nothing_publishes()
    {
        var pod = Pod();
        var node = Container(pod, "containers", "node");

        // Set in the container's environment, which its probes run with too.
        var env = ((YamlSequenceNode)node["env"]).Children.Cast<YamlMappingNode>()
            .ToDictionary(e => e["name"].ToString(), e => e["value"].ToString());
        Assert.True(env.TryGetValue("MODULARCA__HEALTH__LOOPBACKPORT", out var value), "the node has no health port");
        var port = int.Parse(value!, System.Globalization.CultureInfo.InvariantCulture);

        // A port of its own: not the node's listeners, not the signer's.
        var published = ((YamlSequenceNode)node["ports"]).Children.Cast<YamlMappingNode>()
            .Select(p => int.Parse(p["containerPort"].ToString(), System.Globalization.CultureInfo.InvariantCulture)).ToList();
        Assert.DoesNotContain(port, published);
        Assert.NotEqual(8446, port);
        Assert.InRange(port, 1, 65535);

        // Nothing in the pod publishes it.
        foreach (var container in ((YamlSequenceNode)pod["containers"]).Children.Cast<YamlMappingNode>())
        {
            if (!container.Children.TryGetValue(new YamlScalarNode("ports"), out var ports))
                continue;
            Assert.DoesNotContain(((YamlSequenceNode)ports).Children.Cast<YamlMappingNode>(),
                p => p["containerPort"].ToString() == value || (p.Children.TryGetValue(new YamlScalarNode("hostPort"), out var host) && host.ToString() == value));
        }
    }

    [Fact]
    public void The_nodes_probes_ask_whether_it_is_alive_so_a_node_waiting_for_its_signer_is_not_restarted()
    {
        var node = Container(Pod(), "containers", "node");
        foreach (var probe in new[] { "startupProbe", "livenessProbe" })
        {
            var spec = (YamlMappingNode)node[probe];
            var command = ((YamlSequenceNode)((YamlMappingNode)spec["exec"])["command"]).Children.Select(c => c.ToString()).ToList();
            // The node's role and the node's check: never the signer's, and never an httpGet,
            // which Podman runs as curl, which the image does not have.
            Assert.Equal(["/opt/modularca/ModularCA.API", "--role", "node", "--check-ready", "--live"], command);
            Assert.False(spec.Children.ContainsKey(new YamlScalarNode("httpGet")));
            // Each run starts a .NET process: give it time, and do not run it every second.
            Assert.True(int.Parse(spec["timeoutSeconds"].ToString()) >= 10, $"{probe} timeoutSeconds");
            Assert.True(int.Parse(spec["periodSeconds"].ToString()) >= 5, $"{probe} periodSeconds");
        }

        // The startup window covers Schema.WaitSeconds (900 s by default), as the signer's does.
        var startup = (YamlMappingNode)node["startupProbe"];
        Assert.True(int.Parse(startup["periodSeconds"].ToString()) * int.Parse(startup["failureThreshold"].ToString()) >= 900);

        // Readiness answers 503 while the signer is locked or away; it gates no restart and no Service here.
        Assert.False(node.Children.ContainsKey(new YamlScalarNode("readinessProbe")));
    }

    [Fact]
    public void The_image_has_the_signers_directory_owner_only_and_the_entrypoint_knows_it()
    {
        var image = Read("deploy/container/Containerfile");
        Assert.Contains("install -d -o modularca -g modularca -m 0700 /opt/modularca/signer", image);

        var entrypoint = Read("deploy/container/entrypoint.sh");
        Assert.Contains("--signer-dir)", entrypoint);
        Assert.Contains("\"$signer_dir/signer.yaml\"", entrypoint);
        Assert.Contains("\"$signer_dir/db.yaml\"", entrypoint);
    }

    private static YamlMappingNode Pod()
    {
        var stream = new YamlStream();
        using var reader = new StringReader(Read("deploy/container/modularca-pod.yaml"));
        stream.Load(reader);
        return (YamlMappingNode)((YamlMappingNode)stream.Documents[0].RootNode)["spec"];
    }

    private static YamlMappingNode Container(YamlMappingNode pod, string list, string name)
        => ((YamlSequenceNode)pod[list]).Children.Cast<YamlMappingNode>().Single(c => c["name"].ToString() == name);

    private static List<string> Strings(YamlMappingNode container, string key)
        => ((YamlSequenceNode)container[key]).Children.Select(c => c.ToString()).ToList();

    /// <summary>The container's mounts, volume name to mount path.</summary>
    private static Dictionary<string, string> Mounts(YamlMappingNode container)
        => ((YamlSequenceNode)container["volumeMounts"]).Children.Cast<YamlMappingNode>()
            .ToDictionary(m => m["name"].ToString(), m => m["mountPath"].ToString());

    private static string Read(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar)));
    }
}
