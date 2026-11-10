using YamlDotNet.RepresentationModel;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// The pod manifest's security division, read from the file: the signer reads its settings from
/// its own volume, which the node never mounts; the node never mounts the keystores; the init
/// containers fill the signer's directory, create its identity and apply the node's, in that
/// order and each with <c>--signer-dir</c>, the last with both volumes read-write so it can clean
/// the signer's files out of the node's; the signer's probes are <c>--check-ready</c> on the
/// same directory; and the image has the directory the volume is mounted on, owner-only.
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
