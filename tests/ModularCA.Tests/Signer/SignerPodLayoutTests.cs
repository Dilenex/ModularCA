using System.Net;
using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Signer.Client;
using ModularCA.Signer.Identity;
using ModularCA.Signer.Server;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The pod's init containers with the signer's configuration apart from the node's, run in the
/// order the pod runs them: the copy into the signer's directory (<c>--migrate-signer-dir</c>),
/// the signer's identity (<c>--init-identity</c>) and the node's (<c>--issue-node-identity
/// --apply</c>), each with <c>--signer-dir</c>. The node's half of the channel lands in the
/// node's <c>config.yaml</c>, the signer's in <c>signer.yaml</c>, nothing of the signer's under
/// the node's directory; a real signer listener over those files admits the node over those
/// files; every step finds its work done on a second start; and a pod made before the split is
/// carried over without a new identity. Once the pins are in place the node's config directory
/// loses what the signer's holds a verified copy of (<c>keystore.yaml</c>, the identity files, the
/// signer's half of <c>Signer:</c> and <c>Hsm:</c>), a copy that does not check out is left with a
/// warning, and a second start finds nothing to remove and says nothing.
/// </summary>
[Collection(RemoteSignerCollection.Name)]
public sealed class SignerPodLayoutTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-signerpod-" + Guid.NewGuid().ToString("N"));
    private readonly string _base;
    private readonly string _config;
    private readonly string _dir;

    /// <summary>Creates the application directory with its config/ and the signer's directory.</summary>
    public SignerPodLayoutTests()
    {
        _base = Path.Combine(_root, "app");
        _config = Path.Combine(_base, "config");
        _dir = Path.Combine(_root, "signer");
        Directory.CreateDirectory(_config);
        Directory.CreateDirectory(_dir);
    }

    /// <summary>Removes the temporary root.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string NodeConfig => Path.Combine(_config, "config.yaml");
    private SignerPaths Paths => SignerPaths.Dedicated(_base, _dir);

    /// <summary>What a headless bootstrap leaves in the config volume; <paramref name="configure"/> changes the config.yaml it writes.</summary>
    private void Bootstrap(Action<SystemConfig>? configure = null)
    {
        var config = new SystemConfig();
        config.JWT.Secret = "a-jwt-secret-only-the-node-reads";
        config.Hsm.ModulePath = "/usr/lib/softhsm/libsofthsm2.so";
        config.Https.Port = 8443;
        configure?.Invoke(config);
        ConfigYamlWriter.Write(NodeConfig, config);
        YamlDbConfigLoader.Write(Path.Combine(_config, "db.yaml"), new YamlDbConfigLoader.DbYamlConfig
        {
            App = new() { Host = "db.example", Database = "modularca", Username = "mca_app", Password = "app-pass" },
            Audit = new() { Host = "db.example", Database = "modularca_audit", Username = "mca_audit", Password = "audit-pass" },
        });
        File.WriteAllText(Path.Combine(_config, "keystore.yaml"), "ca-certs.keystore: \"secondary\"\n");
    }

    /// <summary>The three init containers after bootstrap, as the pod runs them; returns their exit codes.</summary>
    private (int Migrate, int Init, int Node) InitContainers()
    {
        var migrate = RunMigration(SignerPaths.Shared(_base), Paths);
        // Each later step is a process of its own, which reads signer.yaml as it then is.
        var init = SignerIdentityInitTests.RunIdentity(["--role", "signer", SignerPaths.Flag, _dir, "--init-identity"], SignerSettings(), Paths);
        var node = SignerIdentityInitTests.RunIdentity(["--role", "signer", SignerPaths.Flag, _dir, "--issue-node-identity", "--apply", NodeConfig], SignerSettings(), Paths);
        return (migrate, init, node);
    }

    private SignerConfig SignerSettings() => YamlConfigLoader.Load(Paths.ConfigPath, _ => { }).Signer;
    private SignerConfig NodeSettings() => YamlConfigLoader.Load(NodeConfig, _ => { }).Signer;

    [Fact]
    public async Task A_first_start_puts_each_half_where_its_process_reads_it_and_the_channel_works()
    {
        Bootstrap();

        Assert.Equal((0, 0, 0), InitContainers());

        var signer = SignerSettings();
        var node = NodeSettings();
        using var server = Pkcs12Files.Load(Path.Combine(_dir, "signer-server.pfx"), signer.ServerCertificatePassword);
        using var client = Pkcs12Files.Load(Path.Combine(_config, "signer-client.pfx"), node.ClientCertificatePassword);

        // The node's half, in the node's file, and the rest of that file as it was.
        Assert.True(node.IsRemote);
        Assert.Equal("https://127.0.0.1:8446", node.Endpoint);
        Assert.Equal("config/signer-client.pfx", node.ClientCertificate);
        Assert.Equal(SpkiPin.Compute(server), node.PinnedServerSpki);
        Assert.Equal(string.Empty, node.PinnedClientSpki);
        var nodeConfig = YamlConfigLoader.Load(NodeConfig, _ => { });
        Assert.Equal("a-jwt-secret-only-the-node-reads", nodeConfig.JWT.Secret);
        Assert.Equal(8443, nodeConfig.Https.Port);

        // The signer's half, in signer.yaml, with what the copy put there.
        Assert.Equal(SpkiPin.Compute(client), signer.PinnedClientSpki);
        Assert.Equal("127.0.0.1:8446", signer.Listen);
        Assert.Equal("signer-server.pfx", signer.ServerCertificate);
        var signerConfig = YamlConfigLoader.Load(Paths.ConfigPath, _ => { });
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", signerConfig.Hsm.ModulePath);
        Assert.DoesNotContain("a-jwt-secret-only-the-node-reads", File.ReadAllText(Paths.ConfigPath));
        Assert.DoesNotContain("Endpoint", File.ReadAllText(Paths.ConfigPath));

        // Nothing of the signer's identity in the node's directory, nothing of the node's in the signer's.
        Assert.False(File.Exists(Path.Combine(_config, "signer-identity-ca.pfx")));
        Assert.False(File.Exists(Path.Combine(_config, "signer-server.pfx")));
        Assert.True(File.Exists(Path.Combine(_dir, "signer-identity-ca.pfx")));
        Assert.False(File.Exists(Path.Combine(_dir, "signer-client.pfx")));

        // And the two halves make a channel: a signer listening on signer.yaml's settings admits
        // a node dialling on config.yaml's.
        await using var listening = await ListenAsync(server, signer.PinnedClientSpki);
        using var remote = new RemoteSigningService(
            new RemoteSignerOptions(new Uri($"https://127.0.0.1:{listening.Port}"), client, node.PinnedServerSpki) { ConnectTimeout = TimeSpan.FromSeconds(5) },
            NullLogger<RemoteSigningService>.Instance);
        var health = await remote.HealthAsync();
        Assert.NotEqual(SignerHealth.UnreachableBackend, health.Backend);
    }

    [Fact]
    public void A_second_start_finds_every_step_done_and_changes_nothing()
    {
        Bootstrap();
        Assert.Equal((0, 0, 0), InitContainers());
        var before = Snapshot();

        Assert.Equal((0, 0, 0), InitContainers());
        Assert.Equal((0, 0, 0), InitContainers());

        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void A_replaced_identity_ca_is_noticed_and_the_node_is_issued_and_pinned_again()
    {
        Bootstrap();
        Assert.Equal((0, 0, 0), InitContainers());
        var oldClient = File.ReadAllBytes(Path.Combine(_config, "signer-client.pfx"));

        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--init-identity", "--force"], SignerSettings(), Paths));
        Assert.Equal((0, 0, 0), InitContainers());

        Assert.NotEqual(oldClient, File.ReadAllBytes(Path.Combine(_config, "signer-client.pfx")));
        using var server = Pkcs12Files.Load(Path.Combine(_dir, "signer-server.pfx"), string.Empty);
        using var client = Pkcs12Files.Load(Path.Combine(_config, "signer-client.pfx"), string.Empty);
        Assert.Equal(SpkiPin.Compute(server), NodeSettings().PinnedServerSpki);
        Assert.Equal(SpkiPin.Compute(client), SignerSettings().PinnedClientSpki);
    }

    [Fact]
    public void A_first_start_removes_the_nodes_keystore_yaml_and_hsm_section_once_the_signer_holds_them()
    {
        Bootstrap();
        var passphrases = File.ReadAllBytes(Path.Combine(_config, "keystore.yaml"));

        Assert.Equal((0, 0, 0), InitContainers());

        // The passphrases are the signer's alone now, byte for byte as bootstrap wrote them.
        Assert.False(File.Exists(Path.Combine(_config, "keystore.yaml")));
        Assert.Equal(passphrases, File.ReadAllBytes(Paths.KeystoreYamlPath));

        // Hsm: is the signer's: in signer.yaml, and no longer in the node's file.
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", YamlConfigLoader.Load(Paths.ConfigPath, _ => { }).Hsm.ModulePath);
        Assert.DoesNotContain("Hsm:", File.ReadAllText(NodeConfig));
        Assert.DoesNotContain("libsofthsm2", File.ReadAllText(NodeConfig));

        // What the node reads is all still there.
        var nodeConfig = YamlConfigLoader.Load(NodeConfig, _ => { });
        Assert.True(nodeConfig.Signer.IsRemote);
        Assert.Equal("a-jwt-secret-only-the-node-reads", nodeConfig.JWT.Secret);
        Assert.Equal(8443, nodeConfig.Https.Port);
    }

    [Fact]
    public void A_pod_made_before_the_split_is_carried_over_with_its_identity_and_the_nodes_volume_is_cleaned()
    {
        // The 0.4.3 pod: one config.yaml with both halves, the identity under config/, passwords on
        // the identity files and an HSM PIN in the node's file.
        Bootstrap(c =>
        {
            c.Signer.ServerCertificatePassword = "server-pass-only-the-signer-reads";
            c.Signer.IdentityCaPassword = "ca-pass-only-the-signer-reads";
            c.Hsm.Pin = "hsm-pin-only-the-signer-reads";
        });
        var shared = SignerPaths.Shared(_base);
        var sharedSigner = YamlConfigLoader.Load(NodeConfig, _ => { }).Signer;
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", "--init-identity"], sharedSigner, shared));
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", "--issue-node-identity", "--apply", NodeConfig], sharedSigner, shared));
        var before = NodeSettings();
        var client = File.ReadAllBytes(Path.Combine(_config, "signer-client.pfx"));
        var server = File.ReadAllBytes(Path.Combine(_config, "signer-server.pfx"));
        var ca = File.ReadAllBytes(Path.Combine(_config, "signer-identity-ca.pfx"));
        Assert.True(File.Exists(Path.Combine(_config, "keystore.yaml")));

        // The new manifest: the signer's directory is filled from it, and nothing is reissued.
        Assert.Equal((0, 0, 0), InitContainers());

        Assert.Equal(client, File.ReadAllBytes(Path.Combine(_config, "signer-client.pfx")));
        Assert.Equal(server, File.ReadAllBytes(Path.Combine(_dir, "signer-server.pfx")));
        Assert.Equal(ca, File.ReadAllBytes(Path.Combine(_dir, "signer-identity-ca.pfx")));
        var signer = SignerSettings();
        Assert.Equal(before.PinnedClientSpki, signer.PinnedClientSpki);
        Assert.Equal("server-pass-only-the-signer-reads", signer.ServerCertificatePassword);
        Assert.Equal("hsm-pin-only-the-signer-reads", YamlConfigLoader.Load(Paths.ConfigPath, _ => { }).Hsm.Pin);

        // The signer's files are gone from the node's directory.
        Assert.False(File.Exists(Path.Combine(_config, "signer-server.pfx")));
        Assert.False(File.Exists(Path.Combine(_config, "signer-identity-ca.pfx")));
        Assert.False(File.Exists(Path.Combine(_config, "keystore.yaml")));

        // The node's file keeps the node's half, exactly, and nothing of the signer's.
        var node = NodeSettings();
        Assert.Equal(before.Mode, node.Mode);
        Assert.Equal(before.Endpoint, node.Endpoint);
        Assert.Equal(before.ClientCertificate, node.ClientCertificate);
        Assert.Equal(before.ClientCertificatePassword, node.ClientCertificatePassword);
        Assert.Equal(before.PinnedServerSpki, node.PinnedServerSpki);
        var text = File.ReadAllText(NodeConfig);
        foreach (var key in new[] { "Listen:", "ServerCertificate:", "ServerCertificatePassword:", "PinnedClientSpki:", "IdentityCa:", "IdentityCaPassword:", "Hsm:" })
            Assert.DoesNotContain(key, text);
        Assert.DoesNotContain("only-the-signer-reads", text);
        Assert.Equal("a-jwt-secret-only-the-node-reads", YamlConfigLoader.Load(NodeConfig, _ => { }).JWT.Secret);

        // The copy kept beside it, and the copies 0.4.3 left there, keep the node's settings and
        // lose the signer's.
        Assert.Single(Directory.GetFiles(_config, "config.yaml.pre-signer-cleanup-*.bak"));
        Assert.True(Directory.GetFiles(_config, "config.yaml.*.bak").Length >= 2);
        foreach (var backup in Directory.GetFiles(_config, "config.yaml.*.bak"))
        {
            var copy = File.ReadAllText(backup);
            Assert.DoesNotContain("only-the-signer-reads", copy);
            Assert.DoesNotContain("PinnedClientSpki", copy);
            Assert.DoesNotContain("Hsm:", copy);
            Assert.Equal("a-jwt-secret-only-the-node-reads", YamlConfigLoader.Load(backup, _ => { }).JWT.Secret);
        }
    }

    [Fact]
    public void The_copy_of_config_yaml_a_first_start_keeps_holds_none_of_the_signers_settings()
    {
        Bootstrap(c =>
        {
            c.Signer.ServerCertificatePassword = "server-pass-only-the-signer-reads";
            c.Signer.IdentityCaPassword = "ca-pass-only-the-signer-reads";
            c.Hsm.Pin = "hsm-pin-only-the-signer-reads";
        });

        Assert.Equal((0, 0, 0), InitContainers());

        // --apply's copy of the file as bootstrap wrote it.
        var backup = Assert.Single(Directory.GetFiles(_config, "config.yaml.pre-signer-2*.bak"));
        var copy = File.ReadAllText(backup);
        Assert.DoesNotContain("only-the-signer-reads", copy);
        foreach (var key in new[] { "Listen:", "ServerCertificate:", "PinnedClientSpki:", "IdentityCa:", "Hsm:" })
            Assert.DoesNotContain(key, copy);
        var config = YamlConfigLoader.Load(backup, _ => { });
        Assert.Equal("a-jwt-secret-only-the-node-reads", config.JWT.Secret);
        Assert.Equal(8443, config.Https.Port);
        // The signer's copies are where it reads them.
        Assert.Equal("server-pass-only-the-signer-reads", SignerSettings().ServerCertificatePassword);
        Assert.Equal("hsm-pin-only-the-signer-reads", YamlConfigLoader.Load(Paths.ConfigPath, _ => { }).Hsm.Pin);
    }

    [Fact]
    public void An_old_copy_of_config_yaml_is_scrubbed_of_the_signers_settings_and_otherwise_kept_byte_for_byte()
    {
        Bootstrap();
        static string Lines(params string[] lines) => string.Join("\r\n", lines) + "\r\n";
        var old = Path.Combine(_config, "config.yaml.pre-settings-20261001T000000Z.bak");
        File.WriteAllText(old, Lines(
            "# a comment the operator wrote",
            "JWT:",
            "  Secret: \"old-jwt\"",
            "Signer:",
            "  Mode: \"Remote\"",
            "  Endpoint: \"https://127.0.0.1:8446\"",
            "  Listen: \"127.0.0.1:8446\"",
            "  ServerCertificatePassword: \"old-server-pass-only-the-signer-reads\"",
            "  PinnedClientSpki: \"abcd\"",
            "  PinnedServerSpki: \"ef01\"",
            "Hsm:",
            "  Enabled: true",
            "  ModulePath: \"/usr/lib/softhsm/libsofthsm2.so\"",
            "  Pin: \"old-pin-only-the-signer-reads\"",
            "",
            "Https:",
            "  Port: 8443"));

        Assert.Equal((0, 0, 0), InitContainers());

        Assert.True(File.Exists(old));
        Assert.Equal(Lines(
            "# a comment the operator wrote",
            "JWT:",
            "  Secret: \"old-jwt\"",
            "Signer:",
            "  Mode: \"Remote\"",
            "  Endpoint: \"https://127.0.0.1:8446\"",
            "  PinnedServerSpki: \"ef01\"",
            "",
            "Https:",
            "  Port: 8443"), File.ReadAllText(old));

        // A second start finds nothing in it, or anywhere, and says nothing.
        var cleaned = Snapshot();
        Assert.Equal((0, 0, 0), InitContainers());
        Assert.Equal(cleaned, Snapshot());
        var (output, error) = RunCleanup();
        Assert.Equal(string.Empty, output);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void A_copy_of_config_yaml_that_cannot_be_read_is_left_with_a_warning_that_shows_none_of_it()
    {
        Bootstrap();
        var broken = Path.Combine(_config, "config.yaml.mariadb-20250101-000000.bak");
        const string contents = "Signer:\n  IdentityCaPassword: \"unparsed-secret\n  : [\n";
        File.WriteAllText(broken, contents);

        Assert.Equal((0, 0, 0), InitContainers());

        Assert.Equal(contents, File.ReadAllText(broken));
        var (_, error) = RunCleanup();
        Assert.Contains("[WARNING]", error);
        Assert.Contains("config.yaml.mariadb-20250101-000000.bak was left as it is", error);
        Assert.DoesNotContain("unparsed-secret", error);
    }

    [Fact]
    public async Task After_the_clean_up_the_channel_still_works_and_a_second_start_changes_and_says_nothing()
    {
        Bootstrap();
        var shared = SignerPaths.Shared(_base);
        var sharedSigner = YamlConfigLoader.Load(NodeConfig, _ => { }).Signer;
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", "--init-identity"], sharedSigner, shared));
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", "--issue-node-identity", "--apply", NodeConfig], sharedSigner, shared));
        Assert.Equal((0, 0, 0), InitContainers());
        var cleaned = Snapshot();

        Assert.Equal((0, 0, 0), InitContainers());
        Assert.Equal(cleaned, Snapshot());
        var (output, error) = RunCleanup();
        Assert.Equal(string.Empty, output);
        Assert.Equal(string.Empty, error);

        // The node saving its settings writes every setting back, the signer's at their defaults:
        // that carries nothing of the signer's, and the next start leaves it alone.
        ConfigYamlWriter.Write(NodeConfig, YamlConfigLoader.Load(NodeConfig, _ => { }));
        var resaved = Snapshot();
        Assert.Equal((0, 0, 0), InitContainers());
        Assert.Equal(resaved, Snapshot());
        (output, error) = RunCleanup();
        Assert.Equal(string.Empty, output);
        Assert.Equal(string.Empty, error);

        var signer = SignerSettings();
        var node = NodeSettings();
        using var serverCertificate = Pkcs12Files.Load(Path.Combine(_dir, "signer-server.pfx"), signer.ServerCertificatePassword);
        using var clientCertificate = Pkcs12Files.Load(Path.Combine(_config, "signer-client.pfx"), node.ClientCertificatePassword);
        await using var listening = await ListenAsync(serverCertificate, signer.PinnedClientSpki);
        using var remote = new RemoteSigningService(
            new RemoteSignerOptions(new Uri($"https://127.0.0.1:{listening.Port}"), clientCertificate, node.PinnedServerSpki) { ConnectTimeout = TimeSpan.FromSeconds(5) },
            NullLogger<RemoteSigningService>.Instance);
        Assert.NotEqual(SignerHealth.UnreachableBackend, (await remote.HealthAsync()).Backend);
    }

    [Fact]
    public void A_signers_keystore_yaml_with_other_passphrases_leaves_the_nodes_copy_with_a_warning()
    {
        Bootstrap();
        Assert.Equal(0, RunMigration(SignerPaths.Shared(_base), Paths));
        File.WriteAllText(Paths.KeystoreYamlPath, "ca-certs.keystore: \"changed-on-the-signer\"\n");
        var nodeCopy = File.ReadAllBytes(Path.Combine(_config, "keystore.yaml"));

        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", SignerPaths.Flag, _dir, "--init-identity"], SignerSettings(), Paths));
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", SignerPaths.Flag, _dir, "--issue-node-identity", "--apply", NodeConfig], SignerSettings(), Paths));

        Assert.Equal(nodeCopy, File.ReadAllBytes(Path.Combine(_config, "keystore.yaml")));
        var (_, error) = RunCleanup();
        Assert.Contains("[WARNING]", error);
        Assert.Contains("keystore.yaml was left in place", error);
        Assert.Contains("does not hold the same passphrases", error);
        Assert.DoesNotContain("secondary", error);
        Assert.DoesNotContain("changed-on-the-signer", error);
        Assert.Equal(nodeCopy, File.ReadAllBytes(Path.Combine(_config, "keystore.yaml")));
    }

    [Fact]
    public void A_signers_keystore_yaml_written_differently_with_the_same_passphrases_counts_as_a_copy()
    {
        Bootstrap();
        Assert.Equal(0, RunMigration(SignerPaths.Shared(_base), Paths));
        File.WriteAllText(Paths.KeystoreYamlPath, "# reformatted\nca-certs.keystore: secondary\n");

        Assert.Equal((0, 0, 0), InitContainers());

        Assert.False(File.Exists(Path.Combine(_config, "keystore.yaml")));
    }

    [Fact]
    public void A_signers_identity_that_does_not_check_out_leaves_the_nodes_identity_files_and_settings_with_a_warning()
    {
        Bootstrap();
        var shared = SignerPaths.Shared(_base);
        var sharedSigner = YamlConfigLoader.Load(NodeConfig, _ => { }).Signer;
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", "--init-identity"], sharedSigner, shared));
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--role", "signer", "--issue-node-identity", "--apply", NodeConfig], sharedSigner, shared));
        Assert.Equal(0, RunMigration(shared, Paths));
        // The signer's copy of its identity CA is lost before the node's copies are cleaned up.
        File.Delete(Path.Combine(_dir, "signer-identity-ca.pfx"));
        var nodeFile = File.ReadAllText(NodeConfig);

        var (output, error) = RunCleanup();

        Assert.Contains("[WARNING] Left in the node's config directory: signer-server.pfx, signer-identity-ca.pfx, the signer's half of Signer: in config.yaml", error);
        Assert.Contains("identity CA", error);
        Assert.True(File.Exists(Path.Combine(_config, "signer-server.pfx")));
        Assert.True(File.Exists(Path.Combine(_config, "signer-identity-ca.pfx")));
        Assert.Equal(nodeFile, File.ReadAllText(NodeConfig));
        Assert.Empty(Directory.GetFiles(_config, "config.yaml.pre-signer-cleanup-*.bak"));
        // keystore.yaml rests on its own check, which the copy passes.
        Assert.False(File.Exists(Path.Combine(_config, "keystore.yaml")));
        Assert.Contains("keystore.yaml", output);
    }

    [Fact]
    public void Apply_without_the_signers_settings_file_is_refused_and_changes_nothing()
    {
        Bootstrap();
        Assert.Equal(0, SignerIdentityInitTests.RunIdentity(["--init-identity"], new SignerConfig { ServerCertificate = "signer-server.pfx", IdentityCa = "signer-identity-ca.pfx" }, Paths));
        var before = File.ReadAllText(NodeConfig);

        Assert.Equal(1, SignerIdentityInitTests.RunIdentity(["--issue-node-identity", "--apply", NodeConfig], new SignerConfig(), Paths));

        Assert.Equal(before, File.ReadAllText(NodeConfig));
        Assert.False(File.Exists(Path.Combine(_config, "signer-client.pfx")));
    }

    /// <summary>Every file under both directories, with its size and contents' hash, for a before-and-after comparison.</summary>
    private string Snapshot()
        => string.Join("\n", new[] { _config, _dir }.SelectMany(d => Directory.EnumerateFiles(d, "*", SearchOption.AllDirectories))
            .Where(f => !f.Contains(Path.DirectorySeparatorChar + "logs" + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => $"{f} {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(f)))}"));

    /// <summary>Runs the clean-up of the node's config directory on its own, as node-identity does after the pins; returns what it wrote to standard output and standard error.</summary>
    private (string Output, string Error) RunCleanup()
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Startup.NodeSideSignerCleanup");
        var run = type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
        using var output = new StringWriter();
        using var error = new StringWriter();
        try
        {
            run.Invoke(null, [NodeConfig, Paths, output, error]);
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
        return (output.ToString(), error.ToString());
    }

    private static int RunMigration(SignerPaths from, SignerPaths to)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Startup.SignerDirectoryMigration");
        var run = type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
        using var output = new StringWriter();
        using var error = new StringWriter();
        try
        {
            return (int)run.Invoke(null, [from, to, output, error])!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }

    /// <summary>A signer listener on a free loopback port over the given server certificate, admitting the given client pin.</summary>
    private static async Task<Listening> ListenAsync(System.Security.Cryptography.X509Certificates.X509Certificate2 server, string pinnedClientSpki)
    {
        var app = SignerServerHost.Build(new SignerServerOptions(IPAddress.Loopback, 0, server, pinnedClientSpki), builder =>
        {
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton<ISigningService>(new SettingsTestSigner());
        });
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new Listening(app, new Uri(address.Replace("[::1]", "127.0.0.1")).Port);
    }

    /// <summary>A running signer listener and its port.</summary>
    private sealed record Listening(WebApplication App, int Port) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await App.StopAsync();
            await App.DisposeAsync();
        }
    }
}
