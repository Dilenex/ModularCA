using System.Diagnostics;
using System.Reflection;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The signer's own directory end to end: the startup reads its configuration and database
/// credentials through <see cref="SignerPaths"/> and the keystore unlock reads no file of its
/// own, the identity commands write into the directory, the migration copies only what the
/// signer needs, and the built binary, run as the signer with <c>--signer-dir</c>, names only
/// that directory's files and leaves the application directory's <c>config/</c> alone.
/// </summary>
public sealed class SignerDirectoryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-signerdir-" + Guid.NewGuid().ToString("N"));
    private readonly string _base;
    private readonly string _dir;

    public SignerDirectoryTests()
    {
        _base = Path.Combine(_root, "app");
        _dir = Path.Combine(_root, "signer");
        Directory.CreateDirectory(_base);
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    // ── The loader inputs ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_startup_loads_config_and_db_yaml_from_the_signer_paths_and_has_no_setup_fallback_for_them()
    {
        var startup = Source("ModularCA.API", "StartModularCA.cs");

        Assert.Contains("var dbYamlPath = signerPaths.DbYamlPath;", startup);
        Assert.Contains("var dbYaml = YamlDbConfigLoader.Load(dbYamlPath);", startup);
        Assert.Contains("var configPath = signerPaths.ConfigPath;", startup);
        Assert.Contains("config = YamlConfigLoader.Load(configPath);", startup);
        // The maintenance and backup signers of --backup and --restore use the signer's keystore.yaml.
        var flat = startup.ReplaceLineEndings("\n");
        Assert.Contains("MaintenanceSigner.Create(\n        signerPaths.KeystoresDirectory,\n        signerPaths.KeystoreYamlPath,", flat);
        Assert.Contains("MaintenanceSigner.CreateUnlocked(\n            signerPaths.KeystoresDirectory,\n            signerPaths.KeystoreYamlPath,", flat);

        var dedicated = startup.IndexOf("else if (signerPaths.IsDedicated)", StringComparison.Ordinal);
        var setupDatabase = startup.IndexOf("\"setup-database.yaml\")", StringComparison.Ordinal);
        Assert.True(dedicated > 0 && setupDatabase > dedicated, "the setup-database.yaml fallback must sit behind the signer-directory branch");

        Assert.Contains("SignerIdentityCommands.Run(args, config.Signer, signerPaths)", startup);
        Assert.Contains("SignerRole.RunAsync(config, appConnStr, isSetupMode, signerPaths)", startup);
        Assert.Contains("Path.Combine(signerPaths.LogsDirectory, \"modularca-bootstrap-.log\")", startup);
    }

    [Fact]
    public void The_signer_role_takes_every_path_from_its_signer_paths()
    {
        var role = Source("ModularCA.API", "Startup", "SignerRole.cs");

        Assert.DoesNotContain("\"config\",", role);
        Assert.DoesNotContain("\"config\")", role);
        Assert.DoesNotContain("AppContext.BaseDirectory", role);
        Assert.Contains("var keystoreYamlPath = paths.KeystoreYamlPath;", role);
        Assert.Contains("var keystoresDirectory = paths.KeystoresDirectory;", role);
        Assert.Contains("SignerBootstrap.Unlock(keystoreYamlPath, keystoresDirectory, appConnStr)", role);
        Assert.Contains("paths.ResolveFile(signerConfig.ServerCertificate)", role);
        Assert.Contains("KeystoreService.AuditLogDirectory = paths.LogsDirectory", role);
    }

    [Fact]
    public void The_keystore_unlock_reads_no_configuration_file_of_its_own()
    {
        var loader = Source("ModularCA.Keystore", "Utils", "KeystoreDbPassphraseLoader.cs");
        Assert.DoesNotContain("AppContext.BaseDirectory", loader);
        Assert.DoesNotContain("YamlConfigLoader", loader);
        Assert.DoesNotContain("YamlDbConfigLoader", loader);
        Assert.DoesNotContain("LoadSecondaryPassphrase(", loader);

        var method = typeof(ModularCA.Keystore.Utils.KeystoreDbPassphraseLoader).GetMethod("RetrieveFromDatabase")!;
        Assert.Equal(new[] { typeof(ModularCA.Database.ModularCADbContext), typeof(string), typeof(string) },
            method.GetParameters().Select(p => p.ParameterType));
    }

    // ── The identity commands ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Init_identity_writes_into_the_signers_directory_and_nothing_under_config()
    {
        var paths = SignerPaths.Dedicated(_base, _dir);
        var signer = new SignerConfig { Listen = "127.0.0.1:18446" };

        Assert.Equal(0, RunIdentity(new[] { "--role", "signer", SignerPaths.Flag, _dir, "--init-identity" }, signer, paths));

        Assert.True(File.Exists(Path.Combine(_dir, "signer-identity-ca.pfx")));
        Assert.True(File.Exists(Path.Combine(_dir, "signer-server.pfx")));
        Assert.False(Directory.Exists(Path.Combine(_base, "config")));
        Assert.False(Directory.Exists(Path.Combine(_dir, "config")));

        var issued = Path.Combine(_root, "node-identity");
        Assert.Equal(0, RunIdentity(new[] { "--role", "signer", "--issue-node-identity", issued }, signer, paths));
        Assert.True(File.Exists(Path.Combine(issued, "signer-client.pfx")));
        Assert.True(File.Exists(Path.Combine(issued, "signer-pin.txt")));
    }

    [Fact]
    public void Init_identity_without_the_directory_writes_under_config_as_before()
    {
        var signer = new SignerConfig { Listen = "127.0.0.1:18446" };
        Assert.Equal(0, RunIdentity(new[] { "--role", "signer", "--init-identity" }, signer, SignerPaths.Shared(_base)));

        Assert.True(File.Exists(Path.Combine(_base, "config", "signer-identity-ca.pfx")));
        Assert.True(File.Exists(Path.Combine(_base, "config", "signer-server.pfx")));
        Assert.Empty(Directory.EnumerateFileSystemEntries(_dir));
    }

    [Fact]
    public void Apply_is_refused_with_the_signers_directory_and_the_config_is_untouched()
    {
        var paths = SignerPaths.Dedicated(_base, _dir);
        var signer = new SignerConfig { Listen = "127.0.0.1:18446" };
        Assert.Equal(0, RunIdentity(new[] { "--init-identity" }, signer, paths));
        var nodeConfig = Path.Combine(_root, "node", "config.yaml");
        Directory.CreateDirectory(Path.GetDirectoryName(nodeConfig)!);
        File.WriteAllText(nodeConfig, "Signer:\n  Mode: \"InProcess\"\n");

        Assert.Equal(1, RunIdentity(new[] { "--issue-node-identity", "--apply", nodeConfig }, signer, paths));
        Assert.Equal("Signer:\n  Mode: \"InProcess\"\n", File.ReadAllText(nodeConfig));
    }

    // ── The migration ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_migration_copies_only_what_the_signer_reads_and_changes_nothing_under_config()
    {
        var config = Path.Combine(_base, "config");
        Directory.CreateDirectory(config);
        File.WriteAllText(Path.Combine(config, "config.yaml"), """
            JWT:
              Secret: "node-only-jwt-secret"
            Signer:
              Mode: "Remote"
              Endpoint: "https://127.0.0.1:8446"
              ClientCertificate: "config/signer-client.pfx"
              PinnedServerSpki: "aaaa"
              Listen: "127.0.0.1:8446"
              ServerCertificate: "config/signer-server.pfx"
              PinnedClientSpki: "bbbb"
            Hsm:
              Enabled: true
              ModulePath: "/usr/lib/softhsm/libsofthsm2.so"
              SlotId: 3
            Schema:
              WaitSeconds: 42
            Logging:
              MinLevel: "Warning"
              FilePath: "/var/log/modularca/node-.log"
            """);
        YamlDbConfigLoader.Write(Path.Combine(config, "db.yaml"), new YamlDbConfigLoader.DbYamlConfig
        {
            App = new() { Host = "db.example", Database = "modularca", Username = "mca_app", Password = "app-pass" },
            Audit = new() { Host = "db.example", Database = "modularca_audit", Username = "mca_audit", Password = "audit-pass" },
        });
        File.WriteAllText(Path.Combine(config, "keystore.yaml"), "ca-certs.keystore: \"secondary\"\n");
        File.WriteAllBytes(Path.Combine(config, "signer-server.pfx"), new byte[] { 1, 2, 3 });
        File.WriteAllBytes(Path.Combine(config, "signer-identity-ca.pfx"), new byte[] { 4, 5, 6 });
        var before = Snapshot(config);

        var to = SignerPaths.Dedicated(_base, _dir);
        Assert.Equal(0, RunMigration(SignerPaths.Shared(_base), to, out var output, out var error));
        Assert.True(error.Length == 0, error);

        var yaml = File.ReadAllText(to.ConfigPath);
        Assert.DoesNotContain("node-only-jwt-secret", yaml);
        Assert.DoesNotContain("JWT", yaml);
        Assert.DoesNotContain("Endpoint", yaml);
        Assert.DoesNotContain("PinnedServerSpki", yaml);
        Assert.DoesNotContain("/var/log/modularca", yaml);
        var loaded = YamlConfigLoader.Load(to.ConfigPath, _ => { });
        Assert.Equal("127.0.0.1:8446", loaded.Signer.Listen);
        Assert.Equal("bbbb", loaded.Signer.PinnedClientSpki);
        Assert.Equal("signer-server.pfx", loaded.Signer.ServerCertificate);
        Assert.Equal(Path.Combine(_dir, "signer-server.pfx"), to.ResolveFile(loaded.Signer.ServerCertificate));
        Assert.Equal(Path.Combine(_dir, "signer-identity-ca.pfx"), to.ResolveFile(loaded.Signer.IdentityCa));
        Assert.True(loaded.Hsm.Enabled);
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", loaded.Hsm.ModulePath);
        Assert.Equal(3UL, loaded.Hsm.SlotId);
        Assert.Equal(42, loaded.Schema.WaitSeconds);
        Assert.Equal("Warning", loaded.Logging.MinLevel);
        Assert.Equal(new LoggingConfig().FilePath, loaded.Logging.FilePath);

        var db = YamlDbConfigLoader.Load(to.DbYamlPath)!;
        Assert.Equal("mca_app", db.App.Username);
        Assert.Equal("app-pass", db.App.Password);
        Assert.Equal(string.Empty, db.Audit.Database);
        Assert.DoesNotContain("audit-pass", File.ReadAllText(to.DbYamlPath));

        Assert.Equal("ca-certs.keystore: \"secondary\"\n", File.ReadAllText(to.KeystoreYamlPath));
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(Path.Combine(_dir, "signer-server.pfx")));
        Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(Path.Combine(_dir, "signer-identity-ca.pfx")));
        Assert.Equal(before, Snapshot(config));
        Assert.Contains("Hsm.ModulePath", output);

        // A second run refuses and changes nothing.
        var signerYaml = File.ReadAllText(to.ConfigPath);
        Assert.Equal(1, RunMigration(SignerPaths.Shared(_base), to, out _, out var again));
        Assert.Contains("already holds", again);
        Assert.Equal(signerYaml, File.ReadAllText(to.ConfigPath));
    }

    [Fact]
    public void The_migration_refuses_a_directory_that_does_not_exist()
    {
        var missing = SignerPaths.Dedicated(_base, Path.Combine(_root, "absent"));
        Assert.Equal(1, RunMigration(SignerPaths.Shared(_base), missing, out _, out var error));
        Assert.Contains("does not exist", error);
        Assert.False(Directory.Exists(Path.Combine(_root, "absent")));
    }

    // ── The built binary ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_binary_as_signer_with_its_own_directory_creates_its_identity_there()
    {
        File.WriteAllText(Path.Combine(_dir, "signer.yaml"), "Signer:\n  Listen: \"127.0.0.1:18447\"\n");
        var apiConfig = Path.Combine(ApiDirectory(), "config");
        var before = Snapshot(apiConfig);

        var (code, output) = RunApi("--role", "signer", SignerPaths.Flag, _dir, "--init-identity");

        Assert.True(code == 0, output);
        Assert.True(File.Exists(Path.Combine(_dir, "signer-identity-ca.pfx")), output);
        Assert.True(File.Exists(Path.Combine(_dir, "signer-server.pfx")), output);
        Assert.Contains(Path.Combine(_dir, "signer-server.pfx"), output);
        Assert.True(Directory.Exists(Path.Combine(_dir, "logs")), "the startup log goes to the signer's directory");
        Assert.Equal(before, Snapshot(apiConfig));
    }

    [Fact]
    public void The_binary_as_signer_with_its_own_directory_and_no_db_yaml_there_refuses_naming_only_that_directory()
    {
        File.WriteAllText(Path.Combine(_dir, "signer.yaml"), "Signer:\n  Listen: \"127.0.0.1:18448\"\n");

        var (code, output) = RunApi("--role", "signer", SignerPaths.Flag, _dir);

        Assert.True(code == 1, output);
        Assert.Contains(Path.Combine(_dir, "signer.yaml"), output);
        Assert.Contains(Path.Combine(_dir, "db.yaml"), output);
        Assert.DoesNotContain("Running in setup mode", output);
        Assert.DoesNotContain(Path.Combine("config", "config.yaml"), output);
    }

    [Fact]
    public void The_binary_refuses_the_flag_outside_the_signer_role()
    {
        var (code, output) = RunApi("--role", "node", SignerPaths.Flag, _dir);
        Assert.True(code == 1, output);
        Assert.Contains("signer role only", output);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private static int RunIdentity(string[] args, SignerConfig signer, SignerPaths paths)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Startup.SignerIdentityCommands");
        var run = type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static, new[] { typeof(IReadOnlyList<string>), typeof(SignerConfig), typeof(SignerPaths) })!;
        return Invoke<int>(run, args, signer, paths);
    }

    private static int RunMigration(SignerPaths from, SignerPaths to, out string output, out string error)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Startup.SignerDirectoryMigration");
        var run = type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
        using var o = new StringWriter();
        using var e = new StringWriter();
        var code = Invoke<int>(run, from, to, o, e);
        output = o.ToString();
        error = e.ToString();
        return code;
    }

    private static T Invoke<T>(MethodInfo method, params object[] args)
    {
        try
        {
            return (T)method.Invoke(null, args)!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }

    private static string ApiDirectory() => Path.GetDirectoryName(ApiAssembly.Instance.Location)!;

    /// <summary>Runs the built API with <paramref name="args"/> and returns its exit code and combined output.</summary>
    private (int Code, string Output) RunApi(params string[] args)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = _root,
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

    private static string Snapshot(string directory)
        => !Directory.Exists(directory) ? "(none)" : string.Join("\n", Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => $"{f} {new FileInfo(f).Length} {File.GetLastWriteTimeUtc(f):O}"));

    private static string Source(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(new[] { dir!.FullName }.Concat(parts).ToArray()));
    }
}
