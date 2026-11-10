using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using ModularCA.Core.Services.Settings;
using ModularCA.Shared.Models.Config;
using ModularCA.Signer.Identity;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// <c>--role signer --check-ready</c>, the signer container's health command: it answers 0 only
/// when the real signer listener, mutual TLS and all, is up at <c>Signer.Listen</c> with the
/// signer's own server certificate, and 1 when nothing listens there, another certificate
/// answers, or the signer is not configured. The built binary is run as a container manager
/// would run it.
/// </summary>
[Collection(RemoteSignerCollection.Name)]
public sealed class SignerReadinessCheckTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-signerready-" + Guid.NewGuid().ToString("N"));
    private readonly string _base;
    private readonly string _dir;

    /// <summary>Creates an application directory and a signer directory holding the test signer's server certificate.</summary>
    public SignerReadinessCheckTests()
    {
        _base = Path.Combine(_root, "app");
        _dir = Path.Combine(_root, "signer");
        Directory.CreateDirectory(_base);
        Directory.CreateDirectory(_dir);
        var identity = RemoteSignerIdentity.Instance;
        Pkcs12Files.Write(Path.Combine(_dir, "signer-server.pfx"), identity.Server, [identity.IdentityCa], string.Empty);
    }

    /// <summary>Removes the temporary root.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private SignerPaths Paths => SignerPaths.Dedicated(_base, _dir);

    [Fact]
    public async Task A_listening_signer_with_its_own_certificate_is_ready()
    {
        await using var signer = await HostedSigner.StartAsync(new NoSecretsSigner());

        var (code, output) = await CheckAsync(new SignerConfig { Listen = $"127.0.0.1:{signer.Port}" });

        Assert.True(code == 0, output);
        Assert.Contains("ready", output);
    }

    [Fact]
    public async Task A_signer_that_admits_another_client_is_still_ready_since_the_check_presents_none()
    {
        var other = RemoteSignerIdentity.Instance.UnpinnedClient;
        await using var signer = await HostedSigner.StartAsync(new NoSecretsSigner(), pinnedClientSpki: SpkiPin.Compute(other));

        var (code, output) = await CheckAsync(new SignerConfig { Listen = $"127.0.0.1:{signer.Port}" });

        Assert.True(code == 0, output);
    }

    [Fact]
    public async Task Nothing_listening_is_not_ready()
    {
        var (code, output) = await CheckAsync(new SignerConfig { Listen = $"127.0.0.1:{FreePort()}" });

        Assert.Equal(1, code);
        Assert.Contains("nothing accepts connections", output);
    }

    [Fact]
    public async Task A_stopped_signer_is_not_ready()
    {
        var signer = await HostedSigner.StartAsync(new NoSecretsSigner());
        var port = signer.Port;
        await signer.DisposeAsync();

        var (code, _) = await CheckAsync(new SignerConfig { Listen = $"127.0.0.1:{port}" });

        Assert.Equal(1, code);
    }

    [Fact]
    public async Task Another_certificate_answering_is_not_ready()
    {
        await using var signer = await HostedSigner.StartAsync(new NoSecretsSigner());
        var now = DateTimeOffset.UtcNow;
        using var otherCa = SignerIdentity.CreateIdentityCa(now);
        using var otherServer = SignerIdentity.IssueServerCertificate(otherCa, "127.0.0.1", now);
        Pkcs12Files.Write(Path.Combine(_dir, "signer-server.pfx"), otherServer, [otherCa], string.Empty);

        var (code, output) = await CheckAsync(new SignerConfig { Listen = $"127.0.0.1:{signer.Port}" });

        Assert.Equal(1, code);
        Assert.Contains("not the signer's", output);
    }

    [Fact]
    public async Task A_signer_with_no_server_certificate_is_not_ready()
    {
        File.Delete(Path.Combine(_dir, "signer-server.pfx"));

        var (code, output) = await CheckAsync(new SignerConfig { Listen = $"127.0.0.1:{FreePort()}" });

        Assert.Equal(1, code);
        Assert.Contains("signer-server.pfx", output);
    }

    [Fact]
    public async Task The_binary_answers_zero_for_a_listening_signer_and_one_for_none()
    {
        await using var signer = await HostedSigner.StartAsync(new NoSecretsSigner());
        File.WriteAllText(Path.Combine(_dir, "signer.yaml"), $"Signer:\n  Listen: \"127.0.0.1:{signer.Port}\"\n  ServerCertificate: \"signer-server.pfx\"\n");

        var (ready, readyOutput) = RunApi("--role", "signer", SignerPaths.Flag, _dir, "--check-ready");
        Assert.True(ready == 0, readyOutput);
        Assert.Contains("ready:", readyOutput);
        Assert.False(Directory.Exists(Path.Combine(_dir, "logs")), "the health command writes no log");

        await signer.StopAsync();
        var (down, downOutput) = RunApi("--role", "signer", SignerPaths.Flag, _dir, "--check-ready");
        Assert.True(down == 1, downOutput);
        Assert.Contains("not ready", downOutput);
    }

    [Fact]
    public void The_binary_refuses_the_check_outside_the_signer_role_and_an_unconfigured_signer()
    {
        var (node, nodeOutput) = RunApi("--role", "node", "--check-ready");
        Assert.True(node == 1, nodeOutput);
        Assert.Contains("add --role signer", nodeOutput);

        var (unconfigured, output) = RunApi("--role", "signer", SignerPaths.Flag, _dir, "--check-ready");
        Assert.True(unconfigured == 1, output);
        Assert.Contains("signer.yaml", output);
    }

    /// <summary>Runs <c>SignerReadinessCheck.CheckAsync</c> from the built API and returns its exit code with both outputs.</summary>
    private async Task<(int Code, string Output)> CheckAsync(SignerConfig signer)
    {
        signer.ServerCertificate = "signer-server.pfx";
        var type = ApiAssembly.TypeNamed("ModularCA.API.Startup.SignerReadinessCheck");
        var check = type.GetMethod("CheckAsync", BindingFlags.Public | BindingFlags.Static)!;
        using var output = new StringWriter();
        using var error = new StringWriter();
        Task<int> task;
        try
        {
            task = (Task<int>)check.Invoke(null, [signer, Paths, TimeSpan.FromSeconds(10), output, error])!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
        var code = await task;
        return (code, output.ToString() + error);
    }

    /// <summary>A loopback port nothing listens on at the moment of asking.</summary>
    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
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
}
