using System.Diagnostics;
using ModularCA.Ssh;
using ModularCA.Tests.Signer;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// OpenSSH's own tool reads what the node issues: a certificate with <c>ssh-keygen -L</c> and a
/// KRL with <c>ssh-keygen -Q</c>. The node never runs the tool; this test does, and only where
/// it is installed.
/// </summary>
public sealed class SshCaOpenSshInteropTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-ssh-interop-{Guid.NewGuid():N}");

    public SshCaOpenSshInteropTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string Write(string name, string text)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, text + "\n");
        return path;
    }

    private string Write(string name, byte[] bytes)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static async Task<(int ExitCode, string Output)> SshKeygenAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo(RequiresSshKeygenFactAttribute.SshKeygenPath!)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);

        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("ssh-keygen did not finish within 30 seconds.");
        }
        return (process.ExitCode, await output + await error);
    }

    [RequiresSshKeygenFact]
    public async Task Ssh_keygen_reads_a_certificate_the_node_issued_and_the_krl_that_revokes_it()
    {
        foreach (var (keyType, keySize) in new (string, int?)[] { ("ed25519", null), ("ecdsa", 384), ("rsa", 2048) })
        {
            using var node = new SshNode();
            var ca = await node.CreateCaAsync($"Interop {keyType}", keyType, keySize);
            var revoked = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice", "ops"], 2,
                ["permit-pty", "force-command=/usr/bin/uptime", "source-address=192.0.2.0/24"], node.Actor);
            var standing = await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey("ECDSA", "P-256", "host1"), ["host1.example.com"], 2, node.Actor);
            var caFingerprint = SshPublicKey.ParseAuthorizedKey(ca.PublicKey).Fingerprint;

            var userFile = Write($"{keyType}-user-cert.pub", revoked.SignedCertificate);
            var hostFile = Write($"{keyType}-host-cert.pub", standing.SignedCertificate);

            var (userExit, user) = await SshKeygenAsync("-L", "-f", userFile);
            Assert.True(userExit == 0, user);
            Assert.Contains("user certificate", user);
            Assert.Contains($"Serial: {revoked.SerialNumber}", user);
            Assert.Contains($"Key ID: \"{SshNode.CiKeyId}\"", user);
            Assert.Contains(caFingerprint, user);
            Assert.Contains("alice", user);
            Assert.Contains("ops", user);
            Assert.Contains("force-command /usr/bin/uptime", user);
            Assert.Contains("source-address 192.0.2.0/24", user);
            Assert.Contains("permit-pty", user);
            Assert.DoesNotContain("permit-agent-forwarding", user);
            Assert.DoesNotContain("permit-user-rc", user);

            var (hostExit, host) = await SshKeygenAsync("-L", "-f", hostFile);
            Assert.True(hostExit == 0, host);
            Assert.Contains("host certificate", host);
            Assert.Contains("host1.example.com", host);

            // Nothing revoked: a KRL with no entries, which the tool reads and finds neither certificate in.
            var emptyKrl = Write($"{keyType}-empty.krl", await node.Service.GenerateKrlAsync(ca.Id));
            var (_, clean) = await SshKeygenAsync("-Q", "-f", emptyKrl, userFile, hostFile);
            Assert.DoesNotContain("REVOKED", clean);
            Assert.Equal(2, clean.Split('\n').Count(line => line.TrimEnd().EndsWith(": ok", StringComparison.Ordinal)));

            Assert.True(await node.Service.RevokeCertificateAsync(revoked.Id, ca.Id, node.Actor));
            var krl = Write($"{keyType}.krl", await node.Service.GenerateKrlAsync(ca.Id));
            var (_, userVerdict) = await SshKeygenAsync("-Q", "-f", krl, userFile);
            var (_, hostVerdict) = await SshKeygenAsync("-Q", "-f", krl, hostFile);
            Assert.Contains("REVOKED", userVerdict);
            Assert.DoesNotContain("REVOKED", hostVerdict);
            Assert.Contains(": ok", hostVerdict);

            var (listExit, listing) = await SshKeygenAsync("-Q", "-l", "-f", krl);
            Assert.True(listExit == 0, listing);
            Assert.Contains($"serial: {revoked.SerialNumber}", listing);
        }
    }
}
