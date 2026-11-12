using System.Reflection;
using ModularCA.Shared.Models.Config;
using ModularCA.Signer.Identity;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// <c>--role signer --init-identity</c> run more than once, as the pod's <c>signer-init</c> init
/// container runs it on every start: a whole identity already on disk is left alone and the
/// command exits zero; a partial or inconsistent one is refused, loudly and without a change;
/// and <c>--force</c> is still the only way to replace the CA.
/// </summary>
public sealed class SignerIdentityInitTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-signerinit-" + Guid.NewGuid().ToString("N"));
    private readonly string _base;
    private readonly string _dir;

    /// <summary>Creates an application directory and a signer directory under a fresh temporary root.</summary>
    public SignerIdentityInitTests()
    {
        _base = Path.Combine(_root, "app");
        _dir = Path.Combine(_root, "signer");
        Directory.CreateDirectory(_base);
        Directory.CreateDirectory(_dir);
    }

    /// <summary>Removes the temporary root.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string CaPath => Path.Combine(_dir, "signer-identity-ca.pfx");
    private string ServerPath => Path.Combine(_dir, "signer-server.pfx");
    private SignerPaths Dedicated => SignerPaths.Dedicated(_base, _dir);
    private static SignerConfig Loopback() => new() { Listen = "127.0.0.1:18446" };

    [Fact]
    public void A_second_run_finds_the_identity_and_exits_zero_with_both_files_unchanged()
    {
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        var ca = File.ReadAllBytes(CaPath);
        var server = File.ReadAllBytes(ServerPath);

        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));

        Assert.Equal(ca, File.ReadAllBytes(CaPath));
        Assert.Equal(server, File.ReadAllBytes(ServerPath));
    }

    [Fact]
    public void A_second_run_in_the_shared_layout_also_exits_zero_and_changes_nothing()
    {
        var shared = SignerPaths.Shared(_base);
        Assert.Equal(0, RunIdentity(["--role", "signer", "--init-identity"], Loopback(), shared));
        var caPath = Path.Combine(_base, "config", "signer-identity-ca.pfx");
        var ca = File.ReadAllBytes(caPath);

        Assert.Equal(0, RunIdentity(["--role", "signer", "--init-identity"], Loopback(), shared));
        Assert.Equal(ca, File.ReadAllBytes(caPath));
    }

    [Fact]
    public void A_second_run_with_passwords_opens_the_files_under_them()
    {
        var signer = new SignerConfig { Listen = "127.0.0.1:18446", IdentityCaPassword = "ca-pass", ServerCertificatePassword = "server-pass" };
        Assert.Equal(0, RunIdentity(["--init-identity"], signer, Dedicated));
        Assert.Equal(0, RunIdentity(["--init-identity"], signer, Dedicated));

        var wrong = new SignerConfig { Listen = "127.0.0.1:18446", IdentityCaPassword = "other", ServerCertificatePassword = "server-pass" };
        var ca = File.ReadAllBytes(CaPath);
        Assert.Equal(1, RunIdentity(["--init-identity"], wrong, Dedicated));
        Assert.Equal(ca, File.ReadAllBytes(CaPath));
    }

    [Fact]
    public void A_ca_without_its_server_certificate_is_refused_and_nothing_is_written()
    {
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        var ca = File.ReadAllBytes(CaPath);
        File.Delete(ServerPath);

        Assert.Equal(1, RunIdentity(["--init-identity"], Loopback(), Dedicated));

        Assert.Equal(ca, File.ReadAllBytes(CaPath));
        Assert.False(File.Exists(ServerPath));
    }

    [Fact]
    public void A_server_certificate_without_its_ca_is_refused_and_no_new_ca_is_made()
    {
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        var server = File.ReadAllBytes(ServerPath);
        File.Delete(CaPath);

        Assert.Equal(1, RunIdentity(["--init-identity"], Loopback(), Dedicated));

        Assert.False(File.Exists(CaPath));
        Assert.Equal(server, File.ReadAllBytes(ServerPath));
    }

    [Fact]
    public void A_file_that_is_not_pkcs12_is_refused()
    {
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        File.WriteAllBytes(CaPath, [1, 2, 3, 4]);

        Assert.Equal(1, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(CaPath));
    }

    [Fact]
    public void A_server_certificate_from_another_ca_is_refused()
    {
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        var now = DateTimeOffset.UtcNow;
        using var otherCa = SignerIdentity.CreateIdentityCa(now);
        using var foreign = SignerIdentity.IssueServerCertificate(otherCa, "127.0.0.1", now);
        Pkcs12Files.Write(ServerPath, foreign, [otherCa], string.Empty);
        var server = File.ReadAllBytes(ServerPath);

        Assert.Equal(1, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        Assert.Equal(server, File.ReadAllBytes(ServerPath));
    }

    [Fact]
    public void An_expired_identity_is_refused()
    {
        var past = DateTimeOffset.UtcNow.AddYears(-11);
        using var ca = SignerIdentity.CreateIdentityCa(past);
        using var server = SignerIdentity.IssueServerCertificate(ca, "127.0.0.1", past);
        Pkcs12Files.Write(CaPath, ca, null, string.Empty);
        Pkcs12Files.Write(ServerPath, server, [ca], string.Empty);

        Assert.Equal(1, RunIdentity(["--init-identity"], Loopback(), Dedicated));
    }

    [Fact]
    public void A_server_certificate_for_another_host_is_refused()
    {
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        var server = File.ReadAllBytes(ServerPath);

        Assert.Equal(1, RunIdentity(["--init-identity", "--host", "signer.example"], Loopback(), Dedicated));
        Assert.Equal(1, RunIdentity(["--init-identity"], new SignerConfig { Listen = "10.0.0.5:8446" }, Dedicated));
        Assert.Equal(server, File.ReadAllBytes(ServerPath));

        // A Listen on every interface and no --host names nothing to compare with.
        Assert.Equal(0, RunIdentity(["--init-identity"], new SignerConfig { Listen = "0.0.0.0:8446" }, Dedicated));
    }

    [Fact]
    public void A_dns_name_given_with_host_is_matched_on_the_next_run()
    {
        Assert.Equal(0, RunIdentity(["--init-identity", "--host", "signer.example"], Loopback(), Dedicated));
        Assert.Equal(0, RunIdentity(["--init-identity", "--host", "SIGNER.example"], Loopback(), Dedicated));
    }

    [Fact]
    public void Force_still_replaces_the_identity()
    {
        Assert.Equal(0, RunIdentity(["--init-identity"], Loopback(), Dedicated));
        var ca = File.ReadAllBytes(CaPath);

        Assert.Equal(0, RunIdentity(["--init-identity", "--force"], Loopback(), Dedicated));
        Assert.NotEqual(ca, File.ReadAllBytes(CaPath));

        // And repairs a partial identity, which is what it is for.
        File.Delete(ServerPath);
        Assert.Equal(0, RunIdentity(["--init-identity", "--force"], Loopback(), Dedicated));
        Assert.True(File.Exists(ServerPath));
    }

    /// <summary>Runs <c>SignerIdentityCommands.Run</c> from the built API and returns its exit code.</summary>
    internal static int RunIdentity(string[] args, SignerConfig signer, SignerPaths paths)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Startup.SignerIdentityCommands");
        var run = type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static, [typeof(IReadOnlyList<string>), typeof(SignerConfig), typeof(SignerPaths)])!;
        try
        {
            return (int)run.Invoke(null, [args, signer, paths])!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }
}
