using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Services;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// When the node issues its own Web TLS certificate at start. No backup carries the certificate's
/// key file, so a restored node has either none or the one of the installation it replaced.
/// </summary>
public sealed class WebTlsProvisioningNeedTests : IDisposable
{
    private readonly string _base = Path.Combine(Path.GetTempPath(), $"mca-webtls-{Guid.NewGuid():N}");
    private string PfxPath => Path.Combine(_base, "config", "api-tls.pfx");

    public WebTlsProvisioningNeedTests() => Directory.CreateDirectory(Path.Combine(_base, "config"));

    public void Dispose()
    {
        try { Directory.Delete(_base, recursive: true); } catch (IOException) { }
    }

    private void WritePfx(string password)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        File.WriteAllBytes(PfxPath, certificate.Export(X509ContentType.Pfx, password));
    }

    [Fact]
    public void A_first_start_issues_the_certificate()
    {
        Assert.True(WebTlsProvisioningService.NeedsProvisioning(new HttpsConfig { Mode = "Pending" }, _base));
    }

    [Fact]
    public void A_self_issued_certificate_that_opens_is_kept()
    {
        WritePfx("right");

        Assert.False(WebTlsProvisioningService.NeedsProvisioning(new HttpsConfig { Mode = "SelfIssued", CertificatePassword = "right" }, _base));
    }

    [Fact]
    public void A_restore_onto_a_new_host_leaves_no_file_and_a_new_certificate_is_issued()
    {
        Assert.True(WebTlsProvisioningService.NeedsProvisioning(new HttpsConfig { Mode = "SelfIssued", CertificatePassword = "right" }, _base));
    }

    [Fact]
    public void A_file_left_by_the_installation_a_restore_replaced_does_not_open_and_a_new_certificate_is_issued()
    {
        WritePfx("the replaced installation's password");

        Assert.True(WebTlsProvisioningService.NeedsProvisioning(new HttpsConfig { Mode = "SelfIssued", CertificatePassword = "right" }, _base));
    }

    [Fact]
    public void An_operators_own_certificate_is_never_replaced()
    {
        Assert.False(WebTlsProvisioningService.NeedsProvisioning(new HttpsConfig { Mode = "Custom", CertificatePath = "config/own.pfx" }, _base));
    }
}
