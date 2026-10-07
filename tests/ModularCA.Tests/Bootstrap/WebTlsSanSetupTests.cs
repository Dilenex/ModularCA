using ModularCA.Bootstrap;
using ModularCA.Shared.Errors;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The setup Web TLS certificate carries only DNS and IP SANs: the CSR builder that issues it on
/// first start encoded those two and skipped every other entry. Setup now refuses any other entry
/// with a setup error before any work is done, on the wizard and the CLI path.
/// </summary>
public class WebTlsSanSetupTests
{
    [Theory]
    [InlineData("EMAIL:ops@example.com", "type 'EMAIL'")]
    [InlineData("URI:https://ca.example.com", "type 'URI'")]
    [InlineData("UPN:admin@example.com", "type 'UPN'")]
    [InlineData("ca.example.com", "no type")]
    [InlineData("IP:ca.example.com", "not an IP address")]
    [InlineData("DNS:", "no value")]
    public void An_unsupported_web_tls_san_is_refused(string san, string reason)
    {
        var ex = Assert.Throws<InvalidRequestException>(
            () => BootstrapCertCreator.EnsureWebTlsSansSupported(["DNS:ca.example.com", san]));

        Assert.Contains(san.Trim(), ex.Message);
        Assert.Contains(reason, ex.Message);
    }

    [Fact]
    public void Dns_and_ip_sans_are_accepted_and_blank_entries_ignored()
    {
        BootstrapCertCreator.EnsureWebTlsSansSupported(["DNS:ca.example.com", "dns:localhost", "IP:127.0.0.1", "IP:::1", " ", ""]);
        BootstrapCertCreator.EnsureWebTlsSansSupported(null);
    }
}
