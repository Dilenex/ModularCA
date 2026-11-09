using ModularCA.Core.Services.Est;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services.Est;

/// <summary>
/// The mTLS branch of EST holds every SAN a CSR asks for to a SAN the client certificate holds.
/// The values used to be compared with their types stripped, and the certificate's common name
/// stood in for any type, so a certificate could vouch for a UPN or an IP address it never held
/// by having the same string as an email address or a common name.
/// </summary>
public class EstSanBindingTests
{
    /// <summary>The raw SAN extension value carrying the given names.</summary>
    private static byte[] San(params GeneralName[] names) => new GeneralNames(names).GetEncoded();

    /// <summary>A SAN as the CSR parser renders it.</summary>
    private static string Csr(GeneralName name) => UpnSanEncoding.Describe(name);

    private static bool Held(GeneralName requested, byte[][] certSans, string? commonName)
        => EstService.CsrSansHeldByClient([Csr(requested)], EstService.ClientCertSanCandidates(certSans, commonName));

    [Fact]
    public void A_san_the_certificate_holds_with_the_same_type_is_held()
    {
        var dns = new GeneralName(GeneralName.DnsName, "printer1.example.com");
        Assert.True(Held(dns, [San(dns)], "printer1"));
        Assert.True(Held(new GeneralName(GeneralName.DnsName, "PRINTER1.example.com"), [San(dns)], null));
    }

    [Fact]
    public void An_email_san_does_not_vouch_for_a_upn_of_the_same_string()
    {
        var email = new GeneralName(GeneralName.Rfc822Name, "admin@corp.example");
        Assert.False(Held(UpnSanEncoding.BuildUpnGeneralName("admin@corp.example"), [San(email)], "device"));
        Assert.True(Held(email, [San(email)], "device"));
    }

    [Fact]
    public void A_common_name_vouches_for_nothing_but_its_dns_name()
    {
        Assert.False(Held(UpnSanEncoding.BuildUpnGeneralName("admin@corp.example"), [], "admin@corp.example"));
        Assert.False(Held(new GeneralName(GeneralName.Rfc822Name, "admin@corp.example"), [], "admin@corp.example"));
        Assert.False(Held(new GeneralName(GeneralName.IPAddress, "10.0.0.1"), [], "10.0.0.1"));
    }

    /// <summary>The case clients rely on: a device certificate with no SAN, renewing its host name.</summary>
    [Fact]
    public void A_host_name_common_name_vouches_for_that_dns_name_when_the_certificate_has_no_dns_san()
        => Assert.True(Held(new GeneralName(GeneralName.DnsName, "printer1.example.com"), [], "printer1.example.com"));

    [Fact]
    public void A_common_name_is_not_a_further_dns_name_beside_the_certificates_own_dns_sans()
    {
        var own = San(new GeneralName(GeneralName.DnsName, "printer1.example.com"));
        Assert.False(Held(new GeneralName(GeneralName.DnsName, "ca.example.com"), [own], "ca.example.com"));
    }

    [Fact]
    public void A_csr_with_no_sans_asks_for_nothing()
        => Assert.True(EstService.CsrSansHeldByClient([], []));
}
