using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Services.Est;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Est;

/// <summary>
/// Pins the rule that decides whether an EST client certificate is real.
/// </summary>
/// <remarks>
/// <para>
/// This is the only chain check an EST client certificate gets. <c>EstService</c> reads the
/// certificate's CN and SANs and requires the CSR to match them, but never checks who issued the
/// certificate — it trusts the TLS handshake to have done that. So a permissive answer here is not
/// "slightly weaker transport security": it means an attacker generates a self-signed
/// <c>CN=root-admin</c>, presents it, submits a CSR for <c>CN=root-admin</c>, and every binding
/// check downstream confirms the forgery against itself.
/// </para>
/// <para>
/// The case worth the most attention is <see cref="A_certificate_from_a_non_EST_CA_under_the_same_root_is_refused"/>.
/// Enabling EST on one CA must not enable it on every CA that shares a root, or "EST enabled" stops
/// meaning anything at the transport layer.
/// </para>
/// </remarks>
public class EstClientCertValidatorTests
{
    [Fact]
    public void A_certificate_issued_by_an_EST_enabled_CA_is_accepted()
    {
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var device = TestCertificates.IssueLeaf(estCa, "CN=device-01.example.test");

        Assert.True(EstClientCertValidator.IsIssuedByEstCa(device, [estCa]));
    }

    [Fact]
    public void A_certificate_from_an_unrelated_CA_is_refused()
    {
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var otherCa = TestCertificates.CreateCa("CN=Some Other CA");
        using var stranger = TestCertificates.IssueLeaf(otherCa, "CN=device-01.example.test");

        Assert.False(EstClientCertValidator.IsIssuedByEstCa(stranger, [estCa]));
    }

    [Fact]
    public void A_certificate_from_a_non_EST_CA_under_the_same_root_is_refused()
    {
        // The case a naive implementation gets wrong. Both intermediates chain to the same root,
        // and the root is present as chain material so the EST intermediate's own chain can
        // terminate — so a validator that stops at "the chain built" accepts both. Only one of
        // these CAs has EST enabled, and only its devices may enroll.
        using var root = TestCertificates.CreateCa("CN=Shared Root");
        using var estCa = TestCertificates.IssueIntermediate(root, "CN=EST Issuing CA");
        using var payrollCa = TestCertificates.IssueIntermediate(root, "CN=Payroll Issuing CA");
        using var payrollCert = TestCertificates.IssueLeaf(payrollCa, "CN=device-01.example.test");

        Assert.False(EstClientCertValidator.IsIssuedByEstCa(
            payrollCert, [estCa], [root, payrollCa]));
    }

    [Fact]
    public void Enabling_EST_on_the_root_does_not_admit_a_sibling_intermediates_certificates()
    {
        // The original version accepted the EST CA anywhere in the chain. Enable EST on the root
        // and every subordinate's certificates passed: the login-signing intermediate, the web-TLS
        // intermediate, all of them. RFC 7030 section 4.2.2 says "previously issued by this CA",
        // and "by" is the direct issuer.
        using var root = TestCertificates.CreateCa("CN=Root");
        using var loginCa = TestCertificates.IssueIntermediate(root, "CN=Login CA");
        using var loginCert = TestCertificates.IssueLeaf(loginCa, "CN=alice");

        Assert.False(EstClientCertValidator.IsIssuedByEstCa(loginCert, [root], [loginCa]));
    }

    [Fact]
    public void A_certificate_issued_directly_by_the_EST_root_is_accepted()
    {
        using var root = TestCertificates.CreateCa("CN=Root");
        using var device = TestCertificates.IssueLeaf(root, "CN=device-01.example.test");

        Assert.True(EstClientCertValidator.IsIssuedByEstCa(device, [root]));
    }

    [Fact]
    public void A_certificate_whose_EKU_permits_only_server_auth_is_refused()
    {
        // A TLS server certificate obtained via ACME from the same CA is not a client identity.
        // Without the EKU policy, a tenant holding DNS:host.example presented it and enrolled an
        // EST-profile certificate for the same name.
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var serverCert = TestCertificates.IssueLeaf(estCa, "CN=host.example.test",
            ekuOids: ["1.3.6.1.5.5.7.3.1"]);

        Assert.False(EstClientCertValidator.IsIssuedByEstCa(serverCert, [estCa]));
    }

    [Fact]
    public void A_certificate_whose_EKU_includes_client_auth_is_accepted()
    {
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var device = TestCertificates.IssueLeaf(estCa, "CN=device-01.example.test",
            ekuOids: ["1.3.6.1.5.5.7.3.1", EstClientCertValidator.ClientAuthEkuOid]);

        Assert.True(EstClientCertValidator.IsIssuedByEstCa(device, [estCa]));
    }

    [Fact]
    public void A_certificate_with_no_EKU_extension_is_accepted()
    {
        // RFC 5280 section 4.2.1.12: no EKU extension means unrestricted. Device profiles that
        // omit the extension must keep working, or the EKU check would be a silent fleet outage.
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var device = TestCertificates.IssueLeaf(estCa, "CN=device-01.example.test", ekuOids: null);

        Assert.True(EstClientCertValidator.IsIssuedByEstCa(device, [estCa]));
    }

    [Fact]
    public void A_certificate_under_an_EST_enabled_intermediate_is_accepted()
    {
        // The realistic deployment: EST is enabled on an issuing CA, not on the offline root.
        using var root = TestCertificates.CreateCa("CN=Shared Root");
        using var estCa = TestCertificates.IssueIntermediate(root, "CN=EST Issuing CA");
        using var device = TestCertificates.IssueLeaf(estCa, "CN=device-01.example.test");

        Assert.True(EstClientCertValidator.IsIssuedByEstCa(device, [estCa], [root]));
    }

    [Fact]
    public void A_self_signed_certificate_is_refused()
    {
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var selfSigned = TestCertificates.CreateCa("CN=root-admin");

        // Anyone can make this in one command. If it were accepted, EstService's CN binding would
        // then happily issue a real certificate for whatever name it claims.
        Assert.False(EstClientCertValidator.IsIssuedByEstCa(selfSigned, [estCa]));
    }

    [Fact]
    public void A_certificate_that_only_names_the_CA_as_its_issuer_is_refused()
    {
        // The Issuer field is text in a certificate the attacker generates and signs themselves.
        // Any check that compares issuer DNs as strings accepts this.
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var forged = TestCertificates.ForgedIssuer(estCa, "CN=device-01.example.test");

        Assert.False(EstClientCertValidator.IsIssuedByEstCa(forged, [estCa]));
    }

    [Fact]
    public void An_empty_anchor_set_refuses_everything()
    {
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var device = TestCertificates.IssueLeaf(estCa, "CN=device-01.example.test");

        // Fails closed. An empty set means "no CA has EST enabled", and the tempting reading —
        // nothing to check against, so let it through — makes the transport gate decorative
        // exactly when it is least supervised.
        Assert.False(EstClientCertValidator.IsIssuedByEstCa(device, []));
    }

    [Fact]
    public void A_null_certificate_is_refused()
    {
        using var estCa = TestCertificates.CreateCa("CN=EST CA");

        // The handshake callback decides separately that an absent client certificate is allowed
        // through for the /cacerts bootstrap. That is a policy choice about anonymity and it lives
        // there, where the RFC reason is stated — this function only answers "was this issued by an
        // EST CA", and null was not.
        Assert.False(EstClientCertValidator.IsIssuedByEstCa(null, [estCa]));
    }

    [Fact]
    public void The_CA_certificate_itself_is_accepted_by_its_own_anchor()
    {
        // Degenerate but worth pinning: the anchor appears in its own chain, so the thumbprint
        // check must look at every element rather than only the elements above the leaf.
        using var estCa = TestCertificates.CreateCa("CN=EST CA");

        Assert.True(EstClientCertValidator.IsIssuedByEstCa(estCa, [estCa]));
    }

    [Fact]
    public void Any_one_of_several_EST_enabled_CAs_authorises_a_certificate()
    {
        using var estCaA = TestCertificates.CreateCa("CN=EST CA A");
        using var estCaB = TestCertificates.CreateCa("CN=EST CA B");
        using var device = TestCertificates.IssueLeaf(estCaB, "CN=device-01.example.test");

        Assert.True(EstClientCertValidator.IsIssuedByEstCa(device, [estCaA, estCaB]));
    }

    [Fact]
    public void An_expired_certificate_is_refused()
    {
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var expired = TestCertificates.IssueExpiredLeaf(estCa, "CN=device-01.example.test");

        // Revocation is deliberately lenient here (Offline, unknown tolerated) because a cold CRL
        // cache must not take enrollment down. Expiry is not — it needs no external state to
        // decide, so there is no reason to let it slide.
        Assert.False(EstClientCertValidator.IsIssuedByEstCa(expired, [estCa]));
    }
}
