using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Services.Cmp;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.X509;
using Xunit;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Pins which certificate a signature-protected CMP request is verified against.
/// </summary>
/// <remarks>
/// The dedicated CMP signer that fixed signature-protected <em>responses</em> also became the
/// first return of the signer resolver, and that value was being reused to verify the incoming
/// request. The signer's subject is "... CMP Signer", not the CA, so a client certificate whose
/// issuer is the CA no longer matched, and every kur was rejected with "Signing certificate was
/// not issued by the CA this request addresses." Verification must use the issuing CA; signing the
/// response uses the delegated signer. Two roles, two certificates.
/// </remarks>
public class CmpVerificationCertTests
{
    private static BcX509Certificate ToBc(X509Certificate2 cert) =>
        new X509CertificateParser().ReadCertificate(cert.RawData);

    [Fact]
    public void With_a_delegated_signer_the_issuing_CA_is_used_not_the_signer()
    {
        using var ca = TestCertificates.CreateCa("CN=Issuing CA");
        using var signer2 = TestCertificates.IssueLeaf(ca, "CN=Issuing CA CMP Signer");
        var caBc = ToBc(ca);
        var signerBc = ToBc(signer2);

        // responseSigner is the delegated signer; signerIssuer is the real CA.
        var chosen = CmpService.SelectRequestVerificationCert(signerBc, caBc);

        Assert.Equal(caBc.SubjectDN.ToString(), chosen.SubjectDN.ToString());
    }

    [Fact]
    public void With_no_delegated_signer_the_response_signer_is_already_the_CA()
    {
        using var ca = TestCertificates.CreateCa("CN=Issuing CA");
        var caBc = ToBc(ca);

        // The CA signs directly: responseSigner is the CA, signerIssuer is null.
        var chosen = CmpService.SelectRequestVerificationCert(caBc, null);

        Assert.Same(caBc, chosen);
    }
}
