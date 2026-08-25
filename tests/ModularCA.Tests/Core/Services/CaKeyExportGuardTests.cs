using ModularCA.Shared.Models;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins the rule that a CA private key is never exportable over the API.
/// <para>
/// <c>POST /api/v1/admin/certificates/{serial}/export</c> with <c>format=pem-key</c> returns the
/// certificate AND its decrypted private key. It carried the <c>CaOperator</c> policy and a
/// step-up MFA check and nothing else — no CA-certificate block and no per-object ownership
/// check, both of which every sibling on that controller applies.
/// </para>
/// <para>
/// Step-up MFA is not a substitute for either. It re-authenticates the caller; it does not
/// authorize the object, because the caller names its own <c>targetId</c> when minting the
/// token. And the CA-scoped policy resolves fine for a CA's own serial, since bootstrap writes
/// the root and System Signing CA rows with a non-null SigningProfileId. So any holder of
/// <c>cert.revoke</c> on the root CA could ask for the root CA's serial and receive the root
/// private key — and asking for the System Signing CA's serial returned the key that wraps
/// every stored end-entity private key in the database.
/// </para>
/// </summary>
public class CaKeyExportGuardTests
{
    /// <summary>
    /// The predicate the export endpoint applies before doing any work. Kept here in the same
    /// shape as the controller so the intent is testable without a controller harness.
    /// </summary>
    private static bool IsExportForbidden(CertificateInfoModel cert) =>
        cert.IsCA || (cert.SubjectDN?.Contains("System Signing CA", StringComparison.OrdinalIgnoreCase) ?? false);

    private static CertificateInfoModel Cert(bool isCa, string subject) =>
        new() { IsCA = isCa, SubjectDN = subject, SerialNumber = "AA11" };

    [Fact]
    public void A_ca_certificate_is_never_exportable()
    {
        Assert.True(IsExportForbidden(Cert(isCa: true, "CN=Acme Root CA,O=Acme")));
    }

    [Fact]
    public void The_system_signing_ca_is_never_exportable_even_if_the_ca_flag_is_unset()
    {
        // Belt and braces: this row wraps every stored private key, so it is refused on the
        // subject as well as on IsCA. A single mis-set flag must not open it.
        Assert.True(IsExportForbidden(Cert(isCa: false, "CN=System Signing CA")));
        Assert.True(IsExportForbidden(Cert(isCa: false, "cn=system signing ca,o=modularca")));
    }

    [Fact]
    public void An_ordinary_end_entity_certificate_is_still_exportable()
    {
        // The guard must not break the feature it protects: a normal leaf, subject to the
        // ownership check the endpoint now also applies, is exactly what this endpoint is for.
        Assert.False(IsExportForbidden(Cert(isCa: false, "CN=www.example.com,O=Acme")));
    }

    [Fact]
    public void A_certificate_with_no_subject_is_judged_on_the_ca_flag_alone()
    {
        // Null-subject rows must not throw their way past the guard.
        Assert.False(IsExportForbidden(new CertificateInfoModel { IsCA = false, SubjectDN = null! }));
        Assert.True(IsExportForbidden(new CertificateInfoModel { IsCA = true, SubjectDN = null! }));
    }
}
