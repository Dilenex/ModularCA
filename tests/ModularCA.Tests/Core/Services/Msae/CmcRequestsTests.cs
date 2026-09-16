using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Services.Msae;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins how a Windows client's CMC request is unwrapped: the PKCS#10 comes out, the wrapper
/// must be signed by the key being certified, and anything that is not that shape is refused.
/// </summary>
public class CmcRequestsTests
{
    /// <summary>
    /// A real request from Get-Certificate on Windows 11 (build 22631) against a stand-in policy
    /// server: CMS SignedData (v3, SHA-1, signer by subject key identifier, no certificates) over a
    /// PKIData with one tagged certification request. The PKCS#10 inside has an empty subject and
    /// carries key usage, EKU, application policies, template information and a key identifier.
    /// </summary>
    public const string WindowsCmcRequestBase64 =
        "MIIEzwYJKoZIhvcNAQcCoIIEwDCCBLwCAQMxCzAJBgUrDgMCGgUAMIIDKQYIKwYBBQUHDAKgggMbBIIDFzCCAxMwADCCAwmgggMFAgEBMIIC/jCCAeYCAQAw" +
        "ADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM9daDWPrRhWBxhSY31aWvNqQvuR/nu9ldDixETTPjZGoER7qteUwPH1g5ydU607TJL6006WFz58" +
        "JNhl5/3ueiIGao1f+aMFr4T0eZX0f7oaa3cZJHtUU7ttNJu24dMbMCeIHCcvb0xo0d662aK5PthBGHWt2ljw/ojf5ztI+12FmKULj86dCkMRGeYn62+KvU5/" +
        "Js4PTzMkl5MaF+ikUzpZSRpt3Th98/vDLPhDBIq8VlD9xYotukDQgMoN5DDVWxUSn/gW3EEMs0zml/gRVfuIvC4Omrz+3egtwaQlWx9MvAeYcIr28zM+Ms8f" +
        "ikdQw3jSllFKqkQA5E+FLe5JF+UCAwEAAaCBuDCBtQYJKoZIhvcNAQkOMYGnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB" +
        "BQUHAwEwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDAjAKBggrBgEFBQcDATArBgkrBgEEAYI3FQcEHjAcBhRpg4aDnZbelZqgxaPX6eXOgsOYAgIBZAIB" +
        "ADAdBgNVHQ4EFgQUFJjSNThPuke8eP+kfBO9wJUDQdowDQYJKoZIhvcNAQEFBQADggEBADkMVVMy1CvVF3LqcMUzzewYu1vxC53TefCTJIPOTW1p99Phpn6V" +
        "ub1UpmZY+PubAHDpOKEWejOYOKxlFQBwczy8HiGmYI21O/dSy3mhfB+raufVsmwZqhni894Zrsyzz/JI/eANujWPO784cgPRKN84Sv/1KU12TS2KELjHQdsr" +
        "4FGUoEhblnVpUiB+lqlqdNaKyc8KbhXHBa9ZgSv8uAU87W6/SsidVXs1peC/pv+zyY9/54h2oMBhXP5+uolWVGGwIT6CizBSvezqG/hI8x3a1JRzlfCN8CAA" +
        "+J3+bAT/ht5RqO/kR5MYeFgeEXtoOXsIMSKK3CJyGMS9NvrBucowADAAMYIBezCCAXcCAQOAFBSY0jU4T7pHvHj/pHwTvcCVA0HaMAkGBSsOAwIaBQCgPjAX" +
        "BgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwIwYJKoZIhvcNAQkEMRYEFIUe1oNFPJgGjeyAtDshy7qnA/5JMA0GCSqGSIb3DQEBAQUABIIBAImr7hoTYa5OJG1j" +
        "FnT78UiAms3wgOPJ5EvxPAgDivGZl+PUCc8QAMN2cuUBjFzUP76nVD3XE8O4NH5jKtkYxrQiAh7+ehZQytbJ20w655Hvz1lNoLmZI1NxwwlYPkzzU8CiloKU" +
        "9/789m/y1KdonYJHYkppWIR0rgiF1sVdTZ9r3+uufQ6TEE90LX0RiC+lObTW81pyMlsv1Xl62BgxLdBX48O5nlU1faCvl8+NXdAWALj6zd4Oeou0SwpfOtVW" +
        "6ou0fSZ7mDU/F0aHKP2I8bmBTc6BJQ5L6L2KaegU8ZyoE4AUqbkcgcgD7o0mXGKky42XfERejS9oivnfVkruOWY=";

    private static (byte[] Pkcs10Der, AsymmetricCipherKeyPair Key) SamplePkcs10(string cn = "CN=device-01.example.test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(cn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var der = req.CreateSigningRequest();
        var key = DotNetUtilities.GetRsaKeyPair(rsa);
        return (der, key);
    }

    /// <summary>
    /// Builds a CMC request the way Windows does: PKIData with one tcr, signed by
    /// <paramref name="signingKey"/> under a key identifier. <paramref name="requestTag"/> is the
    /// TaggedRequest choice: 0 for a PKCS#10 (tcr), 1 for a CRMF request (crm).
    /// </summary>
    private static byte[] BuildCmc(byte[] pkcs10Der, AsymmetricKeyParameter signingKey, bool includeRequest = true, int requestTag = 0)
    {
        var tcr = new DerSequence(new DerInteger(1), Asn1Object.FromByteArray(pkcs10Der));
        var requests = includeRequest ? new DerSequence(new DerTaggedObject(false, requestTag, tcr)) : new DerSequence();
        var pkiData = new DerSequence(new DerSequence(), requests, new DerSequence(), new DerSequence());

        var generator = new CmsSignedDataGenerator();
        generator.AddSigner(signingKey, [1, 2, 3, 4], CmsSignedDataGenerator.DigestSha256);
        return generator.Generate(CmcRequests.PkiDataOid, new CmsProcessableByteArray(pkiData.GetDerEncoded()), true).GetEncoded();
    }

    /// <summary>
    /// A renewal the way the autoenrollment engine builds one: the PKCS#10 carries the existing
    /// certificate in szOID_RENEWAL_CERTIFICATE, and the wrapper is signed by the new key (by key
    /// identifier) and, when <paramref name="signWithOld"/>, by the existing certificate's key
    /// (by issuer and serial).
    /// </summary>
    private static (byte[] Cmc, X509Certificate2 Old) BuildRenewal(bool signWithOld, byte[]? wrongOldKeySigner = null)
    {
        using var oldRsa = RSA.Create(2048);
        var oldReq = new CertificateRequest("CN=ws-042.lab.test", oldRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var old = oldReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        using var newRsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ws-042.lab.test", newRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.OtherRequestAttributes.Add(new AsnEncodedData(new Oid(CmcRequests.RenewalCertificateOid), old.RawData));
        var pkcs10 = req.CreateSigningRequest();

        var tcr = new DerSequence(new DerInteger(1), Asn1Object.FromByteArray(pkcs10));
        var pkiData = new DerSequence(new DerSequence(), new DerSequence(new DerTaggedObject(false, 0, tcr)), new DerSequence(), new DerSequence());
        var generator = new CmsSignedDataGenerator();
        generator.AddSigner(DotNetUtilities.GetRsaKeyPair(newRsa).Private, [1, 2, 3, 4], CmsSignedDataGenerator.DigestSha256);
        if (signWithOld)
        {
            var oldBc = DotNetUtilities.FromX509Certificate(old);
            var signingKey = wrongOldKeySigner == null
                ? DotNetUtilities.GetRsaKeyPair(oldRsa).Private
                : DotNetUtilities.GetRsaKeyPair(RSA.Create(2048)).Private;   // claims the old cert, signs with another key
            generator.AddSigner(signingKey, oldBc, CmsSignedDataGenerator.DigestSha256);
        }
        var cmc = generator.Generate(CmcRequests.PkiDataOid, new CmsProcessableByteArray(pkiData.GetDerEncoded()), true).GetEncoded();
        return (cmc, old);
    }

    [Fact]
    public void A_renewal_names_the_old_certificate_and_is_signed_by_it()
    {
        var (cmc, old) = BuildRenewal(signWithOld: true);

        var unwrapped = CmcRequests.Unwrap(cmc);
        Assert.NotNull(unwrapped.Renewal);
        Assert.True(unwrapped.Renewal!.SignedByOldCertificate);
        Assert.Equal(old.RawData, unwrapped.Renewal.OldCertificateDer);
        Assert.Equal(old.SerialNumber, unwrapped.Renewal.Certificate.SerialNumber.ToString(16).ToUpperInvariant().PadLeft(old.SerialNumber.Length, '0'));

        // The PKCS#10 still comes out, and its proof of possession by the new key still held.
        Assert.NotNull(new Pkcs10CertificationRequest(unwrapped.Pkcs10Der).GetPublicKey());
    }

    [Fact]
    public void A_renewal_attribute_without_the_old_certificates_signature_is_reported_not_trusted()
    {
        // The old certificate is named but did not sign: a stranger asking for someone's subject.
        var (unsigned, _) = BuildRenewal(signWithOld: false);
        var a = CmcRequests.Unwrap(unsigned);
        Assert.NotNull(a.Renewal);
        Assert.False(a.Renewal!.SignedByOldCertificate);

        // A signer that claims the old certificate's issuer and serial but signs with another key.
        var (forged, _) = BuildRenewal(signWithOld: true, wrongOldKeySigner: [1]);
        var b = CmcRequests.Unwrap(forged);
        Assert.NotNull(b.Renewal);
        Assert.False(b.Renewal!.SignedByOldCertificate);

        // A first enrollment carries no renewal at all.
        Assert.Null(CmcRequests.Unwrap(Convert.FromBase64String(WindowsCmcRequestBase64)).Renewal);
    }


    [Fact]
    public void The_real_windows_renewal_request_is_recognised_as_signed_by_the_old_certificate()
    {
        // certreq -new with RenewalCert on Windows 11 against a LabShort certificate from the lab
        // CA: CMC over a PKCS#10 with an empty subject and szOID_RENEWAL_CERTIFICATE, two signers.
        var path = Path.Combine(AppContext.BaseDirectory, "Core", "Services", "Msae", "Fixtures", "windows-renewal-cmc.b64");
        var cmc = Convert.FromBase64String(File.ReadAllText(path).Trim());

        var unwrapped = CmcRequests.Unwrap(cmc);
        Assert.NotNull(unwrapped.Renewal);
        Assert.True(unwrapped.Renewal!.SignedByOldCertificate);
        Assert.Equal("CN=desktop-kecnk6q.lab.msae.test", unwrapped.Renewal.Certificate.SubjectDN.ToString());
        Assert.Equal("2.25.1519959719.1205029362.460501268.1492120492", MsaeCsrTemplate.ReadTemplateOid(unwrapped.Renewal.Certificate));
        Assert.Equal("", new Pkcs10CertificationRequest(unwrapped.Pkcs10Der).GetCertificationRequestInfo().Subject.ToString());
    }

    [Fact]
    public void The_real_windows_request_unwraps_and_its_proof_of_possession_verifies()
    {
        var pkcs10 = CmcRequests.UnwrapPkcs10(Convert.FromBase64String(WindowsCmcRequestBase64));
        var csr = CertificateRequest.LoadSigningRequest(pkcs10, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        Assert.Equal("", csr.SubjectName.Name);
        Assert.Equal(2048, csr.PublicKey.GetRSAPublicKey()!.KeySize);
        Assert.Contains(csr.CertificateExtensions, e => e.Oid?.Value == MsaeCsrTemplate.TemplateInfoOid);
    }

    [Fact]
    public void A_request_signed_with_the_certified_key_unwraps()
    {
        var (der, key) = SamplePkcs10();
        var unwrapped = CmcRequests.UnwrapPkcs10(BuildCmc(der, key.Private));
        Assert.Equal(der, unwrapped);
    }

    [Fact]
    public void A_wrapper_signed_by_a_different_key_is_refused()
    {
        // Possession of the certified key is the point of the wrapper signature. A wrapper signed
        // by some other key is a renewal (not supported here) or a substitution; either way the
        // PKCS#10 inside must not be issued on the strength of this message.
        var (der, _) = SamplePkcs10();
        var (_, otherKey) = SamplePkcs10("CN=someone-else");
        var ex = Assert.Throws<WstepMessages.WstepParseException>(() => CmcRequests.UnwrapPkcs10(BuildCmc(der, otherKey.Private)));
        Assert.Contains("proof of possession", ex.Message);
    }

    [Fact]
    public void A_pkidata_without_a_certification_request_is_refused()
    {
        var (der, key) = SamplePkcs10();
        var ex = Assert.Throws<WstepMessages.WstepParseException>(() => CmcRequests.UnwrapPkcs10(BuildCmc(der, key.Private, includeRequest: false)));
        Assert.Contains("no PKCS#10", ex.Message);
    }

    [Fact]
    public void A_request_of_another_kind_is_not_mistaken_for_a_pkcs10()
    {
        // TaggedRequest is a CHOICE; only [0] is a certification request. A CRMF request under
        // [1] happens to be a SEQUENCE too, and reading it as a tcr would hand the issuer garbage.
        var (der, key) = SamplePkcs10();
        var ex = Assert.Throws<WstepMessages.WstepParseException>(() => CmcRequests.UnwrapPkcs10(BuildCmc(der, key.Private, requestTag: 1)));
        Assert.Contains("no PKCS#10", ex.Message);
    }

    [Fact]
    public void Signed_data_over_something_other_than_pkidata_is_refused()
    {
        var (der, key) = SamplePkcs10();
        var generator = new CmsSignedDataGenerator();
        generator.AddSigner(key.Private, [1, 2, 3, 4], CmsSignedDataGenerator.DigestSha256);
        var plainData = generator.Generate(new CmsProcessableByteArray(der), true).GetEncoded();
        var ex = Assert.Throws<WstepMessages.WstepParseException>(() => CmcRequests.UnwrapPkcs10(plainData));
        Assert.Contains("PKIData", ex.Message);
    }

    [Fact]
    public void Bytes_that_are_not_cms_are_refused()
    {
        Assert.Throws<WstepMessages.WstepParseException>(() => CmcRequests.UnwrapPkcs10([0x30, 0x03, 0x02, 0x01, 0x00]));
        Assert.Throws<WstepMessages.WstepParseException>(() => CmcRequests.UnwrapPkcs10([1, 2, 3]));
    }
}
