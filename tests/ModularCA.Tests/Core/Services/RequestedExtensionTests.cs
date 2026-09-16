using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Extensions a request asks for land on the certificate exactly as given, and never on an OID
/// the profiles govern. The Windows Certificate Template Information extension is the reason
/// this exists: without it autoenrollment re-enrolls on every pulse.
/// </summary>
public class RequestedExtensionTests
{
    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => throw new NotSupportedException();
        public Task<ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ResolvedCaServiceUrls([], [], []));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }

    private static readonly TestCaMaterial Issuer = TestCaMaterial.CreateCa("CN=Requested Extension Test CA, O=ModularCA");
    private const string TemplateInfoOid = "1.3.6.1.4.1.311.21.7";

    private static Task<X509Certificate> BuildAsync(params RequestedExtension[] requested)
    {
        var builder = new CertificateBuilderService(new NoServiceUrls(), NullLogger<CertificateBuilderService>.Instance);
        return builder.BuildCertificateAsync(
            serialNumber: BigInteger.ValueOf(7),
            issuerCert: Issuer.Certificate,
            caKeyHandle: new SoftwarePrivateKeyHandle(Issuer.KeyPair.Private),
            subjectDn: new X509Name("CN=ws-042.lab.test"),
            subjectPublicKey: Issuer.KeyPair.Public,
            validFrom: new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc),
            validTo: new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc),
            standardOids: new List<string> { "digitalSignature" },
            extendedOids: new List<string> { "1.3.6.1.5.5.7.3.2" },
            subjectAlternativeNames: null,
            caCertificateId: Guid.NewGuid(),
            signingProfile: null,
            additionalExtensions: requested.Length == 0 ? null : requested);
    }

    private static RequestedExtension TemplateInfo(string templateOid, int major, int minor, bool critical = false)
        => new(TemplateInfoOid, critical,
            Convert.ToBase64String(new DerSequence(new DerObjectIdentifier(templateOid), new DerInteger(major), new DerInteger(minor)).GetDerEncoded()));

    [Fact]
    public async Task A_requested_extension_is_stamped_with_its_oid_criticality_and_value()
    {
        var cert = await BuildAsync(TemplateInfo("2.25.1.2.3.4", 100, 0));

        var value = cert.GetExtensionValue(new DerObjectIdentifier(TemplateInfoOid));
        Assert.NotNull(value);
        var seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(value.GetOctets()));
        Assert.Equal("2.25.1.2.3.4", DerObjectIdentifier.GetInstance(seq[0]).Id);
        Assert.Equal(100, DerInteger.GetInstance(seq[1]).IntValueExact);
        Assert.Equal(0, DerInteger.GetInstance(seq[2]).IntValueExact);
        Assert.DoesNotContain(TemplateInfoOid, cert.GetCriticalExtensionOids().Cast<string>());
        Assert.Contains(TemplateInfoOid, cert.GetNonCriticalExtensionOids().Cast<string>());

        // Criticality is the request's to choose.
        var critical = await BuildAsync(TemplateInfo("2.25.1.2.3.4", 100, 0, critical: true));
        Assert.Contains(TemplateInfoOid, critical.GetCriticalExtensionOids().Cast<string>());

        // No request, no extension; the profile-driven ones are untouched.
        var plain = await BuildAsync();
        Assert.Null(plain.GetExtensionValue(new DerObjectIdentifier(TemplateInfoOid)));
        Assert.NotNull(plain.GetExtensionValue(X509Extensions.KeyUsage));
    }

    [Theory]
    [InlineData("2.5.29.15")]           // key usage
    [InlineData("2.5.29.37")]           // extended key usage
    [InlineData("2.5.29.17")]           // subject alternative name
    [InlineData("2.5.29.19")]           // basic constraints
    [InlineData("2.5.29.31")]           // CRL distribution points
    [InlineData("1.3.6.1.5.5.7.1.1")]   // authority information access
    [InlineData("1.3.6.1.5.5.7.48.1.5")] // OCSP no-check, the builder's own
    public async Task An_oid_the_profiles_govern_is_refused(string oid)
    {
        var ex = await Assert.ThrowsAsync<InvalidRequestException>(() =>
            BuildAsync(new RequestedExtension(oid, false, Convert.ToBase64String(DerNull.Instance.GetDerEncoded()))));
        Assert.Contains("decided by the certificate profile", ex.Message);
    }

    [Fact]
    public async Task Malformed_requests_are_refused_not_stamped()
    {
        var value = Convert.ToBase64String(DerNull.Instance.GetDerEncoded());
        await Assert.ThrowsAsync<InvalidRequestException>(() => BuildAsync(new RequestedExtension("not.an.oid", false, value)));
        await Assert.ThrowsAsync<InvalidRequestException>(() => BuildAsync(new RequestedExtension("1.2.3.4", false, Convert.ToBase64String(new byte[] { 0x30, 0x80, 0x01 }))));
        await Assert.ThrowsAsync<InvalidRequestException>(() => BuildAsync(
            new RequestedExtension("1.2.3.4", false, value), new RequestedExtension("1.2.3.4", true, value)));
    }

    [Fact]
    public void The_json_form_round_trips_and_is_null_when_empty()
    {
        var one = TemplateInfo("2.25.9", 7, 3);
        var json = RequestedExtension.ToJson([one]);
        Assert.NotNull(json);
        Assert.Equal([one], RequestedExtension.FromJson(json));
        Assert.Equal(new DerSequence(new DerObjectIdentifier("2.25.9"), new DerInteger(7), new DerInteger(3)).GetDerEncoded(), one.Value);

        Assert.Null(RequestedExtension.ToJson(null));
        Assert.Null(RequestedExtension.ToJson([]));
        Assert.Empty(RequestedExtension.FromJson(null));
        Assert.Empty(RequestedExtension.FromJson("  "));
    }
}
