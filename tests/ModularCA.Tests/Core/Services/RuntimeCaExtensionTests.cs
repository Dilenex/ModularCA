using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;
using ModularCA.Shared.Errors;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers the extensions a CA certificate built by <see cref="CertificateBuilderService"/> is
/// allowed to carry.
/// <para>
/// <see cref="ModularCA.Core.Implementations.BouncyCastleCertificateAuthority"/> refused an
/// EKU-bearing or encipherment-bearing CA, and <c>SelfSignedCaExtensionTests</c> covers it — but
/// that builder is used only by bootstrap for the self-signed root. Every CA created through the
/// admin API is an intermediate built here instead, and this path enforced neither rule and had
/// no test of any kind for <c>isCa: true</c>. So the defect that was fixed for roots stayed
/// reachable one level down: any CA-flagged cert profile carrying EKUs produced a non-compliant
/// intermediate, silently, and every leaf beneath it failed EKU-nesting with
/// <c>CERT_E_WRONG_USAGE</c>.
/// </para>
/// <para>
/// Both builders now delegate to <see cref="ModularCA.Shared.Utils.CaCertificateRules"/>; these
/// tests pin the runtime half.
/// </para>
/// </summary>
public class RuntimeCaExtensionTests
{
    /// <summary>
    /// A CA with no public base URL, so CDP/AIA resolution is a no-op and the test exercises
    /// extension policy rather than URL plumbing.
    /// </summary>
    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => throw new NotSupportedException();
        public Task<ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId)
            => Task.FromResult(new ResolvedCaServiceUrls(new List<string>(), new List<string>(), new List<string>()));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }

    /// <summary>
    /// Fails if CDP/AIA resolution is reached. The extension guards must fire before any I/O, so
    /// a test using this stub still sees the guard's exception; if a guard were moved below the
    /// <c>await</c>, it would see this one instead.
    /// </summary>
    private sealed class ExplodingServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => throw new NotSupportedException();
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => throw new NotSupportedException();
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => throw new NotSupportedException();
        public Task<ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId)
            => throw new InvalidOperationException("CDP/AIA resolution reached before the CA extension guards.");
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }

    private static readonly TestCaMaterial Issuer = TestCaMaterial.CreateCa("CN=Runtime Test CA, O=ModularCA");

    private static Task<X509Certificate> BuildAsync(
        List<string> standardOids,
        List<string> extendedOids,
        bool isCa,
        ICaServiceUrlService? urls = null)
    {
        var builder = new CertificateBuilderService(
            urls ?? new NoServiceUrls(),
            NullLogger<CertificateBuilderService>.Instance);

        return builder.BuildCertificateAsync(
            serialNumber: BigInteger.ValueOf(42),
            issuerCert: Issuer.Certificate,
            caKeyHandle: new SoftwarePrivateKeyHandle(Issuer.KeyPair.Private),
            subjectDn: new X509Name("CN=Subject, O=ModularCA"),
            subjectPublicKey: Issuer.KeyPair.Public,
            validFrom: new DateTime(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc),
            validTo: new DateTime(2027, 2, 1, 0, 0, 0, DateTimeKind.Utc),
            standardOids: standardOids,
            extendedOids: extendedOids,
            subjectAlternativeNames: null,
            caCertificateId: Guid.NewGuid(),
            signingProfile: null,
            isCa: isCa);
    }

    private static readonly List<string> CaUsages = new() { "digitalSignature", "keyCertSign", "cRLSign" };
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string SmartCardLogon = "1.3.6.1.4.1.311.20.2.2";

    /// <summary>An EKU on an intermediate constrains everything beneath it, so it is refused.</summary>
    [Fact]
    public async Task A_ca_certificate_with_an_extended_key_usage_is_refused()
    {
        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => BuildAsync(CaUsages, new List<string> { ServerAuth, SmartCardLogon }, isCa: true));

        Assert.Contains("must not carry an ExtendedKeyUsage", ex.Message);
        Assert.Contains(ServerAuth, ex.Message);
    }

    /// <summary>RFC 5480 §3 / RFC 8410 §5: a CA key never enciphers or agrees.</summary>
    [Theory]
    [InlineData("keyEncipherment")]
    [InlineData("dataEncipherment")]
    [InlineData("keyAgreement")]
    public async Task A_ca_certificate_asserting_encipherment_or_agreement_is_refused(string usage)
    {
        var usages = new List<string>(CaUsages) { usage };

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => BuildAsync(usages, new List<string>(), isCa: true));

        Assert.Contains("must not assert keyEncipherment", ex.Message);
    }

    /// <summary>
    /// A CA whose profile omits the mandatory bits still gets them (RFC 5280 §4.2.1.3), rather
    /// than being refused — a profile that simply doesn't restate them is valid.
    /// </summary>
    [Fact]
    public async Task A_ca_certificate_gains_the_mandatory_ca_key_usages()
    {
        var cert = await BuildAsync(new List<string> { "digitalSignature" }, new List<string>(), isCa: true);

        var usage = cert.GetKeyUsage();
        Assert.True(usage[5], "keyCertSign must be set on a CA certificate");
        Assert.True(usage[6], "cRLSign must be set on a CA certificate");
        Assert.True(usage[0], "the profile's own digitalSignature must survive");
    }

    /// <summary>The refusals are CA-only: a leaf may carry any of it.</summary>
    [Fact]
    public async Task A_leaf_certificate_may_carry_extended_key_usages_and_encipherment()
    {
        var cert = await BuildAsync(
            new List<string> { "digitalSignature", "keyEncipherment" },
            new List<string> { ServerAuth, SmartCardLogon },
            isCa: false);

        var ekus = cert.GetExtendedKeyUsage();
        Assert.Contains(ServerAuth, ekus.Cast<object>().Select(o => o.ToString()));
        Assert.Contains(SmartCardLogon, ekus.Cast<object>().Select(o => o.ToString()));
        Assert.True(cert.GetKeyUsage()[2], "keyEncipherment must survive on a leaf");
    }

    /// <summary>A leaf must not have the CA bits forced on.</summary>
    [Fact]
    public async Task A_leaf_certificate_does_not_gain_the_ca_key_usages()
    {
        var cert = await BuildAsync(new List<string> { "digitalSignature" }, new List<string>(), isCa: false);

        var usage = cert.GetKeyUsage();
        Assert.False(usage[5], "keyCertSign must not be added to a leaf");
        Assert.False(usage[6], "cRLSign must not be added to a leaf");
    }

    /// <summary>
    /// The guards must fire before anything is signed or fetched. With a URL resolver that
    /// throws, a correctly ordered guard still produces the EKU refusal.
    /// </summary>
    [Fact]
    public async Task The_ca_guards_fire_before_any_io()
    {
        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => BuildAsync(CaUsages, new List<string> { ServerAuth }, isCa: true, urls: new ExplodingServiceUrls()));

        Assert.Contains("must not carry an ExtendedKeyUsage", ex.Message);
    }

    /// <summary>
    /// A CA profile listing no standard usages at all still gets the mandatory bits, rather than
    /// producing a CA certificate with no KeyUsage extension (absence reads as unrestricted per
    /// RFC 5280 §4.2.1.3's surrounding guidance, which is not what a CA should assert).
    /// </summary>
    [Fact]
    public async Task A_ca_certificate_with_no_declared_usages_still_gets_the_mandatory_bits()
    {
        var cert = await BuildAsync(new List<string>(), new List<string>(), isCa: true);

        var usage = cert.GetKeyUsage();
        Assert.NotNull(usage);
        Assert.True(usage[5], "keyCertSign must be set even when the profile declares nothing");
        Assert.True(usage[6], "cRLSign must be set even when the profile declares nothing");
    }

    /// <summary>The certificates these tests call CA certificates must actually be CAs.</summary>
    [Fact]
    public async Task A_ca_certificate_carries_basic_constraints_ca_true()
    {
        var cert = await BuildAsync(CaUsages, new List<string>(), isCa: true);

        Assert.True(cert.GetBasicConstraints() >= 0, "cA must be TRUE on a CA certificate");
    }
}
