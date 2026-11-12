using ModularCA.Core.Services;
using ModularCA.Core.Services.Msae;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Byte-for-byte encodings of the ASN.1 structures Core builds with BouncyCastle, recorded from
/// the code as it was before moving off BouncyCastle's deprecated constructors and generator
/// overloads. A client parses these bytes (Windows for the CMC response and the template
/// extension, every relying party for name constraints), so a change of encoder must not change
/// them.
/// </summary>
public sealed class BouncyCastleEncodingTests
{
    /// <summary>
    /// The CMC "pending" response is an unsigned SignedData, so it is fully deterministic: the
    /// streaming generator's indefinite-length BER included.
    /// </summary>
    [Fact]
    public void The_cmc_pending_response_encodes_byte_for_byte()
    {
        var pendTime = new DateTime(2026, 11, 8, 12, 34, 56, DateTimeKind.Utc);

        Assert.Equal(
            "308006092A864886F70D010702A080308002010331800000308006082B06010505070C03A08004563054304E304C02010206082B06010505070719313D303B02010330030201010C1654616B656E20556E646572205375626D697373696F6E301904067265712D3432180F32303236313130383132333435365A300030000000000031800000000000000000",
            Convert.ToHexString(CmcResponses.BuildPending("req-42", pendTime)));
    }

    [Fact]
    public void The_certificate_template_extension_encodes_byte_for_byte()
    {
        Assert.Equal(
            "3013060B2B06010401823715080102020164020103",
            Convert.ToHexString(MsaeCsrTemplate.TemplateInfoValue("1.3.6.1.4.1.311.21.8.1.2", 100, 3)));
    }

    [Theory]
    [InlineData("[\"DNS:.example.com\",\"IP:10.0.0.0/8\"]", "[\"EMAIL:example.org\"]",
        "302FA01C300E820C2E6578616D706C652E636F6D300A87080A000000FF000000A10F300D810B6578616D706C652E6F7267")]
    [InlineData("[\"DNS:example.com\"]", null, "3011A00F300D820B6578616D706C652E636F6D")]
    [InlineData(null, "[\"DNS:bad.example.com\"]", "3015A1133011820F6261642E6578616D706C652E636F6D")]
    public void Name_constraints_encode_byte_for_byte(string? permitted, string? excluded, string expected)
    {
        var constraints = CertificateBuilderService.BuildNameConstraints(permitted, excluded);

        Assert.NotNull(constraints);
        Assert.Equal(expected, Convert.ToHexString(constraints.GetDerEncoded()));
    }
}
