using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers the shared SAN encoder and the UPN case of the shape validator.
/// <para>
/// Three places built SANs — the runtime certificate builder, the bootstrap self-signed builder,
/// and the admin generate-key path that assembles a PKCS#10 for the caller — and two of them
/// mapped any unrecognised type to <c>DnsName</c>. That default does not drop the entry, it signs
/// the caller's text into the certificate as a DNS name: a <c>UPN:</c> became a DNS SAN holding a
/// principal name, and a typo like <c>DSN:</c> became a DNS SAN with nothing reported.
/// </para>
/// </summary>
public class SanGeneralNamesTests
{
    [Theory]
    [InlineData("DNS", GeneralName.DnsName)]
    [InlineData("dns", GeneralName.DnsName)]
    [InlineData("IP", GeneralName.IPAddress)]
    [InlineData("URI", GeneralName.UniformResourceIdentifier)]
    [InlineData("Email", GeneralName.Rfc822Name)]
    [InlineData("RFC822", GeneralName.Rfc822Name)]
    public void Known_types_map_to_their_general_name_tag(string type, int expectedTag)
    {
        var value = type.Equals("IP", StringComparison.OrdinalIgnoreCase) ? "10.0.0.1" : "host.example.test";
        Assert.Equal(expectedTag, SanGeneralNames.Build(type, value).TagNo);
    }

    /// <summary>UPN is the one type that is not a simple tagged string.</summary>
    [Fact]
    public void Upn_builds_an_othername()
    {
        var gn = SanGeneralNames.Build("UPN", "alice@example.test");

        Assert.Equal(GeneralName.OtherName, gn.TagNo);
        Assert.Equal("alice@example.test", UpnSanEncoding.TryGetUpn(gn));
    }

    /// <summary>
    /// The regression this type exists for: an unknown type must be an error, not a DNS name.
    /// </summary>
    [Theory]
    [InlineData("DSN")]       // transposed "DNS"
    [InlineData("UPN2")]
    [InlineData("registeredID")]
    [InlineData("")]
    public void Unknown_types_are_refused_rather_than_becoming_dns_names(string type)
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => SanGeneralNames.Build(type, "anything"));
        Assert.Contains("Unsupported SAN type", ex.Message);
    }

    // ── Shape validation, as surfaced on the request form ────────────────────

    [Fact]
    public void A_well_formed_upn_passes_shape_validation()
        => Assert.Null(SanShapeValidator.ValidateShape("UPN", "alice@example.test"));

    /// <summary>
    /// Reported at the form rather than at signing. Before this, UPN fell through the validator's
    /// default arm and any string reached the issuance pipeline.
    /// </summary>
    [Theory]
    [InlineData("no-at-sign")]
    [InlineData("alice@")]
    [InlineData("\"Alice\" <alice@example.test>")]
    public void A_malformed_upn_is_reported_by_shape_validation(string upn)
        => Assert.NotNull(SanShapeValidator.ValidateShape("UPN", upn));

    /// <summary>The other types keep their existing shape rules.</summary>
    [Fact]
    public void Existing_shape_rules_are_unchanged()
    {
        Assert.Null(SanShapeValidator.ValidateShape("DNS", "host.example.test"));
        Assert.NotNull(SanShapeValidator.ValidateShape("DNS", "not a hostname"));
        Assert.Null(SanShapeValidator.ValidateShape("IP", "10.0.0.1"));
        Assert.NotNull(SanShapeValidator.ValidateShape("IP", "1.2.3"));
    }
}
