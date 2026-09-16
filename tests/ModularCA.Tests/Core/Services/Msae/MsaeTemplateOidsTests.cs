using ModularCA.Core.Services.Msae;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins the OIDs templates are offered to Windows under: generated ones live in the UUID arc and
/// follow from the template id, and operator-supplied ones must be real dotted-decimal OIDs.
/// </summary>
public class MsaeTemplateOidsTests
{
    [Fact]
    public void A_generated_oid_is_the_template_id_under_the_uuid_arc()
    {
        // X.667: 2.25.{uuid as a decimal integer}. The all-ones UUID is 2^128 - 1.
        var allOnes = new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff");
        Assert.Equal("2.25.340282366920938463463374607431768211455", MsaeTemplateOids.FromTemplateId(allOnes));

        // A concrete id, checked against the value computed by hand from its big-endian bytes.
        var id = new Guid("00000000-0000-0000-0000-000000000001");
        Assert.Equal("2.25.1", MsaeTemplateOids.FromTemplateId(id));
    }

    [Fact]
    public void Generation_is_deterministic_and_distinct_per_template()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        Assert.Equal(MsaeTemplateOids.FromTemplateId(a), MsaeTemplateOids.FromTemplateId(a));
        Assert.NotEqual(MsaeTemplateOids.FromTemplateId(a), MsaeTemplateOids.FromTemplateId(b));
        Assert.True(MsaeTemplateOids.IsValid(MsaeTemplateOids.FromTemplateId(a)));
    }

    [Theory]
    [InlineData("1.3.6.1.4.1.311.21.8.1234567.7654321.1")]
    [InlineData("2.25.1")]
    [InlineData("0.9.2342")]
    public void Dotted_decimal_oids_are_accepted(string oid)
    {
        Assert.True(MsaeTemplateOids.IsValid(oid));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("1")]
    [InlineData("3.1.2")]
    [InlineData("1.02.3")]
    [InlineData("1.3.")]
    [InlineData(".1.3")]
    [InlineData("1.3.6.a")]
    [InlineData("1.3.6.1.4.1.311.21.8.1234567.7654321.1234567.7654321.1234567.7654321.12345")]
    public void Anything_else_is_refused(string oid)
    {
        Assert.False(MsaeTemplateOids.IsValid(oid));
    }
}
