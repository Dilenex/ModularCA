using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// <see cref="CaLabelRules.RequiredLabel"/>: the label code builds a route from, or a refusal
/// naming the CA when a row has none, instead of a URL with an empty segment.
/// </summary>
public sealed class CaRequiredLabelTests
{
    [Fact]
    public void A_labelled_ca_gives_its_label()
    {
        Assert.Equal("issuing", CaLabelRules.RequiredLabel(new CertificateAuthorityEntity { Name = "Issuing", Label = "issuing" }));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void A_ca_without_a_label_is_refused_by_name(string? label)
    {
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Hand Edited", Label = label };

        var ex = Assert.Throws<InvalidOperationException>(() => CaLabelRules.RequiredLabel(ca));

        Assert.Contains("Hand Edited", ex.Message);
        Assert.Contains(ca.Id.ToString(), ex.Message);
    }
}
