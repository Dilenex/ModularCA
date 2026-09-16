using ModularCA.Core;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// The <c>sort</c> parameter of the paged lists: <c>field</c> or <c>-field</c>, only among the
/// fields an endpoint names, so a stale or hostile value falls back to the default order.
/// </summary>
public class ListSortTests
{
    [Fact]
    public void Parses_direction_and_matches_fields_case_insensitively()
    {
        Assert.Equal(("notAfter", false), ListSort.Parse("notAfter", "notBefore", "notAfter"));
        Assert.Equal(("notAfter", true), ListSort.Parse("-NOTAFTER", "notBefore", "notAfter"));
    }

    [Fact]
    public void Rejects_unknown_and_empty_values()
    {
        Assert.Null(ListSort.Parse("subject", "notBefore", "notAfter"));
        Assert.Null(ListSort.Parse("", "notBefore"));
        Assert.Null(ListSort.Parse("  ", "notBefore"));
        Assert.Null(ListSort.Parse(null, "notBefore"));
        Assert.Null(ListSort.Parse("-", "notBefore"));
    }
}
