using ModularCA.Core.Helpers;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// The certificate profiles a request profile designates, which the self-service request form
/// offers by name (<see cref="RequestProfileCertProfiles.DesignatedIds"/>).
/// </summary>
public class DesignatedCertProfileIdsTests
{
    private static readonly Guid A = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid B = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public void The_default_comes_first_and_is_not_repeated()
    {
        var ids = RequestProfileCertProfiles.DesignatedIds(B, $"[\"{A}\",\"{B}\"]");

        Assert.Equal([B, A], ids);
    }

    [Fact]
    public void The_allowed_list_stands_alone_without_a_default()
    {
        Assert.Equal([A, B], RequestProfileCertProfiles.DesignatedIds(null, $"[\"{A}\",\"{B}\"]"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("[]")]
    [InlineData("not json")]
    [InlineData("[\"not-a-guid\"]")]
    public void An_empty_or_unreadable_list_leaves_only_the_default(string? allowed)
    {
        Assert.Equal([A], RequestProfileCertProfiles.DesignatedIds(A, allowed));
        Assert.Empty(RequestProfileCertProfiles.DesignatedIds(null, allowed));
    }
}
