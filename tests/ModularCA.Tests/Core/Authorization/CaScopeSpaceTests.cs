using ModularCA.Core.Authorization;
using Xunit;

namespace ModularCA.Tests.Core.Authorization;

/// <summary>
/// The space scope narrows a list to the CAs of one space and, like the single-CA filter,
/// can never widen what the caller may see.
/// </summary>
public class CaScopeSpaceTests
{
    private static readonly Guid A = Guid.NewGuid();
    private static readonly Guid B = Guid.NewGuid();
    private static readonly Guid C = Guid.NewGuid();

    [Fact]
    public void Without_a_space_the_accessible_set_is_returned_as_is()
    {
        Assert.Null(CaScope.NarrowToSpace(null, null));
        Assert.Equal([A, B], CaScope.NarrowToSpace([A, B], null));
    }

    [Fact]
    public void An_unrestricted_caller_sees_the_whole_space()
    {
        Assert.Equal([B, C], CaScope.NarrowToSpace(null, [B, C]));
    }

    [Fact]
    public void A_restricted_caller_sees_only_what_they_can_see_inside_the_space()
    {
        Assert.Equal([B], CaScope.NarrowToSpace([A, B], [B, C]));
        var nothing = CaScope.NarrowToSpace([A], [B, C]);
        Assert.NotNull(nothing);
        Assert.Empty(nothing);
    }
}
