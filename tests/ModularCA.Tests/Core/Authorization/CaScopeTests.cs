using ModularCA.Core.Authorization;
using Xunit;

namespace ModularCA.Tests.Core.Authorization;

/// <summary>
/// Pins the one rule behind every <c>caId</c> list filter: naming a CA narrows the caller's
/// view and can never widen it. In particular, asking for a CA outside the accessible set
/// must produce an empty list, not the unfiltered one.
/// </summary>
public class CaScopeTests
{
    private static readonly Guid A = Guid.NewGuid();
    private static readonly Guid B = Guid.NewGuid();

    [Fact]
    public void Without_a_request_the_accessible_set_is_returned_as_is()
    {
        Assert.Null(CaScope.Narrow(null, null));
        Assert.Equal([A, B], CaScope.Narrow([A, B], null));
    }

    [Fact]
    public void An_unrestricted_caller_is_narrowed_to_the_requested_ca()
    {
        Assert.Equal([B], CaScope.Narrow(null, B));
    }

    [Fact]
    public void A_restricted_caller_may_pick_a_ca_they_can_see()
    {
        Assert.Equal([B], CaScope.Narrow([A, B], B));
    }

    [Fact]
    public void A_restricted_caller_naming_a_ca_they_cannot_see_gets_nothing_not_everything()
    {
        var narrowed = CaScope.Narrow([A], B);
        Assert.NotNull(narrowed);
        Assert.Empty(narrowed);
    }
}
