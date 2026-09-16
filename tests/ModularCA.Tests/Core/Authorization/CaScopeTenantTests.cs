using ModularCA.Core.Authorization;
using Xunit;

namespace ModularCA.Tests.Core.Authorization;

/// <summary>
/// The tenant scope narrows a list to the CAs of one tenant and, like the single-CA filter,
/// can never widen what the caller may see.
/// </summary>
public class CaScopeTenantTests
{
    private static readonly Guid A = Guid.NewGuid();
    private static readonly Guid B = Guid.NewGuid();
    private static readonly Guid C = Guid.NewGuid();

    [Fact]
    public void Without_a_tenant_the_accessible_set_is_returned_as_is()
    {
        Assert.Null(CaScope.NarrowToTenant(null, null));
        Assert.Equal([A, B], CaScope.NarrowToTenant([A, B], null));
    }

    [Fact]
    public void An_unrestricted_caller_sees_the_whole_tenant()
    {
        Assert.Equal([B, C], CaScope.NarrowToTenant(null, [B, C]));
    }

    [Fact]
    public void A_restricted_caller_sees_only_what_they_can_see_inside_the_tenant()
    {
        Assert.Equal([B], CaScope.NarrowToTenant([A, B], [B, C]));
        var nothing = CaScope.NarrowToTenant([A], [B, C]);
        Assert.NotNull(nothing);
        Assert.Empty(nothing);
    }
}
