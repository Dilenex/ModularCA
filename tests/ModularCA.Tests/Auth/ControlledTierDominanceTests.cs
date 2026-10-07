using ModularCA.Shared.Authorization;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Pins <see cref="ControlledTier.Dominates"/> over every ordered pair of tiers against a table
/// written here, not derived from the implementation, plus the enum values persisted in ceremony
/// parameters and <see cref="ControlledTier.Covering"/>.
/// </summary>
public class ControlledTierDominanceTests
{
    private static readonly Guid T1 = Guid.Parse("00000000-0000-0000-0000-0000000000a1");
    private static readonly Guid T2 = Guid.Parse("00000000-0000-0000-0000-0000000000a2");
    private static readonly Guid X1 = Guid.Parse("00000000-0000-0000-0000-0000000000c1");
    private static readonly Guid X2 = Guid.Parse("00000000-0000-0000-0000-0000000000c2");
    private static readonly Guid Y = Guid.Parse("00000000-0000-0000-0000-0000000000c3");
    private static readonly Guid I = Guid.Parse("00000000-0000-0000-0000-0000000000c4");

    // Undefined levels carry CA X1 in space T1, so neither a CA nor a space scope can rescue them.
    private static readonly Dictionary<string, ControlledTier> Tiers = new()
    {
        ["Super"] = new(ControlledTierLevel.SystemSuper, null),
        ["Admin"] = new(ControlledTierLevel.SystemAdmin, null),
        ["SysOp"] = new(ControlledTierLevel.SystemOperator, null),
        ["OA(T1)"] = new(ControlledTierLevel.SpaceAdmin, null) { SpaceId = T1 },
        ["OA(T2)"] = new(ControlledTierLevel.SpaceAdmin, null) { SpaceId = T2 },
        ["OO(T1)"] = new(ControlledTierLevel.SpaceOperator, null) { SpaceId = T1 },
        ["OO(T2)"] = new(ControlledTierLevel.SpaceOperator, null) { SpaceId = T2 },
        ["CA(X1|T1)"] = new(ControlledTierLevel.CaAdmin, X1) { SpaceId = T1 },
        ["CA(X2|T1)"] = new(ControlledTierLevel.CaAdmin, X2) { SpaceId = T1 },
        ["CA(Y|T2)"] = new(ControlledTierLevel.CaAdmin, Y) { SpaceId = T2 },
        ["CA(I|null)"] = new(ControlledTierLevel.CaAdmin, I),
        ["raw0"] = new((ControlledTierLevel)0, X1) { SpaceId = T1 },
        ["raw1"] = new((ControlledTierLevel)1, X1) { SpaceId = T1 },
        ["raw99"] = new((ControlledTierLevel)99, X1) { SpaceId = T1 },
    };

    private static readonly string[] All = Tiers.Keys.ToArray();

    /// <summary>What each actor dominates. Anything not listed is not dominated.</summary>
    private static readonly Dictionary<string, string[]> Expected = new()
    {
        ["Super"] = All,
        ["Admin"] = All.Where(t => t != "Super").ToArray(),
        ["SysOp"] = ["SysOp"],
        ["OA(T1)"] = ["OA(T1)", "OO(T1)", "CA(X1|T1)", "CA(X2|T1)"],
        ["OA(T2)"] = ["OA(T2)", "OO(T2)", "CA(Y|T2)"],
        ["OO(T1)"] = ["OO(T1)"],
        ["OO(T2)"] = ["OO(T2)"],
        ["CA(X1|T1)"] = ["CA(X1|T1)"],
        ["CA(X2|T1)"] = ["CA(X2|T1)"],
        ["CA(Y|T2)"] = ["CA(Y|T2)"],
        ["CA(I|null)"] = ["CA(I|null)"],
        ["raw0"] = [],
        ["raw1"] = [],
        ["raw99"] = [],
    };

    public static TheoryData<string, string> Pairs()
    {
        var data = new TheoryData<string, string>();
        foreach (var actor in All)
            foreach (var target in All)
                data.Add(actor, target);
        return data;
    }

    [Theory]
    [MemberData(nameof(Pairs))]
    public void Dominance_matches_the_table(string actor, string target)
    {
        Assert.Equal(Expected[actor].Contains(target), Tiers[actor].Dominates(Tiers[target]));
    }

    [Fact]
    public void A_ca_tier_matches_on_the_ca_not_the_space()
    {
        var x1NoSpace = new ControlledTier(ControlledTierLevel.CaAdmin, X1);
        Assert.True(Tiers["CA(X1|T1)"].Dominates(x1NoSpace));
        Assert.True(x1NoSpace.Dominates(Tiers["CA(X1|T1)"]));
        Assert.False(Tiers["OA(T1)"].Dominates(x1NoSpace));
    }

    [Fact]
    public void Persisted_levels_are_pinned_and_1_is_reserved()
    {
        Assert.Equal(2, (int)ControlledTierLevel.CaAdmin);
        Assert.Equal(3, (int)ControlledTierLevel.SystemAdmin);
        Assert.Equal(4, (int)ControlledTierLevel.SystemSuper);
        Assert.Equal(5, (int)ControlledTierLevel.SpaceOperator);
        Assert.Equal(6, (int)ControlledTierLevel.SpaceAdmin);
        Assert.Equal(7, (int)ControlledTierLevel.SystemOperator);
        Assert.False(Enum.IsDefined(typeof(ControlledTierLevel), 1));
        Assert.Equal(new[] { 2, 3, 4, 5, 6, 7 }, Enum.GetValues<ControlledTierLevel>().Select(l => (int)l).OrderBy(v => v));
    }

    private static ControlledTier? Cover(params string[] names) => ControlledTier.Covering(names.Select(n => (ControlledTier?)Tiers[n]));

    [Fact]
    public void Covering_a_same_scope_set_is_its_maximum()
    {
        Assert.Equal(Tiers["OA(T1)"], Cover("CA(X1|T1)", "OO(T1)", "OA(T1)"));
        Assert.Equal(Tiers["CA(X1|T1)"], Cover("CA(X1|T1)"));
        Assert.Equal(Tiers["OO(T1)"], Cover("OO(T1)", "OO(T1)"));
        Assert.Equal(Tiers["SysOp"], Cover("SysOp"));
        Assert.Equal(Tiers["Admin"], Cover("SysOp", "Admin", "OA(T2)"));
    }

    [Fact]
    public void Covering_an_incomparable_set_is_system_admin()
    {
        var admin = Tiers["Admin"];
        Assert.Equal(admin, Cover("CA(X1|T1)", "CA(X2|T1)"));
        Assert.Equal(admin, Cover("CA(X1|T1)", "OO(T1)"));
        Assert.Equal(admin, Cover("OA(T1)", "OA(T2)"));
        Assert.Equal(admin, Cover("SysOp", "OO(T1)"));
        Assert.Equal(admin, Cover("SysOp", "CA(I|null)"));
        Assert.Equal(admin, Cover("raw1"));
        Assert.Equal(admin, Cover("raw0", "CA(X1|T1)"));
    }

    [Fact]
    public void Covering_with_any_super_is_super()
    {
        Assert.Equal(Tiers["Super"], Cover("CA(X1|T1)", "Super"));
        Assert.Equal(Tiers["Super"], Cover("raw99", "OA(T1)", "CA(Y|T2)", "Super"));
    }

    [Fact]
    public void Covering_nothing_is_null()
    {
        Assert.Null(ControlledTier.Covering([]));
        Assert.Null(ControlledTier.Covering([null, null]));
    }
}
