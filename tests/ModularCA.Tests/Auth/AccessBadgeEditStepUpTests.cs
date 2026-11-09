using ModularCA.Auth.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.Roles;
using Xunit;
using Key = ModularCA.Auth.Authorization.AccessBadgePolicy.SourceKey;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Bug hunt 2026-11, F6: switching to a wider badge needs step-up MFA, but the worn badge is read
/// live on every request, so editing it (or deleting it) widened the session with none. Editing
/// the worn badge so the session gains a source, or deleting it, now needs the same step-up;
/// narrowing it, and editing any other badge, does not.
/// </summary>
public sealed class AccessBadgeEditStepUpTests
{
    private static readonly Guid Worn = Guid.NewGuid();
    private static readonly Guid Other = Guid.NewGuid();
    private static readonly Key Operators = new(AccessBadgeSourceKind.Group, Guid.NewGuid());
    private static readonly Key Admins = new(AccessBadgeSourceKind.Group, Guid.NewGuid());

    private static HashSet<Key> Set(params Key[] keys) => [.. keys];

    [Fact]
    public void Adding_a_source_to_the_worn_badge_needs_step_up()
        => Assert.True(AccessBadgePolicy.EditWidensSession(Worn, Worn, Set(Operators), Set(Operators, Admins)));

    [Fact]
    public void Deleting_the_worn_badge_needs_step_up()
        => Assert.True(AccessBadgePolicy.EditWidensSession(Worn, Worn, Set(Operators), edited: null));

    [Fact]
    public void Narrowing_the_worn_badge_or_renaming_it_does_not()
    {
        Assert.False(AccessBadgePolicy.EditWidensSession(Worn, Worn, Set(Operators, Admins), Set(Operators)));
        Assert.False(AccessBadgePolicy.EditWidensSession(Worn, Worn, Set(Operators), Set(Operators)));
    }

    [Fact]
    public void Editing_or_deleting_another_badge_does_not()
    {
        Assert.False(AccessBadgePolicy.EditWidensSession(Worn, Other, Set(Operators), Set(Operators, Admins)));
        Assert.False(AccessBadgePolicy.EditWidensSession(Worn, Other, Set(Operators), edited: null));
        Assert.False(AccessBadgePolicy.EditWidensSession(null, Other, Set(Operators), edited: null));
    }

    /// <summary>The controller reads the worn badge and asks for step-up on both edit paths.</summary>
    [Fact]
    public void The_badge_controller_takes_the_worn_badge_and_the_step_up_cache()
    {
        var ctor = Assert.Single(ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Account.AccountBadgesController").GetConstructors());
        var parameters = ctor.GetParameters().Select(p => p.ParameterType.Name).ToList();

        Assert.Contains(nameof(IAccessBadgeContext), parameters);
        Assert.Contains("IDistributedCache", parameters);
    }
}
