using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// The one rule of switching badges: narrowing is free, broadening needs step-up MFA.
/// </summary>
/// <remarks>
/// Badgeless holds every grant source, so putting any badge on is a narrowing, taking one off
/// is a broadening, and switching between badges broadens exactly when the new badge keeps a
/// source the old one did not. Sources are compared as (kind, id) pairs; a badge that names a
/// source the user no longer holds contributes nothing at enforcement time, but still counts
/// here, since the rule is about what was asked for, not what would happen to work.
/// </remarks>
public static class AccessBadgePolicy
{
    /// <summary>A grant source as a comparable pair.</summary>
    public readonly record struct SourceKey(AccessBadgeSourceKind Kind, Guid SourceId);

    /// <summary>
    /// Whether moving from <paramref name="current"/> to <paramref name="target"/> widens what
    /// the session may do. <c>null</c> means badgeless on either side.
    /// </summary>
    public static bool IsBroadening(IReadOnlySet<SourceKey>? current, IReadOnlySet<SourceKey>? target)
    {
        if (current == null) return false;          // badgeless already holds everything
        if (target == null) return true;            // taking the badge off
        return target.Any(s => !current.Contains(s));
    }

    /// <summary>The sources of a badge as a set of keys.</summary>
    public static IReadOnlySet<SourceKey> KeysOf(IEnumerable<AccessBadgeSourceEntity> sources)
        => sources.Select(s => new SourceKey(s.Kind, s.SourceId)).ToHashSet();
}
