using System.Linq.Expressions;
using Microsoft.AspNetCore.Http;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// The caller's space fence: which spaces' rows (and whether instance rows, a null space) a
/// list or read may return to them. Built by <see cref="ICaGroupAuthorizationService.GetFenceAsync"/>
/// from all four grant sources, so it equals what authorization allows, and stored for the
/// request by <c>SpaceFenceMiddleware</c>. There is no query filter behind it: every
/// endpoint that lists or reads rows of several spaces applies it explicitly through
/// <see cref="Allows"/>, <see cref="AllowsProfile"/> or <see cref="Predicate{T}"/>, on the fence
/// narrowed by <see cref="For"/> to the capability its policy demands. A capability held at
/// system scope opens every space only for that capability, so a system auditor who also operates
/// one CA sees every space's audit views but only that CA's space's operator configuration. A
/// space, or the instance, is admitted for a capability only where something confers that
/// capability there, so a requester role in one space opens none of its operator configuration.
/// </summary>
public sealed class SpaceFence
{
    private const string ItemsKey = "SpaceFence";

    /// <summary>A fence that admits nothing.</summary>
    public static readonly SpaceFence None = new([], false, false, new HashSet<string>(), false, false,
        new Dictionary<string, HashSet<Guid>>(), new HashSet<string>());

    private readonly bool _caInstanceScope;
    private readonly bool _systemMember;
    private readonly IReadOnlySet<string> _systemCapabilities;
    private readonly IReadOnlyDictionary<string, HashSet<Guid>>? _spacesByCapability;
    private readonly IReadOnlySet<string>? _instanceCapabilities;

    private SpaceFence(HashSet<Guid> spaceIds, bool caInstanceScope, bool systemMember,
        IReadOnlySet<string> systemCapabilities, bool isSystemAdmin, bool instanceWide,
        IReadOnlyDictionary<string, HashSet<Guid>>? spacesByCapability, IReadOnlySet<string>? instanceCapabilities)
    {
        IsSystemAdmin = isSystemAdmin;
        _caInstanceScope = caInstanceScope;
        _systemMember = systemMember;
        _systemCapabilities = systemCapabilities;
        _spacesByCapability = spacesByCapability;
        _instanceCapabilities = instanceCapabilities;
        InstanceWide = instanceWide || isSystemAdmin;
        InstanceScope = InstanceWide || caInstanceScope || systemMember;
        SpaceIds = spaceIds;
    }

    /// <summary>The spaces the caller may see, besides everything when <see cref="InstanceWide"/>.</summary>
    internal HashSet<Guid> SpaceIds { get; }

    /// <summary>Whether the caller may see instance rows (a null space).</summary>
    internal bool InstanceScope { get; }

    /// <summary>
    /// Whether this fence admits every space. The fence the middleware stores answers true only
    /// for a system admin; one narrowed by <see cref="For"/> also answers true when the caller
    /// holds that capability at system scope.
    /// </summary>
    public bool InstanceWide { get; }

    /// <summary>Whether the caller is a system admin (system.manage).</summary>
    public bool IsSystemAdmin { get; }

    /// <summary>Whether the fence admits no row at all.</summary>
    public bool IsEmpty => !InstanceScope && SpaceIds.Count == 0;

    /// <summary>Whether the caller holds <paramref name="capability"/> at system scope, or is a system admin.</summary>
    public bool InstanceWideFor(string capability) => IsSystemAdmin || _systemCapabilities.Contains(capability);

    /// <summary>
    /// This fence narrowed to <paramref name="capability"/>: every space when the caller holds it
    /// at system scope, otherwise the spaces where a group, grant or role confers it, and instance
    /// rows only where an instance CA's group, grant or role confers it. A fence built by
    /// <see cref="Of"/> without per-capability scopes narrows only the instance-wide answer.
    /// </summary>
    public SpaceFence For(string capability)
    {
        var wide = InstanceWideFor(capability);
        if (_spacesByCapability == null || _instanceCapabilities == null)
            return new(SpaceIds, _caInstanceScope, false, _systemCapabilities, IsSystemAdmin, wide, null, null);
        var spaces = _spacesByCapability.TryGetValue(capability, out var held) ? held : [];
        return new(spaces, _instanceCapabilities.Contains(capability), false, _systemCapabilities, IsSystemAdmin, wide, null, null);
    }

    /// <summary>
    /// The fence for the current request, or null when the middleware resolved none
    /// (an unauthenticated request); each call site keeps its own rule for that case.
    /// </summary>
    public static SpaceFence? From(HttpContext context) => context.Items[ItemsKey] as SpaceFence;

    /// <summary>
    /// The request's fence narrowed by <see cref="For"/> to <paramref name="capability"/>, or
    /// <see cref="None"/> when the middleware resolved none.
    /// </summary>
    public static SpaceFence From(HttpContext context, string capability) => (From(context) ?? None).For(capability);

    /// <summary>
    /// Stores <paramref name="fence"/> as the request's fence, and sets <c>Items["IsSystemAdmin"]</c>
    /// for the callers that read that key.
    /// </summary>
    public static void Store(HttpContext context, SpaceFence fence)
    {
        context.Items[ItemsKey] = fence;
        if (fence.IsSystemAdmin)
            context.Items["IsSystemAdmin"] = true;
    }

    /// <summary>
    /// A fence over explicit values, for the resolver, tests and callers outside a request.
    /// <paramref name="spaceIds"/> and <paramref name="instanceScope"/> (instance scope through an
    /// instance CA) are the raw fence, over every capability; <paramref name="systemCapabilities"/>
    /// are the capabilities held at system scope, and <paramref name="systemMember"/> whether the
    /// caller is in a system group at all. <paramref name="spacesByCapability"/> and
    /// <paramref name="instanceCapabilities"/> are what <see cref="For"/> selects from: the spaces
    /// each capability is held in, and the capabilities held on an instance CA. Without them
    /// <see cref="For"/> keeps the raw spaces for every capability.
    /// </summary>
    public static SpaceFence Of(IEnumerable<Guid> spaceIds, bool instanceScope, bool isSystemAdmin = false,
        IEnumerable<string>? systemCapabilities = null, bool systemMember = false,
        IReadOnlyDictionary<string, HashSet<Guid>>? spacesByCapability = null, IEnumerable<string>? instanceCapabilities = null)
    {
        var caps = (systemCapabilities ?? []).ToHashSet(StringComparer.Ordinal);
        var byCapability = spacesByCapability?.ToDictionary(e => e.Key, e => e.Value.ToHashSet(), StringComparer.Ordinal);
        var instanceCaps = byCapability == null ? null : (instanceCapabilities ?? []).ToHashSet(StringComparer.Ordinal);
        return new(spaceIds.ToHashSet(), instanceScope, systemMember || caps.Count > 0, caps, isSystemAdmin, false, byCapability, instanceCaps);
    }

    /// <summary>Whether a row of <paramref name="spaceId"/> (null for the instance) is inside the fence.</summary>
    public bool Allows(Guid? spaceId)
        => InstanceWide || (spaceId is Guid t ? SpaceIds.Contains(t) : InstanceScope);

    /// <summary>
    /// Whether a certificate profile of <paramref name="spaceId"/>, bound to
    /// <paramref name="caId"/> or to none, is inside the fence. A profile bound to neither is
    /// instance-wide configuration everyone may see; any other follows <see cref="Allows"/>, so a
    /// profile bound to an instance CA needs instance scope.
    /// </summary>
    public bool AllowsProfile(Guid? spaceId, Guid? caId)
        => (spaceId == null && caId == null) || Allows(spaceId);

    /// <summary>
    /// The same rule as <see cref="Allows"/> as a translatable predicate over rows whose space
    /// <paramref name="spaceOf"/> selects, for <c>IQueryable.Where</c>.
    /// </summary>
    public Expression<Func<T, bool>> Predicate<T>(Expression<Func<T, Guid?>> spaceOf)
    {
        var ids = SpaceIds;
        var all = InstanceWide;
        var instance = InstanceScope;
        Expression<Func<Guid?, bool>> rule = t => all || (t == null && instance) || (t != null && ids.Contains(t.Value));
        var body = new Replace(rule.Parameters[0], spaceOf.Body).Visit(rule.Body)!;
        return Expression.Lambda<Func<T, bool>>(body, spaceOf.Parameters);
    }

    /// <summary>
    /// The same rule as <see cref="AllowsProfile"/> as a translatable predicate over rows whose
    /// profile space and CA <paramref name="spaceOf"/> and <paramref name="caOf"/> select.
    /// </summary>
    public Expression<Func<T, bool>> ProfilePredicate<T>(Expression<Func<T, Guid?>> spaceOf, Expression<Func<T, Guid?>> caOf)
    {
        var ids = SpaceIds;
        var all = InstanceWide;
        var instance = InstanceScope;
        Expression<Func<Guid?, Guid?, bool>> rule = (t, c) =>
            all || (t == null && c == null) || (t == null && instance) || (t != null && ids.Contains(t.Value));
        var parameter = spaceOf.Parameters[0];
        var caBody = new Replace(caOf.Parameters[0], parameter).Visit(caOf.Body)!;
        var body = new Replace(rule.Parameters[1], caBody).Visit(new Replace(rule.Parameters[0], spaceOf.Body).Visit(rule.Body)!)!;
        return Expression.Lambda<Func<T, bool>>(body, parameter);
    }

    private sealed class Replace(ParameterExpression from, Expression to) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) => node == from ? to : base.VisitParameter(node);
    }
}
