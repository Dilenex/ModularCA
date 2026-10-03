namespace ModularCA.Shared.Authorization;

/// <summary>
/// Privilege tiers that a <i>controlled user</i> can hold. Used to gate who may approve (or
/// initiate) a controlled-user ceremony: an approver must <b>dominate</b> the affected privilege's
/// tier. System tiers have no scope; Space tiers are scoped to a space; CA tiers are scoped to one
/// CA (and carry their space so a space admin can dominate them). New tiers are appended so the
/// numeric values of persisted <c>MintedTierLevel</c> stay stable — dominance is explicit below,
/// not derived from the numeric order. A value with no member here fails closed.
/// </summary>
public enum ControlledTierLevel
{
    // 1 is reserved: a former CA operator tier that nothing ever minted.

    /// <summary>Administrator of a specific CA.</summary>
    CaAdmin = 2,

    /// <summary>Global system administrator (holds <c>system.manage</c> via a system group).</summary>
    SystemAdmin = 3,

    /// <summary>System-super (the bootstrap super tier). Dominates everything; mints directly.</summary>
    SystemSuper = 4,

    /// <summary>Operator over a whole space (space-scoped, not tied to one CA).</summary>
    SpaceOperator = 5,

    /// <summary>Administrator over a whole space (space-scoped).</summary>
    SpaceAdmin = 6,

    /// <summary>Operator over the whole instance (<c>ca.manage</c> at instance scope): a key-ceremony approver everywhere.</summary>
    SystemOperator = 7,
}

/// <summary>
/// A concrete privilege tier: a <see cref="ControlledTierLevel"/> plus its scope.
/// <list type="bullet">
/// <item>System tiers: <c>CaId</c> and <c>SpaceId</c> both null.</item>
/// <item>Space tiers: <c>SpaceId</c> set, <c>CaId</c> null.</item>
/// <item>CA tiers: <c>CaId</c> set, and <c>SpaceId</c> = the CA's owning space (so a space admin can dominate).</item>
/// </list>
/// </summary>
public readonly record struct ControlledTier(ControlledTierLevel Level, Guid? CaId)
{
    /// <summary>Owning space for space- and CA-scoped tiers; null for system tiers.</summary>
    public Guid? SpaceId { get; init; }

    /// <summary>
    /// Returns true when this tier dominates <paramref name="target"/> — i.e. a holder of this tier
    /// may approve/initiate a change affecting the target tier. An admin tier dominates every tier
    /// inside its scope; an operator tier dominates only the identical tier; super dominates
    /// everything.
    /// <list type="bullet">
    /// <item>system-super dominates everything.</item>
    /// <item>system-admin dominates everything except system-super.</item>
    /// <item>system-operator dominates only system-operator.</item>
    /// <item>space-admin(T) dominates space-admin/space-operator/ca-admin within space T.</item>
    /// <item>space-operator(T) dominates only space-operator(T).</item>
    /// <item>ca-admin(X) dominates only ca-admin(X), matched on the CA.</item>
    /// </list>
    /// An undefined level dominates nothing, and is dominated only by system-super and system-admin.
    /// </summary>
    public bool Dominates(ControlledTier target)
    {
        return Level switch
        {
            ControlledTierLevel.SystemSuper => true,
            ControlledTierLevel.SystemAdmin => target.Level != ControlledTierLevel.SystemSuper,
            ControlledTierLevel.SystemOperator => target.Level == ControlledTierLevel.SystemOperator,
            ControlledTierLevel.SpaceAdmin => SpaceId != null && target.SpaceId == SpaceId
                && target.Level is ControlledTierLevel.SpaceAdmin or ControlledTierLevel.SpaceOperator or ControlledTierLevel.CaAdmin,
            ControlledTierLevel.SpaceOperator => SpaceId != null && target.SpaceId == SpaceId
                && target.Level == ControlledTierLevel.SpaceOperator,
            ControlledTierLevel.CaAdmin => CaId != null && target.CaId == CaId
                && target.Level == ControlledTierLevel.CaAdmin,
            _ => false,
        };
    }

    /// <summary>
    /// The one tier an approver must dominate to cover all of <paramref name="tiers"/>: null when
    /// there are none, system-super when any is, otherwise the tier that dominates every other one,
    /// and system-admin when none does (the tiers span scopes no single scoped tier covers).
    /// </summary>
    public static ControlledTier? Covering(IEnumerable<ControlledTier?> tiers)
    {
        var all = tiers.Where(t => t != null).Select(t => t!.Value).ToList();
        if (all.Count == 0) return null;
        if (all.Any(t => t.Level == ControlledTierLevel.SystemSuper))
            return new ControlledTier(ControlledTierLevel.SystemSuper, null);
        foreach (var candidate in all)
            if (all.All(candidate.Dominates))
                return candidate;
        return new ControlledTier(ControlledTierLevel.SystemAdmin, null);
    }
}
