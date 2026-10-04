namespace ModularCA.Shared.Utils;

/// <summary>What an integration API key's <c>SpaceId</c> setting fences it to.</summary>
public enum IntegrationScopeKind
{
    /// <summary>Unset: every space's CAs and the instance's.</summary>
    Everything,

    /// <summary><c>instance</c>: the instance's CAs only, those in no space.</summary>
    Instance,

    /// <summary>A space id: that space's CAs only.</summary>
    Space,

    /// <summary>Neither a space id nor <c>instance</c>: matches no CA.</summary>
    Invalid,
}

/// <summary>
/// An integration API key's space fence (<c>IntegrationApi.SpaceId</c>, <c>CertManager.SpaceId</c>),
/// parsed from the setting: unset is every space and the instance, <see cref="InstanceValue"/> the
/// instance's CAs only, and a GUID that space's CAs only. Any other value matches no CA, so a typo
/// fails closed.
/// </summary>
/// <param name="Kind">What the setting names.</param>
/// <param name="SpaceId">The space, for <see cref="IntegrationScopeKind.Space"/>.</param>
public readonly record struct IntegrationSpaceScope(IntegrationScopeKind Kind, Guid? SpaceId)
{
    /// <summary>The setting that fences a key to the instance's CAs (those in no space).</summary>
    public const string InstanceValue = "instance";

    /// <summary>Parses a <c>SpaceId</c> setting; see <see cref="IntegrationSpaceScope"/>.</summary>
    public static IntegrationSpaceScope Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return new(IntegrationScopeKind.Everything, null);
        var trimmed = value.Trim();
        if (string.Equals(trimmed, InstanceValue, StringComparison.OrdinalIgnoreCase))
            return new(IntegrationScopeKind.Instance, null);
        return Guid.TryParse(trimmed, out var id)
            ? new(IntegrationScopeKind.Space, id)
            : new(IntegrationScopeKind.Invalid, null);
    }

    /// <summary>True unless the key reaches every space and the instance.</summary>
    public bool IsRestricted => Kind != IntegrationScopeKind.Everything;

    /// <summary>Whether a CA in <paramref name="caSpaceId"/> (null for the instance) is inside the fence.</summary>
    public bool Allows(Guid? caSpaceId) => Kind switch
    {
        IntegrationScopeKind.Everything => true,
        IntegrationScopeKind.Instance => caSpaceId == null,
        IntegrationScopeKind.Space => caSpaceId == SpaceId,
        _ => false,
    };

    /// <summary>The fence in words, for logs and errors.</summary>
    public override string ToString() => Kind switch
    {
        IntegrationScopeKind.Everything => "every space and the instance",
        IntegrationScopeKind.Instance => "the instance",
        IntegrationScopeKind.Space => $"space {SpaceId}",
        _ => "no CA (the setting is neither a space id nor 'instance')",
    };
}
