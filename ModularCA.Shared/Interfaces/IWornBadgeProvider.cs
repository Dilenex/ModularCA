namespace ModularCA.Shared.Interfaces;

/// <summary>
/// The access badge the current caller wears, if any, for stamping audit rows. Implemented over
/// the access token's claims; absent outside an HTTP request.
/// </summary>
public interface IWornBadgeProvider
{
    /// <summary>The worn badge's id, or null when badgeless.</summary>
    Guid? BadgeId { get; }

    /// <summary>The worn badge's name, or null when badgeless.</summary>
    string? BadgeName { get; }
}
