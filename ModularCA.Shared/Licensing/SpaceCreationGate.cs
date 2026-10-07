using ModularCA.Shared.Interfaces;

namespace ModularCA.Shared.Licensing;

/// <summary>
/// The licence recommendation on space creation. Creating a space always succeeds; past
/// <see cref="SpacesWithoutLicence"/> spaces, an installation whose licence does not carry
/// <see cref="FeatureKeys.MultiTenancy"/> is told a licence is recommended.
/// </summary>
/// <remarks>
/// A soft cap, not a gate: spaces delegate administration within one organisation, and a
/// separate customer belongs in a separate instance. The recommendation makes the licence terms
/// visible without refusing the operator anything.
/// </remarks>
public static class SpaceCreationGate
{
    /// <summary>How many spaces an installation may have before a licence is recommended.</summary>
    public const int SpacesWithoutLicence = 4;

    /// <summary>The recommendation the create response and the console show.</summary>
    public const string LicenceRecommendation = "A licence is recommended for more than four spaces.";

    /// <summary>
    /// Returns <see cref="LicenceRecommendation"/> when the new space would be the fifth or later
    /// and the licence does not carry <see cref="FeatureKeys.MultiTenancy"/>, else <see langword="null"/>.
    /// </summary>
    /// <param name="entitlements">This installation's entitlements.</param>
    /// <param name="existingSpaceCount">How many spaces exist before the new one, disabled ones included.</param>
    public static string? Recommendation(IEntitlementService entitlements, int existingSpaceCount) =>
        existingSpaceCount >= SpacesWithoutLicence && !entitlements.IsAvailable(FeatureKeys.MultiTenancy)
            ? LicenceRecommendation
            : null;
}
