using ModularCA.Shared.Licensing;

namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Answers what this installation is licensed to do.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately separate from <see cref="IFeatureFlagService"/>, which reads a database table an
/// administrator can edit through the admin UI. That is exactly right for "turn OCSP off on this
/// host" and exactly wrong for "you have not bought multi-tenancy": one is an operator
/// preference, the other is a licence term, and an entitlement stored where the operator can
/// flip it is not an entitlement.
/// </para>
/// <para>
/// The two compose rather than compete. A feature is usable when it is both licensed and
/// switched on:
/// </para>
/// <code>
/// available = entitlements.IsAvailable(key) &amp;&amp; flags.IsEnabled(flagName)
/// </code>
/// <para>
/// Enforcement is honour-system by design: this service gates the UI and the write paths and
/// writes an audit record when a limit is refused, and there is no obfuscation or anti-tamper
/// anywhere near it. The protection for a self-hosted product is the licence agreement and the
/// audit trail; a security buyer who cannot read the check would trust the product less, not
/// more.
/// </para>
/// </remarks>
public interface IEntitlementService
{
    /// <summary>
    /// True when the licence grants <paramref name="featureKey"/> at all, ignoring maintenance.
    /// </summary>
    /// <remarks>
    /// Entitlements are perpetual, so this stays true forever once purchased. Use
    /// <see cref="IsAvailable"/> for the question that actually gates behaviour.
    /// </remarks>
    bool IsEntitled(string featureKey);

    /// <summary>
    /// True when the licence grants <paramref name="featureKey"/> <em>and</em> the feature
    /// shipped on or before the licence's maintenance date.
    /// </summary>
    bool IsAvailable(string featureKey);

    /// <summary>
    /// Explains why <paramref name="featureKey"/> is unavailable, or <see langword="null"/> when
    /// it is available.
    /// </summary>
    /// <remarks>
    /// "You never bought this" and "you bought this but your maintenance lapsed before it
    /// shipped" need different messages and different error codes. Rendering them identically
    /// makes the renewal conversation worse, so the distinction is carried here rather than
    /// reconstructed by each caller.
    /// </remarks>
    EntitlementDenial? Explain(string featureKey);

    /// <summary>
    /// The numeric ceiling for <paramref name="limitName"/>, or <see langword="null"/> when the
    /// licence sets none.
    /// </summary>
    int? GetLimit(string limitName);

    /// <summary>The licence backing these answers, including the free-edition case.</summary>
    LicenseLoadResult License { get; }
}

/// <summary>Why a feature is not available.</summary>
public enum EntitlementDenialReason
{
    /// <summary>The licence does not grant this feature.</summary>
    NotEntitled,

    /// <summary>Granted, but the feature shipped after the licence's maintenance date.</summary>
    MaintenanceLapsed,
}

/// <summary>
/// A refusal with enough detail to explain itself to an operator.
/// </summary>
/// <param name="Reason">Which of the two distinct refusals this is.</param>
/// <param name="FeatureKey">The feature that was asked for.</param>
/// <param name="Detail">Operator-facing sentence.</param>
/// <param name="Remediation">What to do about it — purchase, or renew.</param>
public sealed record EntitlementDenial(
    EntitlementDenialReason Reason,
    string FeatureKey,
    string Detail,
    string Remediation);
