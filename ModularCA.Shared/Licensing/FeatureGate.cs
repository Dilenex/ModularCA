using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Shared.Licensing;

/// <summary>
/// Turns an entitlement denial into the refusal an operator sees.
/// </summary>
/// <remarks>
/// <para>
/// Extracted from <see cref="TenantCreationGate"/>, which was the only gate in the product and
/// therefore also the only place that knew how a licensing refusal should read. Two things make
/// that worth generalising before the second gate exists rather than after.
/// </para>
/// <para>
/// The first is that <b>the refusal is part of the product</b>. Every one of these is read by
/// someone who has just been told no by software they are evaluating or already paying for, and
/// the difference between a refusal that explains itself and one that does not is the difference
/// between an email and a churn. Getting that right once and reusing it beats getting it right
/// three times and drifting.
/// </para>
/// <para>
/// The second is the error-code split, which is easy to get wrong and invisible when you do.
/// <see cref="ErrorCodes.FeatureNotEntitled"/> and <see cref="ErrorCodes.MaintenanceLapsed"/> send
/// the reader to different places: one means "this was never purchased", the other means "this was
/// purchased and shipped after the maintenance window closed". Rendering both as the same code
/// tells a customer who has already paid to go and buy the thing again, which is the worst
/// possible answer to give someone mid-renewal.
/// </para>
/// <para>
/// Every gate built on this ships in the open-source core and can be deleted from a fork. That is
/// understood and accepted — enforcement is the licence agreement and the audit record, not the
/// <c>if</c> statement. The job here is to make the terms visible and the refusal explainable.
/// </para>
/// </remarks>
public static class FeatureGate
{
    /// <summary>
    /// Returns the refusal to throw when <paramref name="featureKey"/> is unavailable, or
    /// <see langword="null"/> when the operation may proceed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns rather than throws, which is the one piece of ceremony every caller has to observe:
    /// a refused attempt to exceed a licence limit is exactly the event a commercial dispute later
    /// turns on, so the caller writes its audit record first and throws second. A helper that threw
    /// directly would make the correct ordering impossible to express.
    /// </para>
    /// <para>
    /// <paramref name="whatIsUnaffected"/> has no technical function and is not optional in
    /// practice. An operator refused mid-task assumes the worst — that issuance has stopped, that
    /// something they already built is now unusable — and stating plainly what still works is the
    /// difference between a licensing message and an outage report. Every gate must be able to
    /// answer it, and a feature where nothing can be said in that sentence is a feature that should
    /// not be gated this way.
    /// </para>
    /// </remarks>
    /// <param name="entitlements">This installation's entitlements.</param>
    /// <param name="featureKey">A key from <see cref="FeatureKeys"/>.</param>
    /// <param name="whatIsGated">
    /// The operation, as a sentence opener in the operator's words rather than the code's —
    /// "Creating additional tenants", "Scheduling off-host backups".
    /// </param>
    /// <param name="whatIsUnaffected">
    /// What keeps working regardless, stated plainly. See the remarks.
    /// </param>
    public static LicensingException? Require(
        IEntitlementService entitlements,
        string featureKey,
        string whatIsGated,
        string whatIsUnaffected)
    {
        var denial = entitlements.Explain(featureKey);
        if (denial is null)
            return null;

        var code = denial.Reason == EntitlementDenialReason.MaintenanceLapsed
            ? ErrorCodes.MaintenanceLapsed
            : ErrorCodes.FeatureNotEntitled;

        // Name first, key second. The name is what tells the reader whether this concerns them; the
        // key is what they paste into a ticket or search the catalogue for. "the" rather than "a"
        // because it has to be grammatical in front of every name in the catalogue, including the
        // ones starting with a vowel sound.
        return new LicensingException(
            $"{whatIsGated} requires the {FeatureCatalog.DisplayName(featureKey)} "
            + $"license entitlement: '{featureKey}'. {whatIsUnaffected} {denial.Detail}",
            code,
            denial.Remediation);
    }

    /// <summary>
    /// Returns the refusal to throw when a licensed numeric limit is already reached, or
    /// <see langword="null"/> when there is room.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Require"/> because the two failures are genuinely different: one
    /// says the feature was never bought, the other says it was bought and is full. They carry
    /// different codes, and a caller usually needs both in sequence — entitlement first, because
    /// telling someone their limit is reached when they have no entitlement at all is a confusing
    /// way to say no.
    /// <para>
    /// A limit the licence does not name is unlimited, not zero. Failing closed on a missing limit
    /// would turn every older licence into a broken one the moment a new limit is introduced.
    /// </para>
    /// </remarks>
    /// <param name="entitlements">This installation's entitlements.</param>
    /// <param name="limitName">A key from <see cref="LicenseLimits"/>.</param>
    /// <param name="currentCount">How many already exist.</param>
    /// <param name="noun">What is being counted, singular — "tenant", "connected directory".</param>
    /// <param name="whatIsUnaffected">What keeps working regardless.</param>
    public static LicensingException? RequireHeadroom(
        IEntitlementService entitlements,
        string limitName,
        int currentCount,
        string noun,
        string whatIsUnaffected)
    {
        if (entitlements.GetLimit(limitName) is not { } max || currentCount < max)
            return null;

        return new LicensingException(
            $"This licence permits {max} {noun}(s) and {currentCount} already exist. {whatIsUnaffected}",
            ErrorCodes.LicenseLimitReached,
            $"Raise the {noun} limit on your licence, or remove one you no longer need. "
            + $"Existing {noun}s are never removed automatically.");
    }
}
