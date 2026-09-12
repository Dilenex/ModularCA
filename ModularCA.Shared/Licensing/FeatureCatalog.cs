using System.Reflection;

namespace ModularCA.Shared.Licensing;

/// <summary>
/// Stable identifiers for the features a licence can grant.
/// </summary>
/// <remarks>
/// <para>
/// Format is <c>area.feature</c>, lowercase. These strings appear inside signed licence
/// documents that customers hold, so they are part of the product's external contract in the
/// same way <see cref="ModularCA.Shared.Errors.ErrorCodes"/> is: a key may be added, never
/// renamed and never repurposed. Renaming one silently revokes a feature from everyone holding
/// a licence that names it.
/// </para>
/// <para>
/// Most of these gate code that does not exist in this repository — the enterprise modules ship
/// from a private one. The keys live here anyway, because the licence verifier, the catalogue
/// and the admin UI that displays entitlements are all open-source, and a customer should be
/// able to read what their licence says without owning the code it unlocks.
/// </para>
/// </remarks>
public static class FeatureKeys
{
    /// <summary>Creating tenants beyond the two the bootstrap creates.</summary>
    public const string MultiTenancy = "tenancy.multi";

    /// <summary>Publishing issued certificates into LDAP/AD directories.</summary>
    public const string LdapPublishing = "directory.publishing";

    /// <summary>Submitting issued certificates to Certificate Transparency logs.</summary>
    public const string CtSubmission = "transparency.submission";

    /// <summary>Declarative policy synchronisation from version-controlled YAML.</summary>
    public const string PolicySync = "policy.sync";

    /// <summary>Scheduled expiry notifications and lifecycle automation at fleet scale.</summary>
    public const string LifecycleNotifications = "lifecycle.notifications";

    /// <summary>Scheduled, encrypted, off-host backup and restore orchestration.</summary>
    public const string BackupOrchestration = "backup.orchestration";

    /// <summary>Compliance reporting and auditor evidence packs.</summary>
    public const string ComplianceReporting = "compliance.reporting";

    /// <summary>Multi-HSM key replication, cloud KMS backends, and automated failover.</summary>
    public const string HsmFleet = "hsm.fleet";

    /// <summary>Active/active clustering and multi-region operation.</summary>
    public const string HighAvailability = "ha.clustering";
}

/// <summary>
/// When each feature first shipped, which is what a lapsed maintenance date is compared against.
/// </summary>
/// <remarks>
/// <para>
/// The licence model is perpetual entitlement with maintenance-gated updates: a customer keeps
/// what they bought forever, and <c>maintenanceThrough</c> decides which features they may use,
/// not which build they may run. Availability is therefore
/// <c>entitled(key) &amp;&amp; IntroducedOn(key) &lt;= licence.MaintenanceThrough</c>.
/// </para>
/// <para>
/// The alternative — gating on the running build's release date — forces a long-term-support
/// branch for every release line so lapsed customers can still receive security fixes. Gating on
/// the feature's own introduction date means there is exactly one release line: a lapsed customer
/// upgrades freely, receives every security fix, keeps everything they paid for, and sees
/// newer features stay locked until they renew. The policy becomes a property of the design
/// rather than a promise kept by hand.
/// </para>
/// <para>
/// <b>These dates are append-only, and more strictly so than the error codes.</b> Moving one
/// later retroactively removes a feature from a customer who already paid for it — that is not
/// drift, it is taking back goods. Add rows; never edit them.
/// </para>
/// <para>
/// Note what this check does <em>not</em> read: the current time. Both sides of the comparison
/// come from the licence and the catalogue, so entitlement cannot be affected by clock drift.
/// That is deliberate — this codebase has already been bitten once by a host whose CMOS clock
/// had drifted an hour, and a CA that loses features because NTP is unhappy would be a repeat of
/// the same lesson in a worse place.
/// </para>
/// </remarks>
public static class FeatureCatalog
{
    private static readonly IReadOnlyDictionary<string, DateOnly> Introduced =
        new Dictionary<string, DateOnly>(StringComparer.Ordinal)
        {
            // The 0.1 line. Everything present at first commercial release shares its date, so a
            // licence whose maintenance covers launch covers all of it.
            [FeatureKeys.MultiTenancy] = new DateOnly(2026, 1, 1),
            [FeatureKeys.LdapPublishing] = new DateOnly(2026, 1, 1),
            [FeatureKeys.CtSubmission] = new DateOnly(2026, 1, 1),
            [FeatureKeys.PolicySync] = new DateOnly(2026, 1, 1),
            [FeatureKeys.LifecycleNotifications] = new DateOnly(2026, 1, 1),
            [FeatureKeys.BackupOrchestration] = new DateOnly(2026, 1, 1),
            [FeatureKeys.ComplianceReporting] = new DateOnly(2026, 1, 1),
            [FeatureKeys.HsmFleet] = new DateOnly(2026, 1, 1),
            [FeatureKeys.HighAvailability] = new DateOnly(2026, 1, 1),
        };

    /// <summary>Every feature key the catalogue knows, discovered from the declarations.</summary>
    public static IReadOnlyList<string> AllKeys { get; } =
        typeof(FeatureKeys)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(f => f is { IsLiteral: true, IsInitOnly: false } && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

    /// <summary>
    /// The date <paramref name="featureKey"/> first shipped, or <see langword="null"/> when the
    /// key is not one this build knows.
    /// </summary>
    /// <remarks>
    /// An unknown key is not an error. A licence issued for a newer release may name features
    /// this build has never heard of, and the correct response is to ignore them rather than
    /// refuse the whole licence — a customer who downgrades must not be locked out.
    /// </remarks>
    public static DateOnly? IntroducedOn(string featureKey)
        => Introduced.TryGetValue(featureKey, out var date) ? date : null;

    /// <summary>
    /// True when a licence whose maintenance ran through <paramref name="maintenanceThrough"/>
    /// covers <paramref name="featureKey"/>.
    /// </summary>
    /// <remarks>
    /// A key this build does not know returns false: it cannot be gated coherently, and failing
    /// closed on an unrecognised name is safer than guessing it is free.
    /// </remarks>
    public static bool CoveredByMaintenance(string featureKey, DateOnly maintenanceThrough)
        => IntroducedOn(featureKey) is { } introduced && introduced <= maintenanceThrough;
}
