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
/// The keys live in the open-source tree regardless of where the code they gate lives, because
/// the licence verifier, the catalogue and the admin UI that displays entitlements are all
/// open-source, and a customer should be able to read what their licence says without owning
/// the code it unlocks.
/// </para>
/// <para>
/// <b>Two different things are being gated here, and conflating them produces a claim the
/// repository contradicts.</b>
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///     <b>Licence-gated open code.</b> <see cref="FeatureKeys.MultiTenancy"/>,
///     <see cref="FeatureKeys.BackupOrchestration"/> and
///     <see cref="FeatureKeys.ComplianceReporting"/> are implemented in this repository, under
///     AGPL-3.0, and can be read and forked by anyone. What the licence grants is the right to
///     use them past the free threshold, enforced the way
///     <see cref="TenantCreationGate"/> enforces it: a clear refusal and an audit record, not a
///     technical impossibility. Honour system, with evidence.
///     </description>
///   </item>
///   <item>
///     <description>
///     <b>Private modules.</b> <see cref="FeatureKeys.SingleSignOn"/>,
///     <see cref="FeatureKeys.HsmFleet"/> and <see cref="FeatureKeys.HighAvailability"/> gate
///     code that genuinely is not here and ships from a separate private repository. This is the
///     only mechanism that withholds anything, and it can only ever apply to work not yet
///     published — AGPL is a one-way door, so a feature released here is free at that version
///     forever.
///     </description>
///   </item>
/// </list>
/// <para>
/// Four keys were removed before any licence naming them was ever issued: LDAP publishing,
/// Certificate Transparency submission, policy sync and lifecycle notifications. All four were
/// already implemented and published here, so gating them would have been unenforceable against
/// the fork of this very commit — and all four are table stakes whose absence would have made
/// the free tier feel crippled rather than generous. Policy sync in particular is the feature
/// most likely to earn an advocate inside a platform team, which is a poor thing to charge for
/// at this stage. Removing keys is safe only because none has appeared in an issued licence; a
/// key that has been sold is as append-only as an error code.
/// </para>
/// <para>
/// One rule constrains what may be added here at all: <b>never gate on how many certificates or
/// CAs exist.</b> This is a security product, and a ceiling on those numbers pays operators to do
/// the wrong thing — reuse certificates, skip rotations, let an expiry slide. Gate on
/// organisational boundaries (tenants, identity federation, clustering), never on the activity
/// the product exists to encourage.
/// </para>
/// </remarks>
public static class FeatureKeys
{
    /// <summary>
    /// Creating tenants beyond the two the bootstrap creates. Licence-gated open code: the
    /// multi-tenancy implementation is in this repository and a single-tenant install needs none
    /// of it. What is sold is running more than one organisation's PKI from one deployment, which
    /// is the managed-service case rather than the internal-CA case.
    /// </summary>
    public const string MultiTenancy = "tenancy.multi";

    /// <summary>
    /// Scheduled, encrypted, off-host backup and restore orchestration. Licence-gated open code —
    /// and deliberately only the orchestration. Taking and restoring a backup by hand stays free,
    /// because a CA that cannot be recovered is a disaster rather than an upsell, and charging for
    /// the difference between "has a backup" and "has no backup" would be indefensible.
    /// </summary>
    public const string BackupOrchestration = "backup.orchestration";

    /// <summary>
    /// Auditor evidence packs and compliance reporting. Licence-gated open code, and again only
    /// the export half: the compliance scanner and the findings it produces stay free, because
    /// knowing your own posture should not be a paid feature. What is sold is the packaging of
    /// that evidence for someone else's auditor, which is work a customer would otherwise do by
    /// hand and will not do by choice.
    /// </summary>
    public const string ComplianceReporting = "compliance.reporting";

    /// <summary>
    /// SAML/OIDC single sign-on and SCIM user provisioning. Private module; not implemented in
    /// any form yet. The local accounts, WebAuthn and TOTP in this repository are a complete
    /// authentication story for one organisation — this is the federation an enterprise buyer
    /// requires before the product can be deployed at all, which is why it is worth money and why
    /// its absence is the clearest gap in the roadmap.
    /// </summary>
    public const string SingleSignOn = "identity.federation";

    /// <summary>
    /// Multi-HSM key replication, cloud KMS backends, and automated failover. Private module.
    /// Single-keystore operation, including the break-glass unlocker, stays free.
    /// </summary>
    public const string HsmFleet = "hsm.fleet";

    /// <summary>
    /// Active/active clustering and multi-region operation. Private module; not implemented.
    /// A single-node deployment is the free shape and is sufficient for an internal CA.
    /// </summary>
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
            // licence whose maintenance covers launch covers all of it — including the features
            // not yet built, which is intentional: dating them at launch means a launch customer
            // whose maintenance later lapses still receives SSO, HSM fleet and clustering when
            // they ship. Dating them at their real ship date would sell a lapsed customer a
            // roadmap they then have to renew to collect.
            [FeatureKeys.MultiTenancy] = new DateOnly(2026, 1, 1),
            [FeatureKeys.BackupOrchestration] = new DateOnly(2026, 1, 1),
            [FeatureKeys.ComplianceReporting] = new DateOnly(2026, 1, 1),
            [FeatureKeys.SingleSignOn] = new DateOnly(2026, 1, 1),
            [FeatureKeys.HsmFleet] = new DateOnly(2026, 1, 1),
            [FeatureKeys.HighAvailability] = new DateOnly(2026, 1, 1),
        };

    /// <summary>
    /// What each feature is called in a sentence an operator reads.
    /// </summary>
    /// <remarks>
    /// A key identifies; a name explains — the same division of labour as
    /// <see cref="ModularCA.Shared.Errors.ErrorCodes"/> and the messages beside them. A refusal
    /// reading "requires the 'tenancy.multi' entitlement" makes the reader decode an identifier
    /// before they can tell whether it is relevant to them; one reading "requires the multi-tenancy
    /// license entitlement: 'tenancy.multi'" tells them what it is and still gives them the string
    /// to quote in a ticket.
    /// <para>
    /// Centralised rather than passed in at each gate, because every call site inventing its own
    /// noun is exactly the drift <see cref="FeatureGate"/> exists to prevent — and because the
    /// admin UI that lists entitlements needs the same names.
    /// </para>
    /// <para>
    /// Unlike the keys and the dates, these are <b>not</b> append-only. A name is prose and may be
    /// reworded freely; nothing is keyed on it.
    /// </para>
    /// </remarks>
    private static readonly IReadOnlyDictionary<string, string> DisplayNames =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [FeatureKeys.MultiTenancy] = "multi-tenancy",
            [FeatureKeys.BackupOrchestration] = "backup orchestration",
            [FeatureKeys.ComplianceReporting] = "compliance reporting",
            [FeatureKeys.SingleSignOn] = "identity federation",
            [FeatureKeys.HsmFleet] = "HSM fleet",
            [FeatureKeys.HighAvailability] = "high-availability clustering",
        };

    /// <summary>
    /// The human-readable name for <paramref name="featureKey"/>, falling back to the key itself
    /// when this build does not know it.
    /// </summary>
    /// <remarks>
    /// Falls back rather than throwing, for the same reason <see cref="IntroducedOn"/> tolerates an
    /// unknown key: a licence issued for a newer release may name features this build has never
    /// heard of, and a missing display name must not be the thing that takes down the page listing
    /// a customer's entitlements.
    /// </remarks>
    public static string DisplayName(string featureKey)
        => DisplayNames.TryGetValue(featureKey, out var name) ? name : featureKey;

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
