using System.Text.Json.Serialization;

namespace ModularCA.Shared.Licensing;

/// <summary>
/// The claims inside a signed ModularCA licence.
/// </summary>
/// <remarks>
/// <para>
/// Note what is deliberately absent: there is no expiry field that disables anything. An
/// entitlement is perpetual — a customer who bought a feature keeps it, in every future build,
/// forever. <see cref="MaintenanceThrough"/> decides which features they may use, never whether
/// the software runs. Leaving the field out of the model entirely is the cheapest way to stop
/// someone adding a kill switch later because it seemed tidy.
/// </para>
/// <para>
/// For a certificate authority the stakes make that more than a preference. Every customer's
/// licence would lapse on its own schedule, and a CA that stops signing takes every service
/// depending on it down with it. Issuance, CRL and OCSP must continue regardless of licence
/// state; what a lapse freezes is new configuration of paid features.
/// </para>
/// </remarks>
public sealed class LicenseClaims
{
    /// <summary>Human-readable name of the organisation the licence was issued to.</summary>
    [JsonPropertyName("licensee")]
    public string Licensee { get; init; } = string.Empty;

    /// <summary>Opaque identifier for this licence, for support and audit correlation.</summary>
    [JsonPropertyName("licenseId")]
    public string LicenseId { get; init; } = string.Empty;

    /// <summary>ISO date the licence was issued. Informational; nothing is gated on it.</summary>
    [JsonPropertyName("issuedOn")]
    public DateOnly IssuedOn { get; init; }

    /// <summary>
    /// The last date whose features this licence covers. Features introduced on or before it
    /// remain available in every future build; later ones need a renewal.
    /// </summary>
    [JsonPropertyName("maintenanceThrough")]
    public DateOnly MaintenanceThrough { get; init; }

    /// <summary>Feature keys from <see cref="FeatureKeys"/> this licence grants, perpetually.</summary>
    [JsonPropertyName("entitlements")]
    public IReadOnlyList<string> Entitlements { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Numeric ceilings, keyed by limit name — currently <c>maxTenants</c>. A limit that is
    /// absent means the entitlement carries no ceiling.
    /// </summary>
    [JsonPropertyName("limits")]
    public IReadOnlyDictionary<string, int> Limits { get; init; } =
        new Dictionary<string, int>(StringComparer.Ordinal);
}

/// <summary>Well-known keys for <see cref="LicenseClaims.Limits"/>.</summary>
public static class LicenseLimits
{
    /// <summary>Maximum number of tenants that may exist. Counts, never deletes.</summary>
    public const string MaxTenants = "maxTenants";
}

/// <summary>
/// Why a licence could not be used, when it could not be.
/// </summary>
/// <remarks>
/// Every one of these resolves to "run as the free edition", never to "refuse to start". A CA
/// that will not boot because a licence file is malformed is a worse outage than one running
/// without its paid features.
/// </remarks>
public enum LicenseStatus
{
    /// <summary>No licence file was configured. The free edition; not an error.</summary>
    Absent,

    /// <summary>Signature verified against the pinned key.</summary>
    Valid,

    /// <summary>The file was not in the expected two-part form, or its JSON did not parse.</summary>
    Malformed,

    /// <summary>Well-formed, but the signature did not verify against the pinned key.</summary>
    SignatureInvalid,
}

/// <summary>
/// The outcome of loading a licence: its status, and its claims when it verified.
/// </summary>
/// <param name="Status">Whether the licence verified, and if not, why.</param>
/// <param name="Claims">The claims, present only when <paramref name="Status"/> is Valid.</param>
/// <param name="Diagnostic">Operator-facing explanation, for the log and the admin UI.</param>
public sealed record LicenseLoadResult(
    LicenseStatus Status,
    LicenseClaims? Claims,
    string Diagnostic)
{
    /// <summary>True when the licence verified and its claims may be trusted.</summary>
    public bool IsValid => Status == LicenseStatus.Valid && Claims is not null;

    /// <summary>The free edition: no licence configured.</summary>
    public static LicenseLoadResult None { get; } =
        new(LicenseStatus.Absent, null, "No licence configured; running the free edition.");
}
