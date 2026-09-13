using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Models.Issuance;

/// <summary>
/// Everything an issuance form needs to state the effective validity ceiling for one
/// (signing profile, cert profile) pairing before the operator submits anything.
/// </summary>
/// <remarks>
/// <para>
/// The numbers alone are not enough. "Max 730 days" sends an operator to whichever screen they
/// guess first, and half the time it is the wrong one — they lengthen the certificate profile,
/// reload, and get 730 days again because the tenant was the binding layer all along. So each
/// layer's own answer is carried alongside the winner, which is what lets the UI say
/// "capped by tenant 'Acme Corp' (profile allows 3y)".
/// </para>
/// <para>
/// <see cref="TenantBehavior"/> travels with it because the consequence of exceeding the ceiling
/// differs per tenant: on Shorten the operator gets a shorter certificate and an advisory, on
/// Refuse they get nothing. A form that warns identically in both cases is wrong in one of them.
/// </para>
/// </remarks>
/// <param name="Resolution">The effective ceiling and which layer set it.</param>
/// <param name="SigningProfileName">The signing profile the ceiling was resolved for.</param>
/// <param name="CertProfileName">The certificate profile the ceiling was resolved for.</param>
/// <param name="CertProfileValidityPeriodMax">
/// The profile's configured ISO-8601 maximum as written, or null when it is unset — in which case
/// the effective value is <c>P1Y</c>, the default every issuance path applies.
/// </param>
/// <param name="IssuingCaName">The CA that would sign, or null when the signing profile has no CA.</param>
/// <param name="IssuingCaNotAfter">That CA certificate's own expiry, or null when unresolved.</param>
/// <param name="TenantName">The owning tenant, or null when the signing profile has no CA.</param>
/// <param name="TenantMaxValidityDays">The tenant's ceiling in days; 0 means unlimited.</param>
/// <param name="TenantBehavior">Whether exceeding the tenant ceiling shortens or refuses.</param>
/// <param name="TenantCeilingApplies">
/// False when this pairing is exempt from the tenant ceiling — a CA profile, which must never be
/// shortened. Infrastructure certificates are also exempt but are not issued through this form, so
/// that exemption cannot be determined from a profile pairing alone.
/// </param>
public sealed record ValidityCeilingPreflight(
    ValidityCeilingResolution Resolution,
    string SigningProfileName,
    string CertProfileName,
    string? CertProfileValidityPeriodMax,
    string? IssuingCaName,
    DateTime? IssuingCaNotAfter,
    string? TenantName,
    int TenantMaxValidityDays,
    ValidityCeilingBehavior TenantBehavior,
    bool TenantCeilingApplies);
