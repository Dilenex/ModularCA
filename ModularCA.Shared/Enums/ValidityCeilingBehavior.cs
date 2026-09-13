namespace ModularCA.Shared.Enums;

/// <summary>
/// What a tenant does when a certificate request asks for longer validity than
/// <c>TenantEntity.MaxValidityDays</c> permits.
/// </summary>
/// <remarks>
/// <para>
/// The ceiling shipped as shorten-only, and shortening stays the default: an operator who sets a
/// ceiling and nothing else keeps exactly the behaviour they already had. <see cref="Refuse"/>
/// exists for installations where a silently shortened certificate is worse than a failed
/// request — a device provisioned with a two-year identity when the fleet management system was
/// told to expect five will come back as an outage two years later, long after anyone remembers
/// the <c>MCA-ISS-004</c> advisory scrolled past.
/// </para>
/// <para>
/// <b>Refuse is deliberately asymmetric.</b> It governs interactive and admin issuance only.
/// ACME, EST, SCEP, CMP and the auto-renewal scheduler derive their requested expiry from the
/// certificate profile with no knowledge of the tenant, so refusing there would fail every
/// enrollment and every renewal whose profile out-reaches its tenant, over a condition the
/// enrolling client can neither see nor fix — and would take a working fleet offline the moment
/// an operator flipped a tenant setting. Those paths always shorten. The asymmetry is enforced at
/// the issuance seam by <see cref="ValidityCeilingEnforcement"/>, not by this value.
/// </para>
/// </remarks>
public enum ValidityCeilingBehavior
{
    /// <summary>
    /// Issue the certificate with its validity shortened to the tenant ceiling and attach the
    /// <c>MCA-ISS-004</c> advisory. The behaviour every tenant has by default, and the only
    /// behaviour the protocol and renewal paths ever use.
    /// </summary>
    Shorten = 0,

    /// <summary>
    /// Refuse an interactive or admin request that exceeds the ceiling, with <c>MCA-ISS-005</c>,
    /// instead of quietly issuing something shorter than was asked for. Protocol enrollments and
    /// scheduled renewals still shorten.
    /// </summary>
    Refuse = 1,
}
