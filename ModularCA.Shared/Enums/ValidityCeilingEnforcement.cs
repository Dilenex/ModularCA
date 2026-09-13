namespace ModularCA.Shared.Enums;

/// <summary>
/// How much authority a particular issuance call site grants the tenant's
/// <see cref="ValidityCeilingBehavior"/>. This is the seam that keeps
/// <see cref="ValidityCeilingBehavior.Refuse"/> away from the enrollment protocols.
/// </summary>
/// <remarks>
/// <para>
/// Only an operator who can see the tenant ceiling, and change either it or their request, should
/// ever be refused by it. An ACME client cannot do either: it asks for what the certificate
/// profile allows, has no way to discover the tenant's ceiling, and no way to act on a refusal if
/// it did. The same is true of EST, SCEP, CMP, the auto-renewal job and the Web TLS renewal job —
/// a refusal on any of them turns an operator's tenant setting into a fleet-wide outage.
/// </para>
/// <para>
/// So the decision is made by the <em>caller</em>, not by the tenant record, and the safe reading
/// is the default: a new call site that says nothing gets <see cref="AlwaysShorten"/> and cannot
/// start refusing by omission. The riskier reading has to be typed out, which is the whole point
/// of spelling it as a named enum rather than a <c>bool honourTenantPolicy</c> — at a call site,
/// <c>ValidityCeilingEnforcement.HonourTenantPolicy</c> says what it does, whereas
/// <c>true</c> says nothing and <c>false</c> is easy to get backwards.
/// </para>
/// </remarks>
public enum ValidityCeilingEnforcement
{
    /// <summary>
    /// Shorten to the tenant ceiling and attach <c>MCA-ISS-004</c>, whatever the tenant's
    /// configured behaviour says. The default, and the only correct value for any path whose
    /// caller cannot see or change the ceiling.
    /// </summary>
    AlwaysShorten = 0,

    /// <summary>
    /// Let the tenant's <see cref="ValidityCeilingBehavior"/> decide, which means a tenant set to
    /// <see cref="ValidityCeilingBehavior.Refuse"/> refuses the request with <c>MCA-ISS-005</c>.
    /// Reserved for interactive and admin issuance, where a human sees the refusal and can act on
    /// it. Note that this still shortens for every tenant left on the default behaviour.
    /// </summary>
    HonourTenantPolicy = 1,
}
