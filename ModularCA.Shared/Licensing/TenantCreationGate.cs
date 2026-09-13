using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Shared.Licensing;

/// <summary>
/// Decides whether this installation may create another tenant.
/// </summary>
/// <remarks>
/// <para>
/// Multi-tenancy cannot be a separate module — <c>TenantId</c> reaches 786 sites across 71
/// files and sits inside the authorisation model, not merely the schema — so the code ships in
/// every edition and the licence gates the one thing that can be gated cleanly: creating a new
/// tenant. There is exactly one runtime creation site, which is what makes this viable at all.
/// </para>
/// <para>
/// Pulled out of the controller so it can be tested. The test project deliberately does not
/// reference the API assembly, and a licensing decision buried in an action method would be
/// reachable only through an HTTP test this codebase has no harness for.
/// </para>
/// <para>
/// This gate ships in the open-source core, so it can be removed from a fork. That is
/// understood and accepted: enforcement here is honour-system, and the protection for a
/// self-hosted product is the licence agreement and the audit record, not the <c>if</c>
/// statement. Its job is to make the terms visible and the refusal explainable, not to be
/// unbypassable.
/// </para>
/// </remarks>
public static class TenantCreationGate
{
    /// <summary>
    /// Tenants the bootstrap creates on a fresh install — the system tenant and the operator's
    /// own organisation. The free edition keeps both; it simply cannot add a third.
    /// </summary>
    public const int FreeEditionTenantCeiling = 2;

    /// <summary>
    /// Returns the refusal to throw, or <see langword="null"/> when creation may proceed.
    /// </summary>
    /// <remarks>
    /// Returns rather than throws so the caller can write its audit record before the exception
    /// leaves the action. A refused attempt to exceed a licence limit is exactly the event a
    /// licence dispute later turns on, and it must be recorded whether or not the operator ever
    /// sees the message.
    /// </remarks>
    /// <param name="entitlements">This installation's entitlements.</param>
    /// <param name="existingTenantCount">How many tenants already exist.</param>
    public static LicensingException? Evaluate(IEntitlementService entitlements, int existingTenantCount)
    {
        // Entitlement before headroom. Telling an operator their tenant limit is reached, when the
        // actual position is that they have no multi-tenancy entitlement at all, sends them to
        // negotiate a bigger number for something they have not bought.
        const string unaffected =
            "Existing tenants are unaffected and continue to issue certificates normally.";

        return FeatureGate.Require(
                   entitlements, FeatureKeys.MultiTenancy,
                   "Creating additional tenants",
                   $"The {FreeEditionTenantCeiling} tenants created at installation are unaffected "
                   + "and continue to issue certificates normally.")
               ?? FeatureGate.RequireHeadroom(
                   entitlements, LicenseLimits.MaxTenants, existingTenantCount,
                   "tenant", unaffected);
    }
}
