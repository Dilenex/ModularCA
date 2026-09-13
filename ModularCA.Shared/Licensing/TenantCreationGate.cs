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
    /// How many tenants the free edition may have.
    /// </summary>
    /// <remarks>
    /// Bootstrap creates two on a fresh install — the system tenant and the operator's own
    /// organisation — so this is three more than the product needs to run, deliberately. Separating
    /// home, lab and a side project is three tenants and is nobody's commercial use of anything;
    /// setting the ceiling where bootstrap happens to land caught exactly the self-hosting operator
    /// the free edition exists for, which is the wrong person to send to a pricing page. An MSP
    /// running forty client organisations is still obviously outside it, and that is the boundary
    /// this is meant to draw.
    /// </remarks>
    public const int FreeEditionTenantCeiling = 5;

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
        const string unaffected =
            "Existing tenants are unaffected and continue to issue certificates normally.";

        // The entitlement is only consulted once the free ceiling is reached. Checking it first
        // would refuse an unlicensed installation its second tenant, which is what this gate used
        // to do — the ceiling existed only in the message and never in the decision.
        if (existingTenantCount >= FreeEditionTenantCeiling)
        {
            var refusal = FeatureGate.Require(
                entitlements, FeatureKeys.MultiTenancy,
                "Creating additional tenants",
                $"The free edition includes {FreeEditionTenantCeiling} tenants and this "
                + $"installation has {existingTenantCount}. {unaffected}");

            if (refusal is not null)
                return refusal;
        }

        // Entitlement satisfied, or not yet needed. A licence may still name its own ceiling, and
        // that one applies from the first tenant rather than from the free threshold.
        return FeatureGate.RequireHeadroom(
            entitlements, LicenseLimits.MaxTenants, existingTenantCount,
            "tenant", unaffected);
    }
}
