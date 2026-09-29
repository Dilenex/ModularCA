using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Shared.Licensing;

/// <summary>
/// Decides whether this installation may create another tenant: first single-organisation mode
/// (<see cref="EvaluateOrganizationMode"/>), then the licence (<see cref="Evaluate"/>).
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
    /// How many tenants (organisations) the free edition may have.
    /// </summary>
    /// <remarks>
    /// Bootstrap creates one on a fresh install — the operator's own organisation; since 0.4.0
    /// there is no system tenant to count — so this is three more than the product needs to run,
    /// deliberately, the same three the ceiling of five allowed when the system tenant counted.
    /// Separating home, lab and a side project is three tenants and is nobody's commercial use of
    /// anything; setting the ceiling where bootstrap happens to land caught exactly the
    /// self-hosting operator the free edition exists for, which is the wrong person to send to a
    /// pricing page. An MSP running forty client organisations is still obviously outside it, and
    /// that is the boundary this is meant to draw.
    /// </remarks>
    public const int FreeEditionTenantCeiling = 4;

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

    /// <summary>
    /// Single-organisation mode: returns the refusal to throw when an organisation tenant already
    /// exists and <paramref name="allowMultipleOrganizations"/> is false, or <see langword="null"/>
    /// when creation may proceed. Evaluated before <see cref="Evaluate"/>; it is configuration,
    /// not licensing. A disabled organisation counts, because disabling is what the tenant delete
    /// endpoint does; only a soft-deleted one does not.
    /// </summary>
    /// <param name="allowMultipleOrganizations"><c>Features.AllowMultipleOrganizations</c> from config.yaml.</param>
    /// <param name="existingOrganizationCount">How many non-deleted tenants already exist, disabled ones included.</param>
    /// <param name="blockingOrganization">The name of an existing organisation, for the message, or null.</param>
    /// <param name="blockingOrganizationDisabled">Whether that organisation is disabled.</param>
    public static ConfigurationValidationException? EvaluateOrganizationMode(
        bool allowMultipleOrganizations, int existingOrganizationCount,
        string? blockingOrganization = null, bool blockingOrganizationDisabled = false)
    {
        if (allowMultipleOrganizations || existingOrganizationCount < 1)
            return null;

        var existing = blockingOrganization is null
            ? "an organisation tenant"
            : $"organisation tenant '{blockingOrganization}'"
              + (blockingOrganizationDisabled ? " (disabled; a disabled organisation still counts)" : "");
        return new ConfigurationValidationException(
            $"This instance is in single-organisation mode and already has {existing}. "
            + "A further organisation is meant to be a further instance.",
            ErrorCodes.MultipleOrganizationsDisabled,
            "To hold several organisations in this instance: stop the service, set "
            + "Features.AllowMultipleOrganizations: true in config.yaml, then start it again. "
            + "Stop the service before editing config.yaml, or a running node may write its own copy over the edit.");
    }

    /// <summary>
    /// The warning the control role logs at startup when single-organisation mode is on but the
    /// instance already holds more than one organisation, or <see langword="null"/> when there is
    /// nothing to say. The mode refuses a new organisation; it never removes existing ones.
    /// </summary>
    /// <param name="allowMultipleOrganizations"><c>Features.AllowMultipleOrganizations</c> from config.yaml.</param>
    /// <param name="organizations">The non-deleted tenants, disabled ones included.</param>
    public static string? SingleOrganizationStartupWarning(
        bool allowMultipleOrganizations, IReadOnlyList<(string Name, bool IsEnabled)> organizations)
    {
        if (allowMultipleOrganizations || organizations.Count <= 1)
            return null;

        var listed = string.Join(", ", organizations.Select(o => o.IsEnabled ? $"'{o.Name}'" : $"'{o.Name}' (disabled)"));
        return $"Single-organisation mode (Features.AllowMultipleOrganizations: false), but this instance holds "
            + $"{organizations.Count} organisations: {listed}. They keep working; creating another is refused "
            + $"({ErrorCodes.MultipleOrganizationsDisabled}). To keep several deliberately, stop the service, set "
            + "Features.AllowMultipleOrganizations: true in config.yaml and start it.";
    }
}
