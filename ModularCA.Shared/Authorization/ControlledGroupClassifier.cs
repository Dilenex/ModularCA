using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Authorization;

/// <summary>
/// Structural classification of a <see cref="CaGroupEntity"/> (template and system flags) into the
/// controlled-user tier its membership confers. Structure alone misses a group that was given a
/// controlled capability through a grant or role, so enforcement uses
/// <c>ModularCA.Core.Authorization.ControlledTierResolver.ClassifyGroupAsync</c>, which takes the
/// covering tier of this and the group's capabilities; this synchronous form is its structural floor.
/// </summary>
public static class ControlledGroupClassifier
{
    /// <summary>
    /// The tier membership in <paramref name="group"/> confers, or <c>null</c> when the group is not
    /// privilege-controlled: system-super and system groups map to the system tiers, a CA
    /// <c>Administrator</c> group to CA-admin, tenant-wide <c>Administrator</c>/<c>Operator</c>
    /// groups to the org tiers. CA operator groups are uncontrolled. A tenant-less, CA-less,
    /// non-system Administrator or Operator group is classified at the system-admin tier, so
    /// changing it needs a system-tier dominator; it confers no system capability.
    /// </summary>
    public static ControlledTier? Classify(CaGroupEntity group)
    {
        if (group.IsSystemTierSuper)
            return new ControlledTier(ControlledTierLevel.SystemSuper, null);
        if (group.IsSystemGroup)
            return new ControlledTier(ControlledTierLevel.SystemAdmin, null);

        var isAdmin = string.Equals(group.TemplateName, "Administrator", StringComparison.OrdinalIgnoreCase);
        var isOperator = string.Equals(group.TemplateName, "Operator", StringComparison.OrdinalIgnoreCase);

        if (group.CertificateAuthorityId != null)
            return isAdmin
                ? new ControlledTier(ControlledTierLevel.CaAdmin, group.CertificateAuthorityId) { TenantId = group.TenantId }
                : null;

        if (!isAdmin && !isOperator) return null;
        // A non-system group with neither tenant nor CA should not exist; gate it at the system tier.
        if (group.TenantId == null) return new ControlledTier(ControlledTierLevel.SystemAdmin, null);
        if (isAdmin) return new ControlledTier(ControlledTierLevel.OrgAdmin, null) { TenantId = group.TenantId };
        return new ControlledTier(ControlledTierLevel.OrgOperator, null) { TenantId = group.TenantId };
    }
}
