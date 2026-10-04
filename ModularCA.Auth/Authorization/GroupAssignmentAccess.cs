using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Who may add a member to a group or remove one from it. The right is read at the group's own
/// scope, from every grant source and under the worn badge, so membership of an unrelated group
/// (a system auditor's, or an operator's on another CA) never counts.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>A system-super may change any group.</item>
/// <item>A system group needs system-super.</item>
/// <item>A CA group needs <c>group.manage</c> on its CA (held on the CA, space-wide in its space,
/// or at system scope).</item>
/// <item>A space-wide group needs <c>group.manage</c> space-wide in its space.</item>
/// <item>A non-system instance group (no CA, no space) needs a system administrator.</item>
/// </list>
/// The controlled-tier gate (ceremony for a privileged membership) applies on top of this.
/// </remarks>
public static class GroupAssignmentAccess
{
    /// <summary>
    /// Why <paramref name="callerId"/> may not change the memberships of <paramref name="group"/>,
    /// or null when they may. <paramref name="callerId"/> must be the request's own user, so the
    /// worn badge applies.
    /// </summary>
    public static async Task<string?> RefusalAsync(
        ICaGroupAuthorizationService auth, IControlledUserCeremonyService controlled, Guid callerId, CaGroupEntity group)
    {
        if (await controlled.IsSuperAsync(callerId))
            return null;

        if (group.IsSystemGroup)
            return "Modifying system group memberships requires system-super.";

        if (group.CertificateAuthorityId is Guid caId)
            return await auth.HasCaCapabilityAsync(callerId, caId, Capabilities.GroupManage)
                ? null
                : "You need group.manage on this group's CA to manage its memberships.";

        if (group.SpaceId is Guid spaceId)
            return await auth.HasSpaceCapabilityAsync(callerId, spaceId, Capabilities.GroupManage)
                ? null
                : "You need group.manage across this group's space to manage its memberships.";

        return await auth.IsSystemAdminAsync(callerId)
            ? null
            : "This instance group's memberships can only be managed by a system administrator.";
    }
}
