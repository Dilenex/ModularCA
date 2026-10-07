using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Authorization;

/// <summary>
/// Shared helper for assigning a built-in role to a group. Creates both a
/// <see cref="RoleAssignmentEntity"/> and direct <see cref="CapabilityGrantEntity"/>
/// rows (for backward compatibility with existing capability-grant queries).
/// Used by both bootstrap seeding and runtime group/CA creation.
/// </summary>
public static class RoleAssignmentHelper
{
    /// <summary>
    /// Assigns a built-in role to a group by template name ("Administrator", "Operator",
    /// "Auditor", "Requester"). Creates a <see cref="RoleAssignmentEntity"/> linking the
    /// role to the group, and seeds direct <see cref="CapabilityGrantEntity"/> rows for
    /// backward compatibility. Calls <c>db.SaveChanges()</c> at the end.
    /// </summary>
    /// <param name="db">The database context.</param>
    /// <param name="group">The group to assign the role to.</param>
    /// <param name="templateName">One of "Administrator", "Operator", "Auditor", "Requester".</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the built-in role for <paramref name="templateName"/> does not exist.
    /// Call <c>SeedBuiltInRoles</c> during bootstrap before using this method.
    /// </exception>
    public static void AssignBuiltInRoleToGroup(ModularCADbContext db, CaGroupEntity group, string templateName)
    {
        var role = db.Roles.FirstOrDefault(r => r.Name == templateName && r.IsBuiltIn);
        if (role == null)
            throw new InvalidOperationException($"Built-in role '{templateName}' not found. Call SeedBuiltInRoles first.");

        // Create role assignment if not already present
        if (!db.RoleAssignments.Any(ra => ra.RoleId == role.Id && ra.GroupId == group.Id))
        {
            db.RoleAssignments.Add(new RoleAssignmentEntity
            {
                RoleId = role.Id,
                GroupId = group.Id,
                SpaceId = group.SpaceId,
                CertificateAuthorityId = group.CertificateAuthorityId,
            });
        }

        // Also seed direct capability grants for backward compatibility
        var capabilities = templateName switch
        {
            "Administrator" => Capabilities.AdministratorTemplate,
            "Operator" => Capabilities.OperatorTemplate,
            "Auditor" => Capabilities.AuditorTemplate,
            _ => Capabilities.RequesterTemplate,
        };
        var existingCaps = db.CapabilityGrants
            .Where(g => g.GroupId == group.Id)
            .Select(g => g.Capability)
            .ToHashSet();
        foreach (var cap in capabilities)
        {
            if (!existingCaps.Contains(cap))
                db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = group.Id, Capability = cap });
        }
        db.SaveChanges();
    }
}
