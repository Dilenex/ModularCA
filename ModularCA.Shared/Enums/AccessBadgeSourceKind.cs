namespace ModularCA.Shared.Entities;

/// <summary>Which kind of grant source an <see cref="AccessBadgeSourceEntity"/> names.</summary>
public enum AccessBadgeSourceKind
{
    /// <summary>Membership of a group (<see cref="CaGroupEntity"/>), with the group's grants and role assignments.</summary>
    Group = 1,
    /// <summary>A role assigned to the user directly (<see cref="RoleAssignmentEntity"/> with a user and no group).</summary>
    RoleAssignment = 2,
    /// <summary>A capability granted to the user directly (<see cref="UserCapabilityGrantEntity"/>).</summary>
    CapabilityGrant = 3,
}
