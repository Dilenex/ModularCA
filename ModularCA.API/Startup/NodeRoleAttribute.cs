namespace ModularCA.API.Startup;

/// <summary>
/// Names the node role a controller belongs to. Every controller carries exactly one, and
/// <see cref="NodeRoleConvention"/> removes the controllers of every role this process does
/// not run before routing exists, so an inactive role's paths are not there: 404, no
/// authentication challenge, no filter. The declaration is per controller and never per
/// route; a controller whose actions would belong to two roles is two controllers.
/// </summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class NodeRoleAttribute : Attribute
{
    /// <summary>Declares the controller as part of <paramref name="role"/>.</summary>
    /// <param name="role">
    /// Exactly one of <see cref="ProcessRole.Enrollment"/>, <see cref="ProcessRole.Validation"/>
    /// or <see cref="ProcessRole.Control"/>. The signer hosts no controller.
    /// </param>
    public NodeRoleAttribute(ProcessRole role)
    {
        Role = role;
    }

    /// <summary>The role the controller belongs to.</summary>
    public ProcessRole Role { get; }
}
