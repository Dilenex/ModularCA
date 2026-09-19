using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace ModularCA.API.Startup;

/// <summary>
/// The application-model convention that makes <see cref="NodeRoleAttribute"/> real: it removes
/// from the application model every controller whose role is not active in this process, so no
/// route, filter or authorization policy of that controller exists. A controller with no role,
/// or with a value that is not exactly one node role, stops startup: the alternative is a
/// controller that is either served by every role or by none, silently, and the architecture
/// test catches it before a build gets that far.
/// </summary>
public sealed class NodeRoleConvention : IApplicationModelConvention
{
    private readonly ProcessRole _active;

    /// <summary>Creates the convention for the roles this process runs.</summary>
    public NodeRoleConvention(ProcessRole active)
    {
        _active = active;
    }

    /// <summary>The roles this process runs.</summary>
    public ProcessRole Active => _active;

    /// <inheritdoc />
    public void Apply(ApplicationModel application)
    {
        ArgumentNullException.ThrowIfNull(application);
        for (var i = application.Controllers.Count - 1; i >= 0; i--)
        {
            var controller = application.Controllers[i];
            var role = RoleOf(controller.ControllerType);
            if (!_active.HasFlag(role))
                application.Controllers.RemoveAt(i);
        }
    }

    /// <summary>
    /// The role a controller type declares. Throws <see cref="InvalidOperationException"/>
    /// naming the type when it declares none, or one that is not a single node role.
    /// </summary>
    public static ProcessRole RoleOf(TypeInfo controllerType)
    {
        ArgumentNullException.ThrowIfNull(controllerType);
        var attribute = controllerType.GetCustomAttribute<NodeRoleAttribute>(inherit: false)
            ?? throw new InvalidOperationException(
                $"{controllerType.FullName} declares no [NodeRole]; every controller belongs to exactly one of enrollment, validation or control.");
        if (!ProcessRoles.IsSingleNodeRole(attribute.Role))
            throw new InvalidOperationException(
                $"{controllerType.FullName} declares [NodeRole({attribute.Role})]; a controller belongs to exactly one of enrollment, validation or control.");
        return attribute.Role;
    }
}
