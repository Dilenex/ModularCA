using System.Reflection;
using Xunit;

namespace ModularCA.Tests.Roles;

/// <summary>
/// Seals the role declaration: every controller the API declares carries exactly one
/// <c>[NodeRole]</c> naming exactly one of the three node roles, so the role convention has an
/// answer for each and an inactive role's controllers are the ones that go. The API is loaded
/// by reflection, as the signer seam test loads it.
/// </summary>
public sealed class NodeRoleArchitectureTests
{
    private const string RoleEnum = "ModularCA.API.Startup.ProcessRole";
    private const string Attribute = "ModularCA.API.Startup.NodeRoleAttribute";

    /// <summary>The API declares a large set of controllers; a walk that found few would be looking at the wrong thing.</summary>
    [Fact]
    public void The_walk_finds_the_controllers()
    {
        var controllers = ApiAssembly.ControllerTypes();
        Assert.True(controllers.Count >= 80, $"Only {controllers.Count} controllers were found; the walk is wrong.");
        Assert.Contains(controllers, c => c.Name == "OcspController");
        Assert.Contains(controllers, c => c.Name == "AcmeDirectoryController");
        Assert.Contains(controllers, c => c.Name == "AuthController");
    }

    [Fact]
    public void Every_controller_declares_exactly_one_node_role()
    {
        var attributeType = ApiAssembly.TypeNamed(Attribute);
        var roleProperty = attributeType.GetProperty("Role")!;
        var single = SingleNodeRoles();

        var failures = new List<string>();
        foreach (var controller in ApiAssembly.ControllerTypes())
        {
            var attributes = controller.GetCustomAttributes(attributeType, inherit: false);
            if (attributes.Length != 1)
            {
                failures.Add($"{controller.FullName}: {attributes.Length} [NodeRole] attributes");
                continue;
            }
            var role = roleProperty.GetValue(attributes[0])!;
            if (!single.Contains(Convert.ToInt32(role)))
                failures.Add($"{controller.FullName}: [NodeRole({role})] is not exactly one node role");
        }

        Assert.True(failures.Count == 0,
            "Every controller belongs to exactly one of enrollment, validation or control:\n  " + string.Join("\n  ", failures));
    }

    /// <summary>The numeric values of Enrollment, Validation and Control, read from the API's enum.</summary>
    internal static HashSet<int> SingleNodeRoles()
    {
        var roleType = ApiAssembly.TypeNamed(RoleEnum);
        return new[] { "Enrollment", "Validation", "Control" }
            .Select(name => Convert.ToInt32(Enum.Parse(roleType, name)))
            .ToHashSet();
    }

    /// <summary>The role a controller declares, as its enum name.</summary>
    internal static string DeclaredRoleName(Type controller)
    {
        var attributeType = ApiAssembly.TypeNamed(Attribute);
        var attribute = controller.GetCustomAttributes(attributeType, inherit: false).Single();
        var role = attributeType.GetProperty("Role")!.GetValue(attribute)!;
        return role.ToString()!;
    }
}
