using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Xunit;

namespace ModularCA.Tests.Roles;

/// <summary>
/// Runs the real <c>NodeRoleConvention</c> over the real controller types with a chosen active
/// role set and checks the survivors: exactly the controllers declaring an active role remain,
/// and the named ones land where the design puts them. A convention that kept an inactive
/// role's controller, or a controller declared under the wrong role, fails here.
/// </summary>
public sealed class NodeRoleConventionTests
{
    private const string Convention = "ModularCA.API.Startup.NodeRoleConvention";
    private const string RoleEnum = "ModularCA.API.Startup.ProcessRole";

    /// <summary>The role sets a process can be started with, as the enum names they combine.</summary>
    public static IEnumerable<object[]> RoleSets()
    {
        yield return new object[] { "Validation" };
        yield return new object[] { "Enrollment" };
        yield return new object[] { "Control" };
        yield return new object[] { "Enrollment,Validation" };
        yield return new object[] { "Enrollment,Control" };
        yield return new object[] { "Validation,Control" };
        yield return new object[] { "Node" };
        yield return new object[] { "All" };
    }

    [Theory]
    [MemberData(nameof(RoleSets))]
    public void The_convention_keeps_exactly_the_controllers_of_the_active_roles(string activeSet)
    {
        var controllers = ApiAssembly.ControllerTypes();
        var survivors = Survivors(activeSet, controllers);

        var active = ActiveSingleRoles(activeSet);
        var expected = controllers
            .Where(c => active.Contains(NodeRoleArchitectureTests.DeclaredRoleName(c)))
            .Select(c => c.FullName!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(expected, survivors);
        Assert.NotEmpty(survivors);
    }

    [Fact]
    public void Every_node_role_together_keeps_every_controller()
    {
        var controllers = ApiAssembly.ControllerTypes();
        Assert.Equal(controllers.Count, Survivors("Node", controllers).Count);
        Assert.Equal(controllers.Count, Survivors("All", controllers).Count);
    }

    [Fact]
    public void Validation_alone_is_distribution_only()
    {
        var survivors = Survivors("Validation", ApiAssembly.ControllerTypes()).Select(Short).ToHashSet();
        Assert.Superset(new HashSet<string>
        {
            "OcspController", "PublicCrlController", "PublicCaCertController", "PublicShortUrlController", "PublicSshController",
        }, survivors);
        Assert.DoesNotContain("AcmeDirectoryController", survivors);
        Assert.DoesNotContain("EstController", survivors);
        Assert.DoesNotContain("TsaController", survivors);
        Assert.DoesNotContain("AuthController", survivors);
        Assert.DoesNotContain("SetupController", survivors);
        Assert.DoesNotContain("AdminCaController", survivors);
        Assert.Equal(5, survivors.Count);
    }

    [Fact]
    public void Enrollment_alone_is_the_protocols_only()
    {
        var survivors = Survivors("Enrollment", ApiAssembly.ControllerTypes()).Select(Short).ToHashSet();
        Assert.Superset(new HashSet<string>
        {
            "AcmeDirectoryController", "AcmeAccountController", "AcmeOrderController", "AcmeChallengeController",
            "EstController", "ScepController", "CmpController", "MsaeController", "TsaController",
            "PublicEnrollmentController", "PublicTemplateController", "CertManagerController", "InfraController",
        }, survivors);
        Assert.DoesNotContain("OcspController", survivors);
        Assert.DoesNotContain("PublicCrlController", survivors);
        Assert.DoesNotContain("AuthController", survivors);
        Assert.DoesNotContain("AdminIssuanceController", survivors);
        Assert.DoesNotContain("SetupController", survivors);
        Assert.Equal(13, survivors.Count);
    }

    [Fact]
    public void Control_alone_is_the_console_and_its_api()
    {
        var survivors = Survivors("Control", ApiAssembly.ControllerTypes()).Select(Short).ToHashSet();
        Assert.Superset(new HashSet<string>
        {
            "AuthController", "MfaStepUpController", "MtlsController", "TotpController", "WebAuthnController",
            "SetupController", "VersionController", "MeController", "AccountManagerController",
            "AdminCaController", "AdminIssuanceController", "AdminSchedulerController", "AdminBackupController",
            "UserCertificateController", "PublicInfoController", "CspReportController",
        }, survivors);
        Assert.DoesNotContain("OcspController", survivors);
        Assert.DoesNotContain("AcmeDirectoryController", survivors);
        Assert.DoesNotContain("TsaController", survivors);
        Assert.All(survivors, name => Assert.False(name.StartsWith("Acme", StringComparison.Ordinal), name));
    }

    [Fact]
    public void A_controller_without_a_role_stops_the_convention()
    {
        var convention = NewConvention("All");
        var application = new ApplicationModel();
        // A type with no [NodeRole]: the convention refuses rather than guessing.
        application.Controllers.Add(new ControllerModel(typeof(UnlabeledController).GetTypeInfo(), Array.Empty<object>()));

        var ex = Assert.Throws<InvalidOperationException>(() => convention.Apply(application));
        Assert.Contains(nameof(UnlabeledController), ex.Message);
        Assert.Contains("[NodeRole]", ex.Message);
    }

    /// <summary>A controller type with no role, for the refusal test.</summary>
    private sealed class UnlabeledController : Microsoft.AspNetCore.Mvc.ControllerBase
    {
    }

    /// <summary>Applies the real convention with the named active set and returns the surviving controllers' full names, sorted.</summary>
    private static List<string> Survivors(string activeSet, IReadOnlyList<Type> controllers)
    {
        var convention = NewConvention(activeSet);
        var application = new ApplicationModel();
        foreach (var controller in controllers)
            application.Controllers.Add(new ControllerModel(controller.GetTypeInfo(), controller.GetCustomAttributes(inherit: true)));

        convention.Apply(application);
        return application.Controllers
            .Select(c => c.ControllerType.FullName!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();
    }

    private static IApplicationModelConvention NewConvention(string activeSet)
    {
        var conventionType = ApiAssembly.TypeNamed(Convention);
        var instance = Activator.CreateInstance(conventionType, RoleValue(activeSet));
        return Assert.IsAssignableFrom<IApplicationModelConvention>(instance);
    }

    /// <summary>The enum value for a comma-separated list of ProcessRole names.</summary>
    internal static object RoleValue(string names)
    {
        var roleType = ApiAssembly.TypeNamed(RoleEnum);
        var combined = 0;
        foreach (var name in names.Split(','))
            combined |= Convert.ToInt32(Enum.Parse(roleType, name.Trim()));
        return Enum.ToObject(roleType, combined);
    }

    /// <summary>The single node roles a role-set name expands to.</summary>
    private static HashSet<string> ActiveSingleRoles(string names)
    {
        var combined = Convert.ToInt32(RoleValue(names));
        var roleType = ApiAssembly.TypeNamed(RoleEnum);
        return new[] { "Enrollment", "Validation", "Control" }
            .Where(n => (combined & Convert.ToInt32(Enum.Parse(roleType, n))) != 0)
            .ToHashSet();
    }

    private static string Short(string fullName) => fullName[(fullName.LastIndexOf('.') + 1)..];
}
