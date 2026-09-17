using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// A process with the ingress role alone hosts nothing of the node: the role convention
/// removes every controller, the scheduler is not hosted, and the role has its name in the
/// health order.
/// </summary>
public sealed class IngressRoleTests
{
    [Fact]
    public void Ingress_alone_keeps_no_controller()
    {
        var conventionType = ApiAssembly.TypeNamed("ModularCA.API.Startup.NodeRoleConvention");
        var convention = (IApplicationModelConvention)Activator.CreateInstance(conventionType, NodeRoleConventionTests.RoleValue("Ingress"))!;
        var application = new ApplicationModel();
        foreach (var controller in ApiAssembly.ControllerTypes())
            application.Controllers.Add(new ControllerModel(controller.GetTypeInfo(), controller.GetCustomAttributes(inherit: true)));

        convention.Apply(application);

        Assert.Empty(application.Controllers);
    }

    [Fact]
    public void Ingress_alone_hosts_no_scheduler_and_ingress_with_control_keeps_the_control_lease()
    {
        var activeRolesType = ApiAssembly.TypeNamed("ModularCA.API.Startup.ActiveRoles");
        var jobRoles = ApiAssembly.TypeNamed("ModularCA.API.Startup.SchedulerJobRoles");
        var ingressOnly = Activator.CreateInstance(activeRolesType, NodeRoleConventionTests.RoleValue("Ingress"))!;
        var ingressAndControl = Activator.CreateInstance(activeRolesType, NodeRoleConventionTests.RoleValue("Ingress,Control"))!;

        Assert.False((bool)IngressApi.Call(jobRoles, "RunsScheduler", ingressOnly)!);
        Assert.True((bool)IngressApi.Call(jobRoles, "RunsScheduler", ingressAndControl)!);
        Assert.Equal("scheduler", IngressApi.Call(jobRoles, "LeaseNameFor", ingressAndControl));
        Assert.False((bool)activeRolesType.GetProperty("HasAnyNodeRole")!.GetValue(ingressOnly)!);
        Assert.Equal(new[] { "ingress" }, (IReadOnlyList<string>)activeRolesType.GetProperty("Names")!.GetValue(ingressOnly)!);
    }

    [Fact]
    public void Every_role_names_the_ingress_last()
    {
        var activeRolesType = ApiAssembly.TypeNamed("ModularCA.API.Startup.ActiveRoles");
        var all = Activator.CreateInstance(activeRolesType, NodeRoleConventionTests.RoleValue("All"))!;
        Assert.Equal(new[] { "enrollment", "validation", "control", "signer", "ingress" }, (IReadOnlyList<string>)activeRolesType.GetProperty("Names")!.GetValue(all)!);
    }

    [Fact]
    public void The_listener_choice_is_by_arrival_and_by_what_the_cluster_defines()
    {
        var middleware = IngressApi.ListenerMiddleware;
        Assert.Equal("plain", IngressApi.Call(middleware, "ChooseDestination", true, true));
        Assert.Equal("https", IngressApi.Call(middleware, "ChooseDestination", true, false));
        Assert.Equal("https", IngressApi.Call(middleware, "ChooseDestination", false, true));
        Assert.Equal("https", IngressApi.Call(middleware, "ChooseDestination", false, false));
    }
}
