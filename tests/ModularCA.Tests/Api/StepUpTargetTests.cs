using System.Reflection;
using ModularCA.Shared.Models.Management;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Two sets of routes change a certificate's access list: by serial and by certificate id. Only
/// the serial routes asked for step-up, so the id routes did the same thing without it. The
/// step-up filter could only read its target from the route; the id routes carry theirs in the
/// body.
/// </summary>
public class StepUpTargetTests
{
    private const string FilterName = "ModularCA.API.Filters.RequireStepUpAttribute";
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.Management.AdminCertPermissionManagerController";

    private static string? Resolve(string? name, Dictionary<string, object?> route, Dictionary<string, object?> arguments)
        => (string?)ApiAssembly.TypeNamed(FilterName)
            .GetMethod("ResolveTarget", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [name, route, arguments]);

    [Fact]
    public void A_plain_name_is_read_from_the_route()
    {
        var route = new Dictionary<string, object?> { ["serial"] = "0A1B" };

        Assert.Equal("0A1B", Resolve("serial", route, []));
        Assert.Null(Resolve("id", route, []));
        Assert.Null(Resolve(null, route, []));
    }

    [Fact]
    public void A_dotted_name_is_read_from_the_bound_body()
    {
        var certId = Guid.NewGuid().ToString();
        var arguments = new Dictionary<string, object?> { ["request"] = new PermissionChangeRequest { CertId = certId, UserId = "u" } };

        Assert.Equal(certId, Resolve("request.CertId", [], arguments));
    }

    [Fact]
    public void A_body_that_is_missing_or_has_no_such_property_gives_no_target()
    {
        var arguments = new Dictionary<string, object?> { ["request"] = null, ["other"] = new PermissionChangeRequest() };

        Assert.Null(Resolve("request.CertId", [], arguments));
        Assert.Null(Resolve("absent.CertId", [], arguments));
        Assert.Null(Resolve("other.NoSuchProperty", [], arguments));
    }

    [Theory]
    [InlineData("SetBySerial", "serial")]
    [InlineData("RevokeBySerial", "serial")]
    [InlineData("GrantViewPermission", "request.CertId")]
    [InlineData("GrantManagePermission", "request.CertId")]
    [InlineData("DowngradePermission", "request.CertId")]
    [InlineData("RevokePermission", "request.CertId")]
    public void Every_route_that_changes_a_certificates_access_list_asks_for_step_up(string action, string target)
    {
        var filter = ApiAssembly.TypeNamed(ControllerName).GetMethod(action)!
            .GetCustomAttributes().SingleOrDefault(a => a.GetType().FullName == FilterName);

        Assert.NotNull(filter);
        Assert.Equal(ModularCA.Shared.Enums.StepUpOps.UpdateCertAcl, Field(filter!, "_operation"));
        Assert.Equal(target, Field(filter!, "_targetRouteParam"));
    }

    private static string? Field(object filter, string name)
        => (string?)filter.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(filter);
}
