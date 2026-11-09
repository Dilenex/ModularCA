using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The CA-scoped policy on the reissue endpoints authorizes the CA of the certificate, serial or
/// request named in the ROUTE. The actions used to act on the id in the BODY instead, so an
/// operator on one CA could reissue another CA's certificate in the same space by naming one of
/// their own in the path (bug hunt 2026-11, F1). The route is now the identity: a body that names
/// something else is refused before anything else runs, and an empty body id takes the route's.
/// </summary>
public sealed class ReissueRouteBindingTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminIssuanceController";

    /// <summary>
    /// A controller with no dependencies: the route check runs first, so a refusal never reaches
    /// one, and an accepted request fails on the first dependency it touches.
    /// </summary>
    private static (object Controller, MethodInfo Action) Action(string name)
    {
        var type = ApiAssembly.TypeNamed(ControllerName);
        return (RuntimeHelpers.GetUninitializedObject(type), type.GetMethod(name)!);
    }

    /// <summary>Invokes the action; a dependency failure after the route check comes back as null.</summary>
    private static async Task<IActionResult?> InvokeAsync(string name, params object?[] args)
    {
        var (controller, action) = Action(name);
        try
        {
            return await (Task<IActionResult>)action.Invoke(controller, args)!;
        }
        catch (Exception e) when (e is NullReferenceException or TargetInvocationException)
        {
            return null;
        }
    }

    private static void AssertRefused(IActionResult? result)
        => Assert.IsType<BadRequestObjectResult>(result);

    [Fact]
    public async Task A_cert_id_reissue_refuses_a_body_naming_another_certificate()
    {
        var route = Guid.NewGuid();
        var request = new ReissueCertificateRequestByCertId { CertificateId = Guid.NewGuid() };

        AssertRefused(await InvokeAsync("ReissueCertId", route, request, null));
    }

    [Fact]
    public async Task A_cert_id_reissue_acts_on_the_route_when_the_body_names_none()
    {
        var route = Guid.NewGuid();
        var request = new ReissueCertificateRequestByCertId();

        await InvokeAsync("ReissueCertId", route, request, null);

        Assert.Equal(route, request.CertificateId);
    }

    [Fact]
    public async Task A_serial_reissue_refuses_a_body_naming_another_serial()
    {
        var request = new ReissueCertificateRequestByCertSn { SerialNumber = "0BBB" };

        AssertRefused(await InvokeAsync("ReissueCertSn", "0AAA", request, null));
    }

    [Fact]
    public async Task A_serial_reissue_accepts_the_same_serial_in_either_case()
    {
        var request = new ReissueCertificateRequestByCertSn { SerialNumber = "0abc" };

        var result = await InvokeAsync("ReissueCertSn", "0ABC", request, null);

        Assert.IsNotType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task A_request_reissue_refuses_a_body_naming_another_request()
    {
        var route = Guid.NewGuid();
        var request = new ReissueCertificateRequestByCsrId { CsrId = Guid.NewGuid() };

        AssertRefused(await InvokeAsync("ReissueCsrId", route, request, null));
    }

    [Fact]
    public async Task A_request_reissue_acts_on_the_route_when_the_body_names_none()
    {
        var route = Guid.NewGuid();
        var request = new ReissueCertificateRequestByCsrId();

        await InvokeAsync("ReissueCsrId", route, request, null);

        Assert.Equal(route, request.CsrId);
    }

    [Theory]
    [InlineData("ReissueCertId", "certId")]
    [InlineData("ReissueCertSn", "serial")]
    [InlineData("ReissueCsrId", "csrId")]
    public void Each_reissue_action_binds_the_route_segment_the_policy_reads(string name, string parameter)
    {
        var (_, action) = Action(name);

        Assert.Contains(action.GetParameters(), p => p.Name == parameter);
    }
}
