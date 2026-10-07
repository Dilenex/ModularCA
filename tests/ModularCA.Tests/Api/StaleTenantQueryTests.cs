using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// A client built before 0.4.0 sends <c>?tenantId=</c>. MVC ignores a key no parameter binds, so
/// on the actions that renamed it to <c>spaceId</c> or <c>chainId</c> a stale call would read as
/// no filter, and a chain restart would restart the instance chain. Each such action carries
/// <c>RefuseQueryKey</c>, which answers 400 naming the key and its replacement.
/// </summary>
public sealed class StaleTenantQueryTests
{
    private const string Attribute = "ModularCA.API.Filters.RefuseQueryKeyAttribute";
    private const string Admin = "ModularCA.API.Controllers.v1.Admin.";

    /// <summary>The actions whose query key was renamed from <c>tenantId</c> in 0.4.0, and the new key.</summary>
    public static TheoryData<string, string, string> RenamedActions() => new()
    {
        { Admin + "AdminAuditController", "GetAuditLogs", "spaceId" },
        { Admin + "AdminAuditController", "VerifyHashChain", "chainId" },
        { Admin + "AdminAuditController", "RestartHashChain", "chainId" },
        { Admin + "AdminCertificateController", "ListCertificates", "spaceId" },
        { Admin + "AdminCertificateController", "ExpiryHistogram", "spaceId" },
        { Admin + "AdminCertificateController", "GetHealthSummary", "spaceId" },
        { Admin + "AdminCertificateController", "GetLifecycleSummary", "spaceId" },
        { Admin + "AdminCertificateTemplateController", "GetAll", "spaceId" },
        { Admin + "AdminCertProfileController", "GetAll", "spaceId" },
        { Admin + "AdminCertSignRequestController", "RetrievePendingRequests", "spaceId" },
    };

    private static MethodInfo Action(string controller, string action)
        => Assert.Single(ApiAssembly.TypeNamed(controller).GetMethods(BindingFlags.Public | BindingFlags.Instance), m => m.Name == action);

    private static ActionFilterAttribute Filter(string key, string replacement)
        => (ActionFilterAttribute)Activator.CreateInstance(ApiAssembly.TypeNamed(Attribute), key, replacement)!;

    private static ActionExecutingContext Request(string query)
    {
        var http = new DefaultHttpContext();
        http.Request.QueryString = new QueryString(query);
        return new ActionExecutingContext(new ActionContext(http, new RouteData(), new ActionDescriptor()),
            new List<IFilterMetadata>(), new Dictionary<string, object?>(), controller: new object());
    }

    private static string Prop(object attribute, string name) => (string)attribute.GetType().GetProperty(name)!.GetValue(attribute)!;

    [Theory]
    [MemberData(nameof(RenamedActions))]
    public void A_renamed_action_binds_the_new_key_and_refuses_the_old_one(string controller, string action, string replacement)
    {
        var method = Action(controller, action);
        Assert.Contains(method.GetParameters(), p => p.Name == replacement && p.GetCustomAttribute<FromQueryAttribute>() != null);
        var refusal = Assert.Single(method.GetCustomAttributes().Where(a => a.GetType().FullName == Attribute));
        Assert.Equal("tenantId", Prop(refusal, "Key"));
        Assert.Equal(replacement, Prop(refusal, "Replacement"));

        var context = Request("?tenantId=" + Guid.NewGuid());
        ((IActionFilter)refusal).OnActionExecuting(context);
        Assert.IsType<BadRequestObjectResult>(context.Result);
    }

    [Fact]
    public void Every_action_binding_spaceId_or_chainId_from_the_query_is_listed()
    {
        var binding = ApiAssembly.ControllerTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => m.GetParameters().Any(p => p.Name is "spaceId" or "chainId" && p.GetCustomAttribute<FromQueryAttribute>() != null))
                .Select(m => $"{t.FullName}.{m.Name}"))
            .Order().ToList();
        var listed = RenamedActions().Select(r => $"{r[0]}.{r[1]}").Order().ToList();
        Assert.Equal(listed, binding);
    }

    [Theory]
    [InlineData("?tenantId=6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60")]
    [InlineData("?TenantId=6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60")]
    [InlineData("?limit=5&tenantId=")]
    [InlineData("?tenantId")]
    public void The_old_key_is_refused_with_a_problem_naming_it_and_its_replacement(string query)
    {
        var context = Request(query);
        Filter("tenantId", "chainId").OnActionExecuting(context);

        var bad = Assert.IsType<BadRequestObjectResult>(context.Result);
        Assert.Equal(400, bad.StatusCode);
        var problem = Assert.IsType<ValidationProblemDetails>(bad.Value);
        Assert.Equal(400, problem.Status);
        Assert.Contains("'tenantId'", problem.Detail);
        Assert.Contains("'chainId'", problem.Detail);
        Assert.Equal(problem.Detail, Assert.Single(problem.Errors["tenantId"]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("?chainId=6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60")]
    [InlineData("?limit=5&tenant=x&tenantIds=y")]
    public void A_request_without_the_old_key_passes(string query)
    {
        var context = Request(query);
        Filter("tenantId", "chainId").OnActionExecuting(context);
        Assert.Null(context.Result);
    }
}
