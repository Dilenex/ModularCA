using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The admin API says space, with no alias for the pre-0.4.0 tenant routes: the new paths resolve
/// to an action, the old ones resolve to none (404), and no route, route value or query
/// parameter is named after a tenant. Routes are read from the built API's attributes.
/// </summary>
public sealed class SpaceRouteTests
{
    private sealed record Route(string Method, string Template, Regex Pattern, MethodInfo Action);

    private static readonly Lazy<IReadOnlyList<Route>> All = new(Load);

    private static IReadOnlyList<Route> Load()
    {
        var routes = new List<Route>();
        foreach (var controller in ApiAssembly.ControllerTypes())
        {
            var prefixes = controller.GetCustomAttributes<RouteAttribute>(true).Select(r => r.Template).DefaultIfEmpty("").ToList();
            foreach (var action in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                foreach (var http in action.GetCustomAttributes<HttpMethodAttribute>(true))
                {
                    foreach (var prefix in prefixes)
                    {
                        var template = string.IsNullOrEmpty(http.Template) ? prefix
                            : http.Template.StartsWith('/') || http.Template.StartsWith("~/") ? http.Template.TrimStart('~')
                            : $"{prefix.TrimEnd('/')}/{http.Template}";
                        template = "/" + template.Trim('/');
                        foreach (var method in http.HttpMethods)
                            routes.Add(new Route(method, template, ToPattern(template), action));
                    }
                }
            }
        }
        Assert.True(routes.Count > 100, $"only {routes.Count} routes were read; the attribute shape changed");
        return routes;
    }

    /// <summary>A route template as a regex: literals case-insensitive, guid and int parameters constrained.</summary>
    private static Regex ToPattern(string template)
    {
        var body = Regex.Replace(Regex.Escape(template).Replace("\\{", "{"), "\\{([^}:]+)(?::([^}]+))?}", m => m.Groups[2].Value switch
        {
            "guid" => "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "int" or "long" => "-?[0-9]+",
            _ => "[^/]+",
        });
        return new Regex("^" + body + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static Route? Resolve(string method, string path)
        => All.Value.FirstOrDefault(r => r.Method == method && r.Pattern.IsMatch(path));

    private static readonly string Id = Guid.NewGuid().ToString();

    public static TheoryData<string, string, string> SpaceRoutes() => new()
    {
        { "GET", "/api/v1/admin/spaces", "AdminSpaceController.GetAll" },
        { "POST", "/api/v1/admin/spaces", "AdminSpaceController.Create" },
        { "GET", $"/api/v1/admin/spaces/{Id}", "AdminSpaceController.GetById" },
        { "PUT", $"/api/v1/admin/spaces/{Id}", "AdminSpaceController.Update" },
        { "DELETE", $"/api/v1/admin/spaces/{Id}", "AdminSpaceController.Disable" },
        { "PUT", $"/api/v1/admin/spaces/{Id}/settings", "AdminSpaceController.UpdateSettings" },
        { "GET", $"/api/v1/admin/spaces/{Id}/kerberos-realms", "AdminKerberosRealmController.List" },
        { "POST", $"/api/v1/admin/spaces/{Id}/kerberos-realms", "AdminKerberosRealmController.Create" },
        { "GET", $"/api/v1/admin/spaces/{Id}/kerberos-realms/{Id}/setup-script", "AdminKerberosRealmController.SetupScript" },
        { "GET", "/api/v1/admin/quotas/by-space", "AdminQuotaController.GetQuotasBySpace" },
        { "PUT", $"/api/v1/admin/user-quorum/space/{Id}", "AdminUserQuorumController.SetSpace" },
    };

    [Theory]
    [MemberData(nameof(SpaceRoutes))]
    public void A_space_route_resolves_to_its_action(string method, string path, string expected)
    {
        var route = Resolve(method, path);
        Assert.True(route != null, $"{method} {path} resolves to no action");
        Assert.Equal(expected, $"{route!.Action.DeclaringType!.Name}.{route.Action.Name}");
    }

    public static TheoryData<string, string> TenantRoutes() => new()
    {
        { "GET", "/api/v1/admin/tenants" },
        { "POST", "/api/v1/admin/tenants" },
        { "GET", $"/api/v1/admin/tenants/{Id}" },
        { "PUT", $"/api/v1/admin/tenants/{Id}" },
        { "DELETE", $"/api/v1/admin/tenants/{Id}" },
        { "PUT", $"/api/v1/admin/tenants/{Id}/settings" },
        { "GET", $"/api/v1/admin/tenants/{Id}/kerberos-realms" },
        { "GET", "/api/v1/admin/quotas/by-tenant" },
        { "PUT", $"/api/v1/admin/user-quorum/tenant/{Id}" },
    };

    /// <summary>A clean break: the pre-0.4.0 paths answer 404, never an alias.</summary>
    [Theory]
    [MemberData(nameof(TenantRoutes))]
    public void A_tenant_route_resolves_to_nothing(string method, string path)
    {
        var route = Resolve(method, path);
        Assert.True(route == null, $"{method} {path} still resolves, to {route?.Action.DeclaringType?.Name}.{route?.Action.Name} ({route?.Template})");
    }

    [Fact]
    public void No_route_template_names_a_tenant()
    {
        var named = All.Value.Where(r => r.Template.Contains("tenant", StringComparison.OrdinalIgnoreCase))
            .Select(r => $"{r.Method} {r.Template}").Distinct().ToList();
        Assert.True(named.Count == 0, "Routes that still say tenant:\n" + string.Join("\n", named));
    }

    /// <summary>
    /// No action binds a route value or query parameter named after a tenant, and the space filters
    /// bind <c>spaceId</c>. The audit chain filters bind <c>chainId</c>: a retired chain is keyed by
    /// the id its space had, and is not a space.
    /// </summary>
    [Fact]
    public void No_parameter_is_named_after_a_tenant_and_the_filters_bind_spaceId()
    {
        var actions = All.Value.Select(r => r.Action).Distinct().ToList();
        var named = actions.SelectMany(a => a.GetParameters().Select(p => (a, p)))
            .Where(x => x.p.Name!.Contains("tenant", StringComparison.OrdinalIgnoreCase))
            .Select(x => $"{x.a.DeclaringType!.Name}.{x.a.Name}({x.p.Name})").ToList();
        Assert.True(named.Count == 0, "Parameters that still say tenant:\n" + string.Join("\n", named));

        string[] spaceFiltered =
        [
            "AdminAuditController.GetAuditLogs", "AdminCertificateController.ListCertificates",
            "AdminCertificateController.ExpiryHistogram", "AdminCertificateController.GetHealthSummary",
            "AdminCertificateTemplateController.GetAll", "AdminCertProfileController.GetAll",
            "AdminCertSignRequestController.RetrievePendingRequests",
        ];
        foreach (var key in spaceFiltered)
            Assert.Contains(actions.Single(a => $"{a.DeclaringType!.Name}.{a.Name}" == key).GetParameters(),
                p => p.Name == "spaceId" && p.GetCustomAttributes<FromQueryAttribute>().Any());
        foreach (var key in new[] { "AdminAuditController.VerifyHashChain", "AdminAuditController.RestartHashChain" })
            Assert.Contains(actions.Single(a => $"{a.DeclaringType!.Name}.{a.Name}" == key).GetParameters(), p => p.Name == "chainId");
    }
}
