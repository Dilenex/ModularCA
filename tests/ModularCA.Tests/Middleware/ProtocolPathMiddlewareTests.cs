using Microsoft.AspNetCore.Http;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// Which protocol paths two middlewares act on: <c>HttpSchemeEnforcementMiddleware</c>, which
/// lets the public PKI surface through over plain HTTP and redirects the rest, and
/// <c>ProtocolFeatureGateMiddleware</c>, which answers 503 for a protocol switched off.
/// </summary>
public class ProtocolPathMiddlewareTests
{
    // ---- plain HTTP ------------------------------------------------------------------------

    /// <summary>Runs the scheme middleware over a plain-HTTP request; true when it passed the request on.</summary>
    private static async Task<(bool Reached, int Status)> OverPlainHttpAsync(string path)
    {
        var config = new SystemConfig { Https = { PublicDomain = "ca.example.test", PublicPort = 443, Port = 8443 }, Http = { Port = 8080 } };
        var type = ApiAssembly.TypeNamed("ModularCA.API.Middleware.HttpSchemeEnforcementMiddleware");
        var reached = false;
        RequestDelegate next = _ => { reached = true; return Task.CompletedTask; };
        var middleware = Activator.CreateInstance(type, next, config)!;

        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("ca.example.test");
        context.Request.Path = path;
        context.Connection.LocalPort = 8080;
        await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [context])!;
        return (reached, context.Response.StatusCode);
    }

    /// <summary>ACME is HTTPS only: every ACME path over plain HTTP is redirected.</summary>
    [Theory]
    [InlineData("/acme/prod/directory")]
    [InlineData("/acme/prod/new-order")]
    [InlineData("/api/v1/acme/directory")]
    [InlineData("/api/v1/acme/prod/revoke-cert")]
    public async Task Acme_over_plain_http_is_redirected(string path)
    {
        var (reached, status) = await OverPlainHttpAsync(path);
        Assert.False(reached);
        Assert.Equal(308, status);
    }

    /// <summary>The public PKI surface, the http-01 path and the portal stay reachable over plain HTTP.</summary>
    [Theory]
    [InlineData("/public/")]
    [InlineData("/api/v1/public/info")]
    [InlineData("/crl/prod.crl")]
    [InlineData("/ocsp")]
    [InlineData("/ca/prod.crt")]
    [InlineData("/.well-known/acme-challenge/token")]
    public async Task The_public_pki_surface_and_portal_stay_on_plain_http(string path)
    {
        var (reached, _) = await OverPlainHttpAsync(path);
        Assert.True(reached);
    }

    // ---- feature gate ----------------------------------------------------------------------

    private sealed class Flags(params string[] disabled) : IFeatureFlagService
    {
        public bool IsEnabled(string flagName) => !disabled.Contains(flagName);
        public string? GetValue(string flagName) => null;
        public (bool Enabled, string? Value)? Get(string flagName) => (IsEnabled(flagName), null);
        public void InvalidateCache() { }
    }

    /// <summary>Runs the feature gate over a request; true when it passed the request on.</summary>
    private static async Task<(bool Reached, int Status)> GatedAsync(string path, params string[] disabled)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Middleware.ProtocolFeatureGateMiddleware");
        var reached = false;
        RequestDelegate next = _ => { reached = true; return Task.CompletedTask; };
        var middleware = Activator.CreateInstance(type, next)!;

        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [context, new Flags(disabled)])!;
        return (reached, context.Response.StatusCode);
    }

    /// <summary>
    /// <c>POST /ocsp</c> is the path an OCSP client uses most, and it was not gated: the gate
    /// listed <c>/ocsp/</c>, which the bare path does not start with.
    /// </summary>
    [Theory]
    [InlineData("/ocsp", "OCSP.Enabled")]
    [InlineData("/OCSP", "OCSP.Enabled")]
    [InlineData("/ocsp/ca/prod", "OCSP.Enabled")]
    [InlineData("/crl", "CRL.Enabled")]
    [InlineData("/acme", "ACME.Enabled")]
    [InlineData("/acme/prod/directory", "ACME.Enabled")]
    [InlineData("/api/v1/acme/directory", "ACME.Enabled")]
    [InlineData("/est/prod/simpleenroll", "EST.Enabled")]
    [InlineData("/.well-known/est/simpleenroll", "EST.Enabled")]
    [InlineData("/cmp", "CMP.Enabled")]
    public async Task A_disabled_protocols_paths_are_gated_with_or_without_a_trailing_segment(string path, string flag)
    {
        var (reached, status) = await GatedAsync(path, flag);
        Assert.False(reached);
        Assert.Equal(503, status);
    }

    /// <summary>Matching is by whole segments, so a path that merely begins with the same letters is not gated.</summary>
    [Theory]
    [InlineData("/ocspfoo", "OCSP.Enabled")]
    [InlineData("/api/v1/acmefoo", "ACME.Enabled")]
    [InlineData("/cmpx/thing", "CMP.Enabled")]
    public async Task A_path_that_only_shares_a_prefix_is_not_gated(string path, string flag)
    {
        var (reached, _) = await GatedAsync(path, flag);
        Assert.True(reached);
    }

    /// <summary>
    /// Every route the API declares that runs the OCSP responder, as the route attributes spell
    /// it: the versioned and the short path, POST and GET, with and without a CA label.
    /// </summary>
    private static List<string> DeclaredOcspRoutes()
    {
        var routes = new List<string>();
        foreach (var controller in ApiAssembly.ControllerTypes().Where(t => t.Namespace == "ModularCA.API.Controllers.v1.Public"))
        {
            var prefixes = controller.GetCustomAttributes(inherit: true)
                .Where(a => a.GetType().Name == "RouteAttribute")
                .Select(a => (string)a.GetType().GetProperty("Template")!.GetValue(a)!)
                .DefaultIfEmpty(string.Empty)
                .ToList();
            foreach (var method in controller.GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.DeclaredOnly))
            {
                foreach (var verb in method.GetCustomAttributes(inherit: true).Where(a => a.GetType().Name is "HttpGetAttribute" or "HttpPostAttribute"))
                {
                    var template = (string?)verb.GetType().GetProperty("Template")!.GetValue(verb) ?? string.Empty;
                    // A template that starts with a slash is the whole path; any other is appended to each class route.
                    IEnumerable<string> paths = template.StartsWith('/')
                        ? new[] { template }
                        : prefixes.Select(p => "/" + string.Join('/', new[] { p.Trim('/'), template }.Where(s => s.Length > 0)));
                    routes.AddRange(paths.Where(p => p.Split('/').Contains("ocsp", StringComparer.OrdinalIgnoreCase)));
                }
            }
        }
        return routes.Distinct(StringComparer.Ordinal).OrderBy(r => r, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// With <c>OCSP.Enabled</c> off, no OCSP route the API declares reaches its controller. The
    /// routes are read from the route attributes, so one added later is covered without being
    /// listed here; the count guards against the reflection finding none.
    /// </summary>
    [Fact]
    public async Task Every_declared_ocsp_route_is_gated_by_the_ocsp_flag()
    {
        var routes = DeclaredOcspRoutes();
        Assert.Equal(
            [
                "/api/v1/public/ocsp",
                "/api/v1/public/ocsp/ca/{caLabel}",
                "/api/v1/public/ocsp/ca/{caLabel}/{encodedRequest}",
                "/api/v1/public/ocsp/{encodedRequest}",
                "/ocsp",
                "/ocsp/ca/{caLabel}",
                "/ocsp/ca/{caLabel}/{encodedRequest}",
                "/ocsp/{encodedRequest}",
            ],
            routes);

        foreach (var route in routes)
        {
            var path = route.Replace("{caLabel}", "prod").Replace("{encodedRequest}", "MEIwQDA-MDwwOjAJBgUrDgMCGgUABBQ");
            var (reached, status) = await GatedAsync(path, "OCSP.Enabled");
            Assert.False(reached, $"{route} is not gated by OCSP.Enabled");
            Assert.Equal(503, status);

            // Another protocol's flag does not close it.
            Assert.True((await GatedAsync(path, "CRL.Enabled")).Reached, $"{route} is gated by the wrong flag");
        }
    }

    [Fact]
    public async Task An_enabled_protocol_passes()
    {
        var (reached, _) = await GatedAsync("/ocsp");
        Assert.True(reached);
    }
}
