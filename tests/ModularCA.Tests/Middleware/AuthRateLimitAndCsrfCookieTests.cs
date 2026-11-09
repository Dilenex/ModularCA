using System.Net;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// The sign-in paths that had no throttle — certificate login, refresh, the mTLS code exchange and
/// the mTLS redirect sign-ins (GET navigations) — draw from per-IP buckets under both route shapes;
/// and the CSRF double-submit cookie is <c>__Host-CSRF-TOKEN</c> over HTTPS, where an unprefixed
/// cookie is neither accepted nor kept, while plain HTTP keeps <c>CSRF-TOKEN</c>.
/// </summary>
public sealed class AuthRateLimitAndCsrfCookieTests
{
    private const string RateLimitName = "ModularCA.API.Middleware.LoginRateLimitMiddleware";
    private const string CsrfName = "ModularCA.API.Middleware.CsrfProtectionMiddleware";

    private static (string Prefix, int Max, int Window)? Bucket(string method, string path)
    {
        var find = ApiAssembly.TypeNamed(RateLimitName).GetMethod("FindBucket", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)!;
        return ((string, int, int)?)find.Invoke(null, new object?[] { method, path });
    }

    [Theory]
    [InlineData("POST", "/api/v1/auth/cert-login", "/api/v1/auth/cert-login")]
    [InlineData("POST", "/auth/cert-login", "/api/v1/auth/cert-login")]
    [InlineData("POST", "/api/v1/auth/refresh", "/api/v1/auth/refresh")]
    [InlineData("POST", "/auth/refresh", "/api/v1/auth/refresh")]
    [InlineData("POST", "/api/v1/auth/mtls/exchange", "/api/v1/auth/mtls/exchange")]
    [InlineData("POST", "/auth/mtls/exchange/", "/api/v1/auth/mtls/exchange")]
    [InlineData("POST", "/auth/mfa/verify-stepup/mtls", "/api/v1/auth/mfa/verify-stepup/mtls")]
    [InlineData("GET", "/api/v1/auth/mtls/login-redirect", "/api/v1/auth/mtls/login-redirect")]
    [InlineData("GET", "/auth/mtls/login-redirect", "/api/v1/auth/mtls/login-redirect")]
    [InlineData("GET", "/auth/mtls/verify-redirect", "/api/v1/auth/mtls/verify-redirect")]
    public void Sign_in_paths_draw_from_a_bucket_under_both_route_shapes(string method, string path, string expectedPrefix)
    {
        var bucket = Bucket(method, path);
        Assert.NotNull(bucket);
        Assert.Equal(expectedPrefix, bucket.Value.Prefix);
    }

    [Theory]
    [InlineData("GET", "/api/v1/auth/refresh")]
    [InlineData("GET", "/auth/mtls/auth-info")]
    [InlineData("GET", "/api/v1/me")]
    public void Ordinary_reads_are_not_throttled(string method, string path)
    {
        Assert.Null(Bucket(method, path));
    }

    [Fact]
    public async Task Repeated_certificate_redirect_sign_ins_from_one_address_get_429()
    {
        var calls = 0;
        RequestDelegate next = _ => { calls++; return Task.CompletedTask; };
        var middleware = Activator.CreateInstance(ApiAssembly.TypeNamed(RateLimitName), next, new SystemConfig())!;
        var invoke = middleware.GetType().GetMethod("InvokeAsync")!;
        // A unique documentation-range address keeps this test's bucket its own.
        var ip = IPAddress.Parse($"198.51.100.{Random.Shared.Next(1, 254)}");
        var max = Bucket("GET", "/auth/mtls/login-redirect")!.Value.Max;

        int last = 0;
        for (var i = 0; i <= max; i++)
        {
            var http = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider() };
            http.Request.Method = "GET";
            http.Request.Path = "/auth/mtls/login-redirect";
            http.Connection.RemoteIpAddress = ip;
            await (Task)invoke.Invoke(middleware, new object[] { http })!;
            last = http.Response.StatusCode;
        }

        Assert.Equal(max, calls);
        Assert.Equal(StatusCodes.Status429TooManyRequests, last);
    }

    private static async Task<(HttpContext Http, bool Passed)> SendCsrfAsync(string scheme, string method, string path, string? cookie, string? header)
    {
        var passed = false;
        RequestDelegate next = _ => { passed = true; return Task.CompletedTask; };
        var middleware = Activator.CreateInstance(ApiAssembly.TypeNamed(CsrfName), next)!;
        var http = new DefaultHttpContext();
        http.Request.Scheme = scheme;
        http.Request.Method = method;
        http.Request.Path = path;
        http.Response.Body = new MemoryStream();
        if (cookie != null) http.Request.Headers.Cookie = cookie;
        if (header != null) http.Request.Headers["X-CSRF-Token"] = header;
        await (Task)middleware.GetType().GetMethod("InvokeAsync")!.Invoke(middleware, new object[] { http })!;
        return (http, passed);
    }

    private static string SetCookies(HttpContext http) => string.Join("\n", http.Response.Headers.SetCookie.ToArray());

    [Fact]
    public async Task Https_issues_a_host_prefixed_secure_cookie()
    {
        var (http, _) = await SendCsrfAsync("https", "GET", "/login", null, null);
        var set = SetCookies(http);

        Assert.StartsWith("__Host-CSRF-TOKEN=", set);
        Assert.Contains("secure", set, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", set, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", set, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Plain_http_keeps_the_unprefixed_cookie()
    {
        var (http, _) = await SendCsrfAsync("http", "GET", "/login", null, null);

        Assert.StartsWith("CSRF-TOKEN=", SetCookies(http));
    }

    [Fact]
    public async Task Https_accepts_the_prefixed_cookie_and_refuses_a_legacy_one()
    {
        var (_, passed) = await SendCsrfAsync("https", "POST", "/auth/login", "__Host-CSRF-TOKEN=abc", "abc");
        Assert.True(passed);

        var (legacy, legacyPassed) = await SendCsrfAsync("https", "POST", "/auth/login", "CSRF-TOKEN=abc", "abc");
        Assert.False(legacyPassed);
        Assert.Equal(StatusCodes.Status403Forbidden, legacy.Response.StatusCode);
        // The leftover cookie is deleted so clients stop reading it.
        Assert.Contains(legacy.Response.Headers.SetCookie.ToArray(), c => c!.StartsWith("CSRF-TOKEN=;", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Plain_http_accepts_the_unprefixed_cookie()
    {
        var (_, passed) = await SendCsrfAsync("http", "POST", "/auth/login", "CSRF-TOKEN=abc", "abc");
        Assert.True(passed);
    }
}
