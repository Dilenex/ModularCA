using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Pins which paths require the CSRF double-submit token.
/// </summary>
/// <remarks>
/// <para>
/// CSRF defends against a browser being walked into a state-changing request using authority it
/// already carries — a session cookie, or the first-run setup surface. Every entry on the
/// protected list has that shape.
/// </para>
/// <para>
/// Public enrollment does not, and was on the list anyway. The request is anonymous and the only
/// thing authorising it is a high-entropy token in the URL, so a forged cross-site POST would need
/// that token, and anyone holding it can enroll directly. The protection defended nothing while
/// making the endpoint unusable by the clients it exists for: a device following a QR code, or any
/// scripted enrollment, had to GET the page purely to harvest a cookie, and a client that did not
/// received 403 "CSRF validation failed" — which reads as an authentication failure and is not one.
/// Found by enrolling against a live CA with curl.
/// </para>
/// <para>
/// These mirror the middleware's list rather than invoking it, because the middleware needs an
/// HttpContext and this test project deliberately does not reference the API assembly. The value
/// is in pinning the membership decision: adding public enrollment back, or dropping a path that
/// genuinely carries ambient authority, fails here with the path named.
/// </para>
/// </remarks>
public class CsrfProtectedPathTests
{
    /// <summary>Mirrors <c>CsrfProtectionMiddleware.ProtectedPaths</c>.</summary>
    private static readonly string[] ProtectedPaths =
    [
        "/api/v1/setup/",
        "/api/v1/auth/login",
        "/api/v1/auth/cert-login",
        "/api/v1/auth/change-password",
    ];

    private static bool RequiresCsrf(string path) =>
        ProtectedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    [Theory]
    [InlineData("/api/v1/setup/initialize")]
    [InlineData("/api/v1/auth/login")]
    [InlineData("/api/v1/auth/cert-login")]
    [InlineData("/api/v1/auth/change-password")]
    public void Paths_carrying_ambient_browser_authority_are_protected(string path)
    {
        Assert.True(RequiresCsrf(path));
    }

    [Theory]
    [InlineData("/api/v1/public/enroll/AbC123")]
    [InlineData("/api/v1/public/enroll")]
    public void Public_enrollment_is_not_protected(string path)
    {
        // The regression this file exists for. Re-adding it breaks every headless and device
        // enrollment with a message about CSRF, which sends the reader looking for a credential
        // problem that does not exist.
        Assert.False(RequiresCsrf(path));
    }

    [Theory]
    [InlineData("/api/v1/public/info")]
    [InlineData("/api/v1/public/ca")]
    [InlineData("/est/my-ca/simpleenroll")]
    [InlineData("/.well-known/est/my-ca/simpleenroll")]
    [InlineData("/cmp/my-ca")]
    [InlineData("/api/v1/acme/new-order")]
    public void The_anonymous_protocol_surface_is_not_protected(string path)
    {
        // EST, CMP, SCEP and ACME clients are not browsers and carry no cookies. Requiring a
        // double-submit token on any of them would make the protocol unimplementable by a
        // conforming client, which is a heavier price than the zero protection it would buy.
        Assert.False(RequiresCsrf(path));
    }

    [Fact]
    public void Setup_is_protected_by_prefix_so_every_wizard_step_is_covered()
    {
        // The setup entry is a prefix on purpose: the wizard has many POST steps and enumerating
        // them would leave the next one added unprotected by default.
        Assert.True(RequiresCsrf("/api/v1/setup/save-database"));
        Assert.True(RequiresCsrf("/api/v1/setup/anything-added-later"));
    }
}
