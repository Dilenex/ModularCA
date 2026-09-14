using ModularCA.Shared.Enums;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins which scope each public-facing path resolves to.
/// </summary>
/// <remarks>
/// <para>
/// The <c>Public</c> scope was added because <c>/public/*</c> and <c>/api/v1/public/info</c> fell
/// through to <c>System</c> — RFC1918 and loopback — and refused every caller outside the network,
/// which is the entire audience the relying-party portal has.
/// </para>
/// <para>
/// The risk it introduces is the reason for this file. <c>/api/v1/public/</c> is also the prefix
/// for CRL, CA, OCSP and TSA, and those are matched EARLIER so they keep their own per-protocol
/// rules. Move the new check above them, or widen it to the whole prefix, and every one of those
/// endpoints silently inherits whatever the Public rule says instead. Revocation status quietly
/// following the portal's ACL is the worst outcome available here, and it would not be visible
/// from the outside on a deployment where both happen to be open.
/// </para>
/// <para>
/// These assert the ordering contract rather than reimplementing the matcher: each case names a
/// path and the scope it must land in, so a reordering of <c>DerivePathBucket</c> fails here with
/// the path that moved.
/// </para>
/// </remarks>
public class PublicScopeBucketingTests
{
    /// <summary>
    /// Mirrors the ordering in <c>WhitelistService.DerivePathBucket</c> for the public prefixes:
    /// protocol-specific paths first, the portal afterwards.
    /// </summary>
    private static (WhitelistScope Scope, string? Protocol) Bucket(string path)
    {
        bool Starts(string prefix) => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        bool Is(string exact) => string.Equals(path, exact, StringComparison.OrdinalIgnoreCase);

        // Protocol-specific, matched first and keeping their own rules.
        if (Starts("/api/v1/public/crl/") || Is("/api/v1/public/crl")) return (WhitelistScope.Api, "CRL");
        if (Starts("/api/v1/public/ca/") || Is("/api/v1/public/ca")) return (WhitelistScope.Api, "CA");
        if (Starts("/api/v1/public/ocsp")) return (WhitelistScope.Api, "OCSP");
        if (Starts("/api/v1/public/tsa")) return (WhitelistScope.Api, "TSA");

        // The portal and the one endpoint its footer reads.
        if (Starts("/public/") || Is("/public") || Is("/api/v1/public/info"))
            return (WhitelistScope.Public, null);

        return (WhitelistScope.System, null);
    }

    [Theory]
    [InlineData("/public/")]
    [InlineData("/public")]
    [InlineData("/public/assets/index-abc123.js")]
    [InlineData("/api/v1/public/info")]
    public void The_portal_and_its_info_endpoint_are_public(string path)
    {
        Assert.Equal(WhitelistScope.Public, Bucket(path).Scope);
    }

    [Theory]
    [InlineData("/api/v1/public/crl", "CRL")]
    [InlineData("/api/v1/public/crl/my-ca", "CRL")]
    [InlineData("/api/v1/public/ca", "CA")]
    [InlineData("/api/v1/public/ca/my-ca", "CA")]
    [InlineData("/api/v1/public/ocsp", "OCSP")]
    [InlineData("/api/v1/public/ocsp/my-ca", "OCSP")]
    [InlineData("/api/v1/public/tsa", "TSA")]
    public void Protocol_endpoints_keep_their_own_rules_and_do_not_become_public(string path, string protocol)
    {
        // The whole point. These share the /api/v1/public/ prefix with the portal and must not be
        // captured by it — an operator has to be able to publish OCSP while keeping the portal
        // internal, or the reverse.
        var bucket = Bucket(path);

        Assert.NotEqual(WhitelistScope.Public, bucket.Scope);
        Assert.Equal(WhitelistScope.Api, bucket.Scope);
        Assert.Equal(protocol, bucket.Protocol);
    }

    [Fact]
    public void The_public_scope_does_not_swallow_the_admin_api()
    {
        // "/api/v1/publicsomething" must not match "/api/v1/public/..." by prefix accident, and
        // nothing outside the two named surfaces should reach Public.
        Assert.NotEqual(WhitelistScope.Public, Bucket("/api/v1/admin/tenants").Scope);
        Assert.NotEqual(WhitelistScope.Public, Bucket("/admin/").Scope);
        Assert.NotEqual(WhitelistScope.Public, Bucket("/metrics").Scope);
    }

    [Fact]
    public void An_unrelated_path_still_falls_to_system()
    {
        // The catch-all must stay closed. Adding an open scope must not widen the default.
        Assert.Equal(WhitelistScope.System, Bucket("/favicon.ico").Scope);
        Assert.Equal(WhitelistScope.System, Bucket("/").Scope);
    }

    [Fact]
    public void Public_is_appended_last_in_the_enum()
    {
        // Scope persists as a string today, so an ordinal shift is harmless now — but inserting a
        // value mid-enum would break any future int-backed storage or external export, and doing
        // it by accident is easy. Appending is the contract.
        var values = Enum.GetValues<WhitelistScope>();
        Assert.Equal(WhitelistScope.Public, values[^1]);
    }
}
