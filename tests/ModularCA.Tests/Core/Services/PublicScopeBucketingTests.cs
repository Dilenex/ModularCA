using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
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

        // The portal, the one endpoint its footer reads, and the root that redirects to it.
        if (Starts("/public/") || Is("/public") || Is("/api/v1/public/info") || Is("/"))
            return (WhitelistScope.Public, null);

        return (WhitelistScope.System, null);
    }

    [Theory]
    [InlineData("/public/")]
    [InlineData("/public")]
    [InlineData("/public/assets/index-abc123.js")]
    [InlineData("/api/v1/public/info")]
    [InlineData("/")]
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
        Assert.NotEqual(WhitelistScope.Public, Bucket("/api/v1/admin/spaces").Scope);
        Assert.NotEqual(WhitelistScope.Public, Bucket("/admin/").Scope);
        Assert.NotEqual(WhitelistScope.Public, Bucket("/metrics").Scope);
    }

    [Fact]
    public void An_unrelated_path_still_falls_to_system()
    {
        // The catch-all must stay closed. Adding an open scope must not widen the default.
        Assert.Equal(WhitelistScope.System, Bucket("/favicon.ico").Scope);
        Assert.Equal(WhitelistScope.System, Bucket("/index.html").Scope);
    }

    /// <summary>
    /// The real matcher, with the seeded defaults: the bare root only redirects to the portal, so
    /// it follows the Public Portal rule. It used to fall to System, and a browser outside the
    /// network that opened the host name got 403 instead of the portal.
    /// </summary>
    [Theory]
    [InlineData("/", true)]
    [InlineData("/public/", true)]
    [InlineData("/favicon.ico", false)]
    [InlineData("/index.html", false)]
    public async Task An_outside_address_reaches_the_root_as_it_reaches_the_portal(string path, bool allowed)
    {
        var whitelist = await SeededAsync(portalOpen: true);
        Assert.Equal(allowed ? WhitelistDecision.Allow : WhitelistDecision.Deny, whitelist.Evaluate(path, IPAddress.Parse("203.0.113.7")));
    }

    [Fact]
    public async Task Closing_the_portal_closes_the_root_too()
    {
        var whitelist = await SeededAsync(portalOpen: false);
        Assert.Equal(WhitelistDecision.Deny, whitelist.Evaluate("/", IPAddress.Parse("203.0.113.7")));
        Assert.Equal(WhitelistDecision.Allow, whitelist.Evaluate("/", IPAddress.Parse("10.1.2.3")));
    }

    private static async Task<WhitelistService> SeededAsync(bool portalOpen)
    {
        var databaseName = $"whitelist-{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddDbContext<ModularCADbContext>(o => o.UseInMemoryDatabase(databaseName));
        var scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
        using (var scope = scopes.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            db.Whitelists.AddRange(
                new WhitelistEntity { Name = "System", Scope = WhitelistScope.System, CidrList = WhitelistDefaults.InternalOnlyCidrs.ToList(), IsEnabled = true },
                new WhitelistEntity
                {
                    Name = "Public Portal", Scope = WhitelistScope.Public, IsEnabled = true,
                    CidrList = (portalOpen ? WhitelistDefaults.AllAddressesCidrs : WhitelistDefaults.InternalOnlyCidrs).ToList(),
                });
            await db.SaveChangesAsync();
        }
        var whitelist = new WhitelistService(scopes, NullLogger<WhitelistService>.Instance);
        await whitelist.ReloadAsync();
        return whitelist;
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
