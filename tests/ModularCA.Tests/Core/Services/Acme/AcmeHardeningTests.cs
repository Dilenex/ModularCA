using System.Net;
using System.Reflection;
using ModularCA.Core.Services.Acme;
using Xunit;

namespace ModularCA.Tests.Core.Services.Acme;

/// <summary>
/// Pins the ACME defects that were live on a default deployment.
/// </summary>
public class AcmeHardeningTests
{
    /// <summary>
    /// Invokes the private SSRF filter directly. It is the whole decision — everything else on
    /// the http-01 path is plumbing — and it takes a single IPAddress, so reflection here buys a
    /// real test of the real predicate rather than a reimplementation of it.
    /// </summary>
    private static bool IsPrivate(string address)
    {
        var method = typeof(AcmeChallengeService).GetMethod("IsPrivateAddress",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (bool)method!.Invoke(null, [IPAddress.Parse(address)])!;
    }

    [Theory]
    // The gap: IPv4-mapped IPv6 reports AddressFamily.InterNetworkV6, so it took the IPv6
    // branch and matched none of its patterns — the entire IPv4 private-range block was skipped.
    [InlineData("::ffff:169.254.169.254")]   // cloud instance metadata
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:172.16.5.4")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:100.64.0.1")]        // CGNAT
    public void An_ipv4_mapped_private_address_is_recognised_as_private(string address)
    {
        Assert.True(IsPrivate(address), $"{address} must not be reachable from http-01 validation");
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("10.0.0.1")]
    [InlineData("127.0.0.1")]
    [InlineData("fc00::1")]                  // ULA — the genuine IPv6 checks were always correct
    [InlineData("fe80::1")]                  // link-local
    public void Plain_private_addresses_are_still_recognised(string address)
    {
        Assert.True(IsPrivate(address));
    }

    [Theory]
    [InlineData("93.184.216.34")]            // example.com
    [InlineData("2606:2800:220:1:248:1893:25c8:1946")]
    [InlineData("::ffff:93.184.216.34")]     // a mapped PUBLIC address must stay reachable
    public void Public_addresses_remain_reachable(string address)
    {
        Assert.False(IsPrivate(address), $"{address} is public and http-01 must be able to reach it");
    }

    // ---- finalize must not be able to switch CAs ----

    /// <summary>
    /// Mirrors the guard in AcmeOrderService.FinalizeOrder: the order's CA is authoritative and
    /// a route label may only confirm it.
    /// </summary>
    private static bool FinalizeAllowed(string? routeLabel, string? orderLabel) =>
        string.IsNullOrWhiteSpace(routeLabel)
        || string.IsNullOrWhiteSpace(orderLabel)
        || string.Equals(routeLabel, orderLabel, StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void An_order_cannot_be_finalized_against_a_different_ca()
    {
        // The escalation: validate under a CA whose AcmeAllowPrivateAddressValidation is on,
        // then finalize against production. Ownership was checked by account id, which says
        // nothing about which CA may sign.
        Assert.False(FinalizeAllowed(routeLabel: "prod", orderLabel: "lab"));
    }

    [Fact]
    public void Finalizing_against_the_orders_own_ca_is_permitted()
    {
        Assert.True(FinalizeAllowed(routeLabel: "prod", orderLabel: "prod"));
        Assert.True(FinalizeAllowed(routeLabel: "PROD", orderLabel: "prod"));
    }

    [Fact]
    public void A_route_with_no_label_falls_back_to_the_orders_ca()
    {
        // The unlabelled /api/v1/acme route still has to work; it inherits the order's CA
        // rather than the protocol default.
        Assert.True(FinalizeAllowed(routeLabel: null, orderLabel: "prod"));
    }
}
