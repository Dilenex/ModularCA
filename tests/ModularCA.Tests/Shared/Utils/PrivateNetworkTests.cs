using System.Net;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers the predicate that decides who may reach the setup wizard.
/// </summary>
/// <remarks>
/// This gates the most privileged unauthenticated surface in the product — the wizard that
/// creates the first administrator and the root CA. It is defence in depth rather than the
/// primary control (every caller must also present the one-time setup token), but a predicate
/// that answers true for a public address would remove a layer without anyone noticing, so the
/// rejections below matter more than the acceptances.
/// </remarks>
public class PrivateNetworkTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.53")]
    [InlineData("::1")]
    public void Loopback_is_private(string ip)
        => Assert.True(PrivateNetwork.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.0.1")]
    [InlineData("192.168.255.254")]
    public void Rfc1918_ranges_are_private(string ip)
        => Assert.True(PrivateNetwork.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("172.15.255.255")]  // one below the /12
    [InlineData("172.32.0.0")]      // one above the /12
    [InlineData("11.0.0.1")]        // adjacent to 10/8
    [InlineData("192.167.255.255")] // adjacent to 192.168/16
    [InlineData("192.169.0.0")]
    public void The_boundaries_of_the_private_ranges_are_not_private(string ip)
    {
        // 172.16.0.0/12 is the range people get wrong — it stops at 172.31, not 172.255. Two
        // copies of this check previously existed with different arithmetic; these are the cases
        // that would have caught them drifting apart.
        Assert.False(PrivateNetwork.IsPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("203.0.113.7")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("100.64.0.1")]      // carrier-grade NAT — not routable, but not ours to trust
    public void Public_addresses_are_not_private(string ip)
        => Assert.False(PrivateNetwork.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("fec0::1")]   // site-local, deprecated by RFC 3879 — not unique-local
    [InlineData("ff02::1")]   // link-scoped multicast
    [InlineData("ff00::1")]
    public void Addresses_just_outside_unique_local_are_not_private(string ip)
    {
        // fc00::/7 is fc and fd only. The tempting mask is `& 0xFC`, which silently also admits
        // fe00::/8 and ff00::/8 — and every fc/fd case still passes, so nothing else here would
        // notice. These are the addresses that separate the correct mask from the plausible one.
        Assert.False(PrivateNetwork.IsPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("169.254.1.1")]     // IPv4 link-local
    [InlineData("fe80::1")]         // IPv6 link-local
    [InlineData("fc00::1")]         // IPv6 unique-local
    [InlineData("fd12:3456:789a::1")]
    public void Link_local_and_unique_local_are_private(string ip)
    {
        // Unique-local is the IPv6 equivalent of RFC 1918; without it an IPv6-only LAN would be
        // treated as public and the wizard unreachable from the network it is deployed on.
        Assert.True(PrivateNetwork.IsPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("::ffff:10.0.0.5")]
    [InlineData("::ffff:192.168.1.20")]
    public void Ipv4_mapped_addresses_are_unwrapped(string ip)
    {
        // A client reaching a dual-stack listener over IPv4 arrives in this form. Without the
        // unwrap the v4 checks never fire and every LAN caller is refused.
        Assert.True(PrivateNetwork.IsPrivate(IPAddress.Parse(ip)));
    }

    [Fact]
    public void A_mapped_public_address_is_still_public()
    {
        // The unwrap must not become a way to smuggle a public address past the check.
        Assert.False(PrivateNetwork.IsPrivate(IPAddress.Parse("::ffff:8.8.8.8")));
    }

    [Fact]
    public void Null_is_not_private()
    {
        // RemoteIpAddress is nullable on unusual transports; failing closed is the only safe
        // reading, and callers should decide separately what to do about an unknown peer.
        Assert.False(PrivateNetwork.IsPrivate(null));
    }

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("10.1.2.3", true)]
    [InlineData("8.8.8.8", false)]
    public void IsPrivateNonLoopback_separates_the_box_from_the_lan(string ip, bool expected)
        => Assert.Equal(expected, PrivateNetwork.IsPrivateNonLoopback(IPAddress.Parse(ip)));
}
