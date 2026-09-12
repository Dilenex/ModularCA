using System.Net;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins that an IPv4 client arriving on a dual-stack listener is matched against IPv4 CIDRs.
/// </summary>
/// <remarks>
/// <para>
/// Reported from a live install: the operator moved the listeners to 80/443, Kestrel bound
/// <c>[::]</c> rather than <c>0.0.0.0</c>, and every IPv4 client on the LAN started arriving as
/// <c>::ffff:a.b.c.d</c>. Sixteen bytes against a four-byte network took the "cannot compare IPv6
/// against an IPv4 network" branch and returned false, and the IPv6 entries in the default
/// allow-list did not match a mapped address either — so <c>IpWhitelistMiddleware</c> answered
/// 403 to the admin console from every machine on the network.
/// </para>
/// <para>
/// It survived setup because a tunnelled connection arrives as <c>::1</c>, which matches
/// <c>::1/128</c> on its own terms. The bug was therefore invisible precisely while the operator
/// was configuring the thing, and appeared the moment they tried to use it normally.
/// </para>
/// </remarks>
public class CidrMatcherMappedAddressTests
{
    private static bool Allowed(string ip) =>
        CidrMatcher.IsAllowed(
            IPAddress.Parse(ip),
            CidrMatcher.ParseNetworks(WhitelistDefaults.InternalOnlyCidrs));

    [Theory]
    [InlineData("::ffff:192.168.1.50")]
    [InlineData("::ffff:10.1.2.3")]
    [InlineData("::ffff:172.16.0.9")]
    [InlineData("::ffff:127.0.0.1")]
    public void An_ipv4_client_on_a_dual_stack_listener_is_allowed(string mapped)
    {
        // The reported failure, in one assertion.
        Assert.True(Allowed(mapped), $"{mapped} should match the RFC 1918 defaults");
    }

    [Theory]
    [InlineData("192.168.1.50")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.9")]
    [InlineData("127.0.0.1")]
    public void A_plain_ipv4_client_is_still_allowed(string ip)
    {
        // The path that already worked, kept working: an IPv4-only listener reports these
        // unmapped, and the unwrap must not disturb them.
        Assert.True(Allowed(ip));
    }

    [Theory]
    [InlineData("::1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    public void Genuine_ipv6_private_addresses_are_still_allowed(string ip)
        => Assert.True(Allowed(ip));

    [Theory]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("::ffff:203.0.113.7")]
    public void A_mapped_public_address_is_still_denied(string mapped)
    {
        // The unwrap must not become a way to smuggle a public address past the allow-list:
        // ::ffff:8.8.8.8 has to be evaluated as 8.8.8.8, not waved through as "some IPv6".
        Assert.False(Allowed(mapped));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
    public void Public_addresses_are_denied(string ip)
        => Assert.False(Allowed(ip));

    [Fact]
    public void A_real_ipv6_address_still_cannot_match_an_ipv4_network()
    {
        // The branch the fix narrowed rather than removed: a genuine IPv6 address has no business
        // inside 10.0.0.0/8, and must not start matching because of the unwrap.
        var tenSlashEight = CidrMatcher.ParseNetworks(new[] { "10.0.0.0/8" });

        Assert.False(CidrMatcher.IsAllowed(IPAddress.Parse("fc00::a00:1"), tenSlashEight));
        Assert.False(CidrMatcher.IsAllowed(IPAddress.Parse("2001:db8::10:0:0:1"), tenSlashEight));
    }

    [Fact]
    public void A_mapped_address_matches_an_ipv4_network_at_the_right_boundary()
    {
        var networks = CidrMatcher.ParseNetworks(new[] { "192.168.1.0/24" });

        Assert.True(CidrMatcher.IsAllowed(IPAddress.Parse("::ffff:192.168.1.255"), networks));
        Assert.False(CidrMatcher.IsAllowed(IPAddress.Parse("::ffff:192.168.2.0"), networks));
    }
}
