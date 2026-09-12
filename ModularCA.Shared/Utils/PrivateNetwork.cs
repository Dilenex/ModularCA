using System.Net;
using System.Net.Sockets;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Decides whether an address belongs to a network that cannot be routed from the public
/// internet.
/// </summary>
/// <remarks>
/// <para>
/// Consolidated from two copies that had already begun to diverge in expression — one testing
/// <c>bytes[1] &gt;= 16 &amp;&amp; bytes[1] &lt;= 31</c> and the other <c>(bytes[1] &amp; 0xF0) == 16</c>
/// for the same /12. Both were correct; the next edit to either was where they would have
/// stopped agreeing, and a network predicate that disagrees with itself across the codebase is
/// the sort of thing that produces an access decision nobody can explain afterwards.
/// </para>
/// <para>
/// The ranges below share one property, and it is the only property that matters here: a packet
/// arriving from the internet cannot carry one of these as its source address and still reach a
/// reply. "Private" here means unroutable, not trusted — a host on the same LAN is still an
/// attacker if it is compromised, which is why the setup wizard's real control is its one-time
/// token rather than this check.
/// </para>
/// </remarks>
public static class PrivateNetwork
{
    /// <summary>
    /// True when <paramref name="address"/> is loopback, RFC 1918, link-local, or IPv6
    /// unique-local.
    /// </summary>
    /// <remarks>
    /// IPv6 unique-local (<c>fc00::/7</c>) is included because it is the direct equivalent of
    /// RFC 1918 and an IPv6-only LAN would otherwise be treated as public. Link-local
    /// (<c>169.254.0.0/16</c>, <c>fe80::/10</c>) is included because it is strictly
    /// same-segment — narrower reach than RFC 1918, not wider.
    /// </remarks>
    public static bool IsPrivate(IPAddress? address)
    {
        if (address is null) return false;

        if (IPAddress.IsLoopback(address)) return true;

        // A client reaching a dual-stack listener over IPv4 appears as ::ffff:10.0.0.5, so the
        // v4 checks below would never fire without this.
        var ip = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10                                  // 10.0.0.0/8
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)   // 172.16.0.0/12
                || (b[0] == 192 && b[1] == 168)                // 192.168.0.0/16
                || (b[0] == 169 && b[1] == 254);               // 169.254.0.0/16 link-local
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal) return true;                       // fe80::/10
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC;                              // fc00::/7 unique-local
        }

        return false;
    }

    /// <summary>
    /// True when <paramref name="address"/> is private but not loopback — i.e. reachable from
    /// elsewhere on the local network rather than only from the machine itself.
    /// </summary>
    /// <remarks>
    /// Used for operator-facing messages that need to distinguish "you are on the box" from
    /// "you are on the LAN", which are the same decision but a very different sentence.
    /// </remarks>
    public static bool IsPrivateNonLoopback(IPAddress? address)
        => address is not null && !IPAddress.IsLoopback(address) && IsPrivate(address);
}
