using System.Net;
using System.Net.Sockets;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Represents a single parsed CIDR network (address + prefix length) and
/// tests whether a given <see cref="IPAddress"/> falls inside it. Handles
/// the IPv4 / IPv6 address-family mismatch by mapping IPv4 clients into
/// the IPv4-mapped-IPv6 space (<c>::ffff:a.b.c.d</c>) when comparing
/// against an IPv6 network, and rejecting IPv6 clients against an IPv4
/// network. Extracted from the old nested type inside
/// <c>IpWhitelistMiddleware</c> so the new whitelist service, the updated
/// middleware, and the pre-bootstrap fallback can all share one
/// implementation.
/// </summary>
public sealed class IpNetwork
{
    private readonly IPAddress _network;
    private readonly int _prefixLength;
    private readonly byte[] _networkBytes;
    private readonly byte[] _mask;

    /// <summary>
    /// Constructs an <see cref="IpNetwork"/> from a network base address and
    /// a prefix length in bits. No validation is performed on the prefix
    /// length beyond what <see cref="CreateMask"/> tolerates; callers should
    /// pre-validate user input before constructing.
    /// </summary>
    /// <param name="network">Network base address (IPv4 or IPv6).</param>
    /// <param name="prefixLength">CIDR prefix length in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="prefixLength"/> is outside 0..32 (IPv4) or 0..128 (IPv6).
    /// <para>
    /// This was unvalidated, and a NEGATIVE prefix was not merely wrong — it was allow-all.
    /// CreateMask walks the address bytes with <c>if (prefixLength &gt;= 8) … else if
    /// (prefixLength &gt; 0) …</c>, so a negative value matched neither branch, every mask byte
    /// stayed zero, and Contains() then returned true for every address on the internet. The only
    /// validation of operator-supplied CIDRs is whether ParseNetworks accepted the entry, so
    /// <c>10.0.0.0/-1</c> — or a fat-fingered <c>/-25</c> — was stored, displayed in the admin UI
    /// as a private range, and silently matched everything. Applied to the Admin or Api whitelist
    /// scope that exposes the admin surface to any source address.
    /// </para>
    /// </exception>
    public IpNetwork(IPAddress network, int prefixLength)
    {
        _network = network;
        _networkBytes = network.GetAddressBytes();

        var maxPrefix = _networkBytes.Length * 8;
        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength), prefixLength,
                $"CIDR prefix length must be between 0 and {maxPrefix} for "
                + $"{(_networkBytes.Length == 4 ? "IPv4" : "IPv6")}.");
        }

        _prefixLength = prefixLength;
        _mask = CreateMask(_networkBytes.Length, prefixLength);
    }

    /// <summary>
    /// Gets the network base address this rule was constructed with.
    /// </summary>
    public IPAddress Network => _network;

    /// <summary>
    /// Gets the CIDR prefix length in bits.
    /// </summary>
    public int PrefixLength => _prefixLength;

    /// <summary>
    /// Returns true if <paramref name="address"/> is inside this network.
    /// Handles IPv4 vs IPv6 address-family mismatches by mapping an IPv4
    /// client address into IPv4-mapped-IPv6 space when the network itself
    /// is IPv6, and returning false when an IPv6 client is compared against
    /// an IPv4 network (the two cannot meaningfully overlap).
    /// </summary>
    public bool Contains(IPAddress address)
    {
        var addrBytes = address.GetAddressBytes();

        // Handle IPv4 vs IPv6 mismatch
        if (addrBytes.Length != _networkBytes.Length)
        {
            if (addrBytes.Length == 4 && _networkBytes.Length == 16)
                addrBytes = MapToIPv6(addrBytes);
            else if (addrBytes.Length == 16 && _networkBytes.Length == 4)
                return false; // Can't compare IPv6 against IPv4 network
        }

        for (int i = 0; i < addrBytes.Length && i < _mask.Length; i++)
        {
            if ((addrBytes[i] & _mask[i]) != (_networkBytes[i] & _mask[i]))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Builds a byte-mask of the given length (4 for IPv4, 16 for IPv6)
    /// with the top <paramref name="prefixLength"/> bits set. The supplied
    /// <paramref name="prefixLength"/> argument is consumed destructively.
    /// </summary>
    private static byte[] CreateMask(int length, int prefixLength)
    {
        var mask = new byte[length];
        for (int i = 0; i < length; i++)
        {
            if (prefixLength >= 8)
            {
                mask[i] = 0xFF;
                prefixLength -= 8;
            }
            else if (prefixLength > 0)
            {
                mask[i] = (byte)(0xFF << (8 - prefixLength));
                prefixLength = 0;
            }
        }
        return mask;
    }

    /// <summary>
    /// Maps a 4-byte IPv4 address into the 16-byte IPv4-mapped-IPv6 form
    /// (<c>::ffff:a.b.c.d</c>) so it can be compared against an IPv6
    /// network byte-for-byte.
    /// </summary>
    private static byte[] MapToIPv6(byte[] ipv4)
    {
        var ipv6 = new byte[16];
        ipv6[10] = 0xFF;
        ipv6[11] = 0xFF;
        Array.Copy(ipv4, 0, ipv6, 12, 4);
        return ipv6;
    }
}

/// <summary>
/// Helper utilities for parsing CIDR strings and evaluating whether a
/// client <see cref="IPAddress"/> is allowed by a parsed network list.
/// Lives in <c>ModularCA.Shared</c> so the whitelist service, the HTTP
/// middleware, and the pre-bootstrap fallback all share one
/// implementation.
/// </summary>
public static class CidrMatcher
{
    /// <summary>
    /// Returns true if <paramref name="remoteIp"/> is contained in any of
    /// the supplied <paramref name="networks"/>. An empty list is treated
    /// as "deny all" — this preserves the historical semantic from the
    /// original middleware where an empty allow-list meant explicit
    /// lockdown rather than pass-through.
    /// </summary>
    public static bool IsAllowed(IPAddress remoteIp, IReadOnlyList<IpNetwork> networks)
    {
        if (networks.Count == 0) return false; // Empty list = block all
        return networks.Any(n => n.Contains(remoteIp));
    }

    /// <summary>
    /// Parses a collection of CIDR strings (e.g. <c>"10.0.0.0/8"</c>) or
    /// bare IP addresses (e.g. <c>"192.0.2.1"</c> — treated as <c>/32</c>
    /// for IPv4 or <c>/128</c> for IPv6) into <see cref="IpNetwork"/>
    /// instances. Invalid entries are silently skipped so a single
    /// operator typo cannot brick the middleware; callers that want to
    /// report parse failures should validate the input themselves first.
    /// </summary>
    public static List<IpNetwork> ParseNetworks(IEnumerable<string> ranges)
    {
        var networks = new List<IpNetwork>();
        foreach (var range in ranges)
        {
            try
            {
                if (range.Contains('/'))
                {
                    var parts = range.Split('/');
                    var ip = IPAddress.Parse(parts[0]);
                    var prefixLength = int.Parse(parts[1]);
                    networks.Add(new IpNetwork(ip, prefixLength));
                }
                else
                {
                    // Single IP — treat as /32 or /128
                    var ip = IPAddress.Parse(range);
                    var prefixLength = ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
                    networks.Add(new IpNetwork(ip, prefixLength));
                }
            }
            catch
            {
                // Skip invalid entries
            }
        }
        return networks;
    }
}
