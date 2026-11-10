using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ModularCA.Core.Services.ProxyProtocol;

/// <summary>What <see cref="ProxyProtocolParser.Parse"/> made of the bytes it was given.</summary>
public enum ProxyHeaderStatus
{
    /// <summary>Every byte so far fits a PROXY header, but the header is not complete yet. Read more.</summary>
    Incomplete,

    /// <summary>A whole, valid header. <see cref="ProxyHeaderResult.HeaderLength"/> bytes belong to it.</summary>
    Complete,

    /// <summary>The bytes are not a PROXY header this node accepts. Close the connection.</summary>
    Invalid,
}

/// <summary>The command a PROXY header carries.</summary>
public enum ProxyCommand
{
    /// <summary>
    /// The proxy opened the connection on its own behalf (v2 <c>LOCAL</c>, a health check), or
    /// sent no usable client address (v2 UNSPEC, v1 <c>UNKNOWN</c>). The connection keeps its real peer.
    /// </summary>
    Local = 0,

    /// <summary>The connection is relayed for a client whose address follows.</summary>
    Proxy = 1,
}

/// <summary>
/// The outcome of parsing a PROXY header.
/// </summary>
/// <param name="Status">Whether the header is complete, needs more bytes, or is refused.</param>
/// <param name="HeaderLength">The header's length in bytes, when <see cref="ProxyHeaderStatus.Complete"/>; otherwise 0. The bytes after it are the client's.</param>
/// <param name="Version">1 or 2 once the version is known from the first byte; 0 before.</param>
/// <param name="Command">The command, when complete.</param>
/// <param name="Source">
/// The client's address and port, when complete with a TCP over IPv4 or IPv6 address. Null for
/// v2 <c>LOCAL</c>, v2 UNSPEC and v1 <c>UNKNOWN</c>: the connection then keeps its real peer.
/// </param>
/// <param name="Destination">The address and port the client connected to at the proxy, when <see cref="Source"/> is set.</param>
/// <param name="Error">Why the header was refused, when <see cref="ProxyHeaderStatus.Invalid"/>; for the log, never for the peer.</param>
public readonly record struct ProxyHeaderResult(
    ProxyHeaderStatus Status,
    int HeaderLength,
    int Version,
    ProxyCommand? Command,
    IPEndPoint? Source,
    IPEndPoint? Destination,
    string? Error)
{
    /// <summary>A result asking for more bytes.</summary>
    internal static ProxyHeaderResult NeedMore(int version) => new(ProxyHeaderStatus.Incomplete, 0, version, null, null, null, null);

    /// <summary>A refusal, with the reason.</summary>
    internal static ProxyHeaderResult Refuse(int version, string error) => new(ProxyHeaderStatus.Invalid, 0, version, null, null, null, error);

    /// <summary>A whole header that keeps the connection's real peer.</summary>
    internal static ProxyHeaderResult KeepPeer(int version, int length) => new(ProxyHeaderStatus.Complete, length, version, ProxyCommand.Local, null, null, null);

    /// <summary>A whole header naming the client.</summary>
    internal static ProxyHeaderResult Client(int version, int length, IPEndPoint source, IPEndPoint destination)
        => new(ProxyHeaderStatus.Complete, length, version, ProxyCommand.Proxy, source, destination, null);
}

/// <summary>
/// Parses the PROXY protocol header as HAProxy's <c>proxy-protocol.txt</c> defines it: a proxy
/// that passes TLS through writes it before the client's first byte, carrying the client's
/// address. Version 2 (binary, HAProxy's <c>send-proxy-v2</c>) is the one to use; version 1
/// (text) is accepted as well, because it is the only one nginx's stream module sends. Pure and
/// allocation-light, so the connection middleware can call it on every read until the header is
/// whole.
/// </summary>
/// <remarks>
/// <para>Version 2:</para>
/// <list type="bullet">
/// <item>Commands LOCAL and PROXY. LOCAL keeps the real peer whatever the address block says, as
/// the spec requires.</item>
/// <item>With PROXY: TCP over IPv4 (<c>0x11</c>) and TCP over IPv6 (<c>0x21</c>) give the client
/// address and port; UNSPEC (<c>0x00</c>) keeps the real peer. UDP, UNIX sockets and every other
/// family byte are refused, not treated as UNSPEC: on a TCP listener they mean the proxy is
/// misconfigured, and quietly keeping the proxy's address would bring back the very problem the
/// header exists to solve, with nothing in the log to say so.</item>
/// <item>The address-and-TLV block may be at most <see cref="MaxV2PayloadLength"/> bytes. TLVs
/// are walked to check they are well formed, then skipped; none is acted on (no CRC32C check,
/// no SSL or authority TLVs, which a passthrough proxy has no reason to send).</item>
/// </list>
/// <para>Version 1:</para>
/// <list type="bullet">
/// <item><c>PROXY TCP4 src dst sport dport\r\n</c> and <c>PROXY TCP6 ...</c>, single spaces,
/// at most <see cref="MaxV1Length"/> bytes with the CRLF, addresses in their own family
/// (IPv4 dotted quad written canonically, IPv6 with no zone), ports decimal with no leading
/// zero. <c>PROXY UNKNOWN</c> keeps the real peer. Anything else is refused.</item>
/// </list>
/// <para>
/// Both forms are checked byte by byte as bytes arrive, so a peer that sends TLS or HTTP
/// instead of a header is refused at its first wrong byte rather than at the read deadline.
/// </para>
/// </remarks>
public static class ProxyProtocolParser
{
    /// <summary>The fixed 12-byte signature every v2 header starts with.</summary>
    public static ReadOnlySpan<byte> V2Signature => [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

    /// <summary>The fixed part of a v2 header: signature, version and command, family and protocol, and the 16-bit length.</summary>
    public const int V2FixedLength = 16;

    /// <summary>
    /// The largest v2 address-and-TLV block accepted, in bytes. The spec sets no limit below
    /// 65535; the largest address block is 216 bytes (UNIX), HAProxy's passthrough header
    /// carries 12 or 36 and no TLV unless asked, and an AWS NLB adds one small TLV. 1024 leaves
    /// room for TLVs while stopping a peer from making the node buffer 64 KB before it can refuse.
    /// </summary>
    public const int MaxV2PayloadLength = 1024;

    /// <summary>The longest v1 line the spec allows, CRLF included.</summary>
    public const int MaxV1Length = 107;

    private static ReadOnlySpan<byte> V1Prefix => "PROXY "u8;

    private const int Ipv4AddressBlock = 12;
    private const int Ipv6AddressBlock = 36;

    /// <summary>
    /// Parses a PROXY header from the start of <paramref name="buffer"/>. Bytes after the
    /// header (the TLS ClientHello, or the HTTP request) are not looked at.
    /// </summary>
    /// <param name="buffer">The bytes received so far on the connection.</param>
    /// <returns>
    /// <see cref="ProxyHeaderStatus.Incomplete"/> while every byte so far fits a header,
    /// <see cref="ProxyHeaderStatus.Complete"/> with the header's length and the client address
    /// once it is whole, or <see cref="ProxyHeaderStatus.Invalid"/> with the reason.
    /// </returns>
    public static ProxyHeaderResult Parse(ReadOnlySequence<byte> buffer)
    {
        if (buffer.IsEmpty)
            return ProxyHeaderResult.NeedMore(0);
        var first = buffer.FirstSpan[0];
        if (first == V2Signature[0])
            return ParseV2(buffer);
        if (first == V1Prefix[0])
            return ParseV1(buffer);
        return ProxyHeaderResult.Refuse(0, "the connection does not start with a PROXY protocol header");
    }

    /// <summary>Parses a version 2 (binary) header. See the class remarks for what is accepted.</summary>
    private static ProxyHeaderResult ParseV2(ReadOnlySequence<byte> buffer)
    {
        Span<byte> fixedPart = stackalloc byte[V2FixedLength];
        var available = (int)Math.Min(buffer.Length, V2FixedLength);
        buffer.Slice(0, available).CopyTo(fixedPart);

        // The signature first, as far as it has arrived: garbage is refused at its first wrong byte.
        var signatureBytes = Math.Min(available, V2Signature.Length);
        if (!fixedPart[..signatureBytes].SequenceEqual(V2Signature[..signatureBytes]))
            return ProxyHeaderResult.Refuse(2, "the PROXY v2 signature is wrong");

        if (available > 12)
        {
            var versionCommand = fixedPart[12];
            if (versionCommand >> 4 != 2)
                return ProxyHeaderResult.Refuse(2, $"PROXY protocol version {versionCommand >> 4} after the v2 signature is not supported");
            if ((versionCommand & 0x0F) > 1)
                return ProxyHeaderResult.Refuse(2, $"PROXY v2 command {versionCommand & 0x0F} is neither LOCAL nor PROXY");
        }

        if (available < V2FixedLength)
            return ProxyHeaderResult.NeedMore(2);

        var isLocal = (fixedPart[12] & 0x0F) == 0;
        var familyProtocol = fixedPart[13];
        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(fixedPart[14..16]);
        if (payloadLength > MaxV2PayloadLength)
            return ProxyHeaderResult.Refuse(2, $"the PROXY v2 header announces {payloadLength} bytes of addresses and TLVs, more than the {MaxV2PayloadLength} accepted");

        // Decide what the address block must be before waiting for it, so a header that can
        // never be accepted is refused without reading its payload.
        var addressBlock = 0;
        if (!isLocal)
        {
            addressBlock = familyProtocol switch
            {
                0x00 => 0,
                0x11 => Ipv4AddressBlock,
                0x21 => Ipv6AddressBlock,
                _ => -1,
            };
            if (addressBlock < 0)
                return ProxyHeaderResult.Refuse(2, familyProtocol switch
                {
                    0x12 or 0x22 => "the PROXY v2 header is for UDP, which a TCP listener does not take",
                    0x31 or 0x32 => "the PROXY v2 header carries UNIX socket addresses, which are refused",
                    _ => $"PROXY v2 address family and protocol 0x{familyProtocol:X2} is not supported",
                });
            if (payloadLength < addressBlock)
                return ProxyHeaderResult.Refuse(2, $"the PROXY v2 header announces {payloadLength} bytes, fewer than the {addressBlock} its address family needs");
        }

        var headerLength = V2FixedLength + payloadLength;
        if (buffer.Length < headerLength)
            return ProxyHeaderResult.NeedMore(2);

        // LOCAL: the spec says the receiver uses the real endpoints and discards the block,
        // family included, so nothing in it is read or held to any format.
        if (isLocal)
            return ProxyHeaderResult.KeepPeer(2, headerLength);

        Span<byte> payload = stackalloc byte[payloadLength];
        buffer.Slice(V2FixedLength, payloadLength).CopyTo(payload);

        // TLVs follow the address block: a type byte, a 16-bit length and that many bytes.
        // One that runs past the end of the header is refused.
        var tlvs = payload[addressBlock..];
        while (!tlvs.IsEmpty)
        {
            if (tlvs.Length < 3)
                return ProxyHeaderResult.Refuse(2, "a PROXY v2 TLV is cut short");
            var valueLength = BinaryPrimitives.ReadUInt16BigEndian(tlvs[1..3]);
            if (tlvs.Length < 3 + valueLength)
                return ProxyHeaderResult.Refuse(2, "a PROXY v2 TLV runs past the end of the header");
            tlvs = tlvs[(3 + valueLength)..];
        }

        if (addressBlock == 0)
            return ProxyHeaderResult.KeepPeer(2, headerLength);

        if (addressBlock == Ipv4AddressBlock)
            return ProxyHeaderResult.Client(2, headerLength,
                new IPEndPoint(new IPAddress(payload[0..4]), BinaryPrimitives.ReadUInt16BigEndian(payload[8..10])),
                new IPEndPoint(new IPAddress(payload[4..8]), BinaryPrimitives.ReadUInt16BigEndian(payload[10..12])));

        return ProxyHeaderResult.Client(2, headerLength,
            new IPEndPoint(new IPAddress(payload[0..16]), BinaryPrimitives.ReadUInt16BigEndian(payload[32..34])),
            new IPEndPoint(new IPAddress(payload[16..32]), BinaryPrimitives.ReadUInt16BigEndian(payload[34..36])));
    }

    /// <summary>Parses a version 1 (text) header. See the class remarks for what is accepted.</summary>
    private static ProxyHeaderResult ParseV1(ReadOnlySequence<byte> buffer)
    {
        Span<byte> line = stackalloc byte[MaxV1Length];
        var available = (int)Math.Min(buffer.Length, MaxV1Length);
        buffer.Slice(0, available).CopyTo(line);
        line = line[..available];

        var prefixBytes = Math.Min(available, V1Prefix.Length);
        if (!line[..prefixBytes].SequenceEqual(V1Prefix[..prefixBytes]))
            return ProxyHeaderResult.Refuse(1, "the connection does not start with a PROXY protocol header");

        var lf = line.IndexOf((byte)'\n');
        if (lf < 0)
        {
            return available < MaxV1Length
                ? ProxyHeaderResult.NeedMore(1)
                : ProxyHeaderResult.Refuse(1, $"the PROXY v1 line has no end within {MaxV1Length} bytes");
        }
        if (lf < V1Prefix.Length + 1 || line[lf - 1] != (byte)'\r')
            return ProxyHeaderResult.Refuse(1, "the PROXY v1 line does not end in CRLF");

        var headerLength = lf + 1;
        var body = line[V1Prefix.Length..(lf - 1)];
        foreach (var b in body)
        {
            if (b is < 0x20 or > 0x7E)
                return ProxyHeaderResult.Refuse(1, "the PROXY v1 line holds a byte that is not printable ASCII");
        }

        var text = Encoding.ASCII.GetString(body);
        if (text == "UNKNOWN" || text.StartsWith("UNKNOWN ", StringComparison.Ordinal))
            return ProxyHeaderResult.KeepPeer(1, headerLength);

        var fields = text.Split(' ');
        if (fields.Length != 5)
            return ProxyHeaderResult.Refuse(1, "the PROXY v1 line does not have the protocol, two addresses and two ports, each separated by one space");

        var family = fields[0] switch
        {
            "TCP4" => AddressFamily.InterNetwork,
            "TCP6" => AddressFamily.InterNetworkV6,
            _ => AddressFamily.Unknown,
        };
        if (family == AddressFamily.Unknown)
            return ProxyHeaderResult.Refuse(1, "the PROXY v1 protocol is not TCP4, TCP6 or UNKNOWN");

        if (!TryParseV1Address(fields[1], family, out var source) || !TryParseV1Address(fields[2], family, out var destination))
            return ProxyHeaderResult.Refuse(1, $"a PROXY v1 address is not a {fields[0]} address");
        if (!TryParseV1Port(fields[3], out var sourcePort) || !TryParseV1Port(fields[4], out var destinationPort))
            return ProxyHeaderResult.Refuse(1, "a PROXY v1 port is not a decimal number from 0 to 65535 without leading zeros");

        return ProxyHeaderResult.Client(1, headerLength, new IPEndPoint(source, sourcePort), new IPEndPoint(destination, destinationPort));
    }

    /// <summary>
    /// Parses a v1 address strictly: IPv4 only in canonical dotted-quad form (so <c>127.1</c> and
    /// <c>0x7f.0.0.1</c>, which <see cref="IPAddress.TryParse(string, out IPAddress)"/> accepts, are
    /// refused), IPv6 with no zone index.
    /// </summary>
    private static bool TryParseV1Address(string text, AddressFamily family, out IPAddress address)
    {
        address = IPAddress.None;
        if (!IPAddress.TryParse(text, out var parsed) || parsed.AddressFamily != family)
            return false;
        if (family == AddressFamily.InterNetwork && parsed.ToString() != text)
            return false;
        if (family == AddressFamily.InterNetworkV6 && (text.Contains('%') || parsed.ScopeId != 0))
            return false;
        address = parsed;
        return true;
    }

    /// <summary>Parses a v1 port: 1 to 5 decimal digits, no leading zero unless the port is 0, at most 65535.</summary>
    private static bool TryParseV1Port(string text, out int port)
    {
        port = 0;
        if (text.Length is 0 or > 5 || (text.Length > 1 && text[0] == '0'))
            return false;
        foreach (var c in text)
        {
            if (c is < '0' or > '9')
                return false;
            port = port * 10 + (c - '0');
        }
        return port <= 65535;
    }
}
