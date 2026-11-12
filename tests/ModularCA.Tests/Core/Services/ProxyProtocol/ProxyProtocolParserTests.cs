using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Text;
using ModularCA.Core.Services.ProxyProtocol;
using Xunit;

namespace ModularCA.Tests.Core.Services.ProxyProtocol;

/// <summary>
/// The PROXY protocol parser: a whole v2 header gives the client's address and exactly the
/// header's length; every prefix of one asks for more; LOCAL, UNSPEC and v1 UNKNOWN keep the
/// peer; and a wrong signature, version, command, family or length, or a malformed TLV, is
/// refused rather than read past. Version 1 is held to the same standard.
/// </summary>
public class ProxyProtocolParserTests
{
    private static readonly byte[] Signature = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

    /// <summary>The first bytes of a TLS 1.2+ ClientHello record, standing for the client's TLS.</summary>
    private static readonly byte[] ClientHelloStart = [0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xFC, 0x03, 0x03];

    /// <summary>A v2 header: signature, version/command byte, family/protocol byte, big-endian length, payload.</summary>
    internal static byte[] V2(byte versionCommand, byte familyProtocol, byte[] payload, int? announcedLength = null)
    {
        var header = new byte[16 + payload.Length];
        Signature.CopyTo(header, 0);
        header[12] = versionCommand;
        header[13] = familyProtocol;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(14), (ushort)(announcedLength ?? payload.Length));
        payload.CopyTo(header, 16);
        return header;
    }

    /// <summary>A v2 PROXY header for TCP over IPv4 or IPv6, by the source address's family, with optional TLV bytes.</summary>
    internal static byte[] V2Tcp(IPEndPoint source, IPEndPoint destination, byte[]? tlvs = null)
    {
        var v4 = source.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var payload = new List<byte>();
        payload.AddRange(source.Address.GetAddressBytes());
        payload.AddRange(destination.Address.GetAddressBytes());
        var ports = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(ports, (ushort)source.Port);
        BinaryPrimitives.WriteUInt16BigEndian(ports.AsSpan(2), (ushort)destination.Port);
        payload.AddRange(ports);
        payload.AddRange(tlvs ?? []);
        return V2(0x21, v4 ? (byte)0x11 : (byte)0x21, payload.ToArray());
    }

    /// <summary>One TLV: type, big-endian length, value.</summary>
    private static byte[] Tlv(byte type, byte[] value)
    {
        var tlv = new byte[3 + value.Length];
        tlv[0] = type;
        BinaryPrimitives.WriteUInt16BigEndian(tlv.AsSpan(1), (ushort)value.Length);
        value.CopyTo(tlv, 3);
        return tlv;
    }

    private static ProxyHeaderResult Parse(byte[] bytes) => ProxyProtocolParser.Parse(new ReadOnlySequence<byte>(bytes));

    private static readonly IPEndPoint Client4 = new(IPAddress.Parse("203.0.113.7"), 51234);
    private static readonly IPEndPoint Front4 = new(IPAddress.Parse("198.51.100.1"), 443);
    private static readonly IPEndPoint Client6 = new(IPAddress.Parse("2001:db8::7"), 61000);
    private static readonly IPEndPoint Front6 = new(IPAddress.Parse("2001:db8::1"), 8443);

    [Fact]
    public void A_tcp4_header_gives_the_client_address_and_port()
    {
        var header = V2Tcp(Client4, Front4);
        var result = Parse(header);

        Assert.Equal(ProxyHeaderStatus.Complete, result.Status);
        Assert.Equal(28, result.HeaderLength);
        Assert.Equal(2, result.Version);
        Assert.Equal(ProxyCommand.Proxy, result.Command);
        Assert.Equal(Client4, result.Source);
        Assert.Equal(Front4, result.Destination);
    }

    [Fact]
    public void A_tcp6_header_gives_the_client_address_and_port()
    {
        var result = Parse(V2Tcp(Client6, Front6));

        Assert.Equal(ProxyHeaderStatus.Complete, result.Status);
        Assert.Equal(52, result.HeaderLength);
        Assert.Equal(Client6, result.Source);
        Assert.Equal(Front6, result.Destination);
    }

    [Theory]
    [InlineData((byte)0x00, 0)]
    [InlineData((byte)0x11, 12)]
    [InlineData((byte)0x31, 216)]
    [InlineData((byte)0xFF, 5)]
    public void A_local_header_keeps_the_peer_whatever_its_address_block_says(byte familyProtocol, int blockLength)
    {
        var header = V2(0x20, familyProtocol, new byte[blockLength]);
        var result = Parse(header);

        Assert.Equal(ProxyHeaderStatus.Complete, result.Status);
        Assert.Equal(header.Length, result.HeaderLength);
        Assert.Equal(ProxyCommand.Local, result.Command);
        Assert.Null(result.Source);
    }

    [Fact]
    public void An_unspec_proxy_header_keeps_the_peer()
    {
        var header = V2(0x21, 0x00, Tlv(0x04, new byte[3]));
        var result = Parse(header);

        Assert.Equal(ProxyHeaderStatus.Complete, result.Status);
        Assert.Equal(header.Length, result.HeaderLength);
        Assert.Equal(ProxyCommand.Local, result.Command);
        Assert.Null(result.Source);
    }

    [Fact]
    public void TLVs_after_the_addresses_are_skipped_and_counted_in_the_header()
    {
        var tlvs = Tlv(0x01, "h2"u8.ToArray())          // ALPN
            .Concat(Tlv(0x04, new byte[7]))               // NOOP padding
            .Concat(Tlv(0xEA, new byte[22]))              // AWS VPC endpoint id
            .Concat(Tlv(0x04, []))                        // empty value
            .ToArray();
        var header = V2Tcp(Client4, Front4, tlvs);
        var result = Parse(header.Concat(ClientHelloStart).ToArray());

        Assert.Equal(ProxyHeaderStatus.Complete, result.Status);
        Assert.Equal(header.Length, result.HeaderLength);
        Assert.Equal(Client4, result.Source);
    }

    [Theory]
    [InlineData(new byte[] { 0x04 })]
    [InlineData(new byte[] { 0x04, 0x00 })]
    [InlineData(new byte[] { 0x04, 0x00, 0x05, 0x00, 0x00 })]
    public void A_TLV_that_runs_past_the_header_is_refused(byte[] tlvs)
    {
        var result = Parse(V2Tcp(Client4, Front4, tlvs));

        Assert.Equal(ProxyHeaderStatus.Invalid, result.Status);
        Assert.Contains("TLV", result.Error);
    }

    public static TheoryData<string, byte[]> WholeHeaders => new()
    {
        { "tcp4", V2Tcp(Client4, Front4) },
        { "tcp6 with TLVs", V2Tcp(Client6, Front6, Tlv(0x04, new byte[9])) },
        { "local", V2(0x20, 0x00, []) },
        { "v1 tcp4", Encoding.ASCII.GetBytes("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n") },
        { "v1 tcp6", Encoding.ASCII.GetBytes("PROXY TCP6 2001:db8::7 2001:db8::1 61000 8443\r\n") },
        { "v1 unknown", Encoding.ASCII.GetBytes("PROXY UNKNOWN\r\n") },
    };

    [Theory]
    [MemberData(nameof(WholeHeaders))]
    public void Every_prefix_of_a_header_asks_for_more_bytes(string name, byte[] header)
    {
        for (var length = 0; length < header.Length; length++)
        {
            var result = Parse(header[..length]);
            Assert.True(result.Status == ProxyHeaderStatus.Incomplete, $"{name}: {length} of {header.Length} bytes gave {result.Status} ({result.Error})");
        }
        Assert.Equal(ProxyHeaderStatus.Complete, Parse(header).Status);
    }

    [Theory]
    [MemberData(nameof(WholeHeaders))]
    public void A_header_split_across_buffer_segments_parses_as_one(string name, byte[] header)
    {
        var withTls = header.Concat(ClientHelloStart).ToArray();
        for (var split = 1; split < withTls.Length; split++)
        {
            var result = ProxyProtocolParser.Parse(Segmented(withTls, split));
            Assert.True(result.Status == ProxyHeaderStatus.Complete, $"{name}: split at {split} gave {result.Status} ({result.Error})");
            Assert.Equal(header.Length, result.HeaderLength);
        }
    }

    [Theory]
    [MemberData(nameof(WholeHeaders))]
    public void The_header_length_stops_at_the_header_when_TLS_follows_in_the_same_read(string name, byte[] header)
    {
        var result = Parse(header.Concat(ClientHelloStart).ToArray());

        Assert.True(result.Status == ProxyHeaderStatus.Complete, name);
        Assert.Equal(header.Length, result.HeaderLength);
    }

    [Fact]
    public void A_wrong_byte_anywhere_in_the_signature_is_refused_as_soon_as_it_arrives()
    {
        var header = V2Tcp(Client4, Front4);
        for (var i = 1; i < 12; i++)
        {
            var bad = (byte[])header.Clone();
            bad[i] ^= 0x40;
            Assert.Equal(ProxyHeaderStatus.Invalid, Parse(bad).Status);
            Assert.Equal(ProxyHeaderStatus.Invalid, Parse(bad[..(i + 1)]).Status);
        }
    }

    [Fact]
    public void TLS_or_HTTP_instead_of_a_header_is_refused_at_the_first_byte_that_cannot_start_one()
    {
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse(ClientHelloStart[..1]).Status);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse("G"u8.ToArray()).Status);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse("PO"u8.ToArray()).Status);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse("POST / HTTP/1.1\r\n"u8.ToArray()).Status);
        Assert.Equal(ProxyHeaderStatus.Incomplete, Parse("PROX"u8.ToArray()).Status);
    }

    [Theory]
    [InlineData((byte)0x11)]
    [InlineData((byte)0x01)]
    [InlineData((byte)0x31)]
    [InlineData((byte)0xF1)]
    public void A_version_other_than_2_is_refused(byte versionCommand)
    {
        var header = V2Tcp(Client4, Front4);
        header[12] = versionCommand;

        var result = Parse(header);
        Assert.Equal(ProxyHeaderStatus.Invalid, result.Status);
        Assert.Contains("version", result.Error);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse(header[..13]).Status);
    }

    [Fact]
    public void A_command_other_than_local_or_proxy_is_refused()
    {
        var header = V2Tcp(Client4, Front4);
        header[12] = 0x22;
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse(header).Status);
    }

    [Theory]
    [InlineData((byte)0x12)]
    [InlineData((byte)0x22)]
    [InlineData((byte)0x31)]
    [InlineData((byte)0x32)]
    [InlineData((byte)0x10)]
    [InlineData((byte)0x41)]
    public void UDP_UNIX_and_unknown_families_are_refused_with_PROXY(byte familyProtocol)
    {
        var result = Parse(V2(0x21, familyProtocol, new byte[216]));
        Assert.Equal(ProxyHeaderStatus.Invalid, result.Status);
    }

    [Fact]
    public void A_length_over_the_cap_is_refused_before_the_payload_arrives()
    {
        var header = V2(0x21, 0x11, [], announcedLength: ProxyProtocolParser.MaxV2PayloadLength + 1);
        var result = Parse(header);

        Assert.Equal(ProxyHeaderStatus.Invalid, result.Status);
        Assert.Contains("1025", result.Error);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse(V2(0x20, 0x00, [], announcedLength: 0xFFFF)).Status);
    }

    [Fact]
    public void A_length_at_the_cap_is_accepted()
    {
        var tlvs = Tlv(0x04, new byte[ProxyProtocolParser.MaxV2PayloadLength - 12 - 3]);
        var header = V2Tcp(Client4, Front4, tlvs);

        Assert.Equal(16 + ProxyProtocolParser.MaxV2PayloadLength, header.Length);
        Assert.Equal(ProxyHeaderStatus.Complete, Parse(header).Status);
    }

    [Theory]
    [InlineData((byte)0x11, 11)]
    [InlineData((byte)0x21, 35)]
    [InlineData((byte)0x21, 12)]
    public void A_length_too_short_for_the_address_family_is_refused(byte familyProtocol, int length)
    {
        var result = Parse(V2(0x21, familyProtocol, new byte[length]));
        Assert.Equal(ProxyHeaderStatus.Invalid, result.Status);
    }

    [Theory]
    [InlineData("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n", "203.0.113.7", 51234)]
    [InlineData("PROXY TCP6 2001:db8::7 2001:db8::1 61000 8443\r\n", "2001:db8::7", 61000)]
    [InlineData("PROXY TCP6 ::ffff:203.0.113.7 ::1 0 65535\r\n", "::ffff:203.0.113.7", 0)]
    public void A_v1_line_gives_the_client_address_and_port(string line, string address, int port)
    {
        var bytes = Encoding.ASCII.GetBytes(line);
        var result = Parse(bytes.Concat(ClientHelloStart).ToArray());

        Assert.Equal(ProxyHeaderStatus.Complete, result.Status);
        Assert.Equal(1, result.Version);
        Assert.Equal(bytes.Length, result.HeaderLength);
        Assert.Equal(new IPEndPoint(IPAddress.Parse(address), port), result.Source);
    }

    [Theory]
    [InlineData("PROXY UNKNOWN\r\n")]
    [InlineData("PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n")]
    public void A_v1_unknown_line_keeps_the_peer(string line)
    {
        var result = Parse(Encoding.ASCII.GetBytes(line));
        Assert.Equal(ProxyHeaderStatus.Complete, result.Status);
        Assert.Null(result.Source);
    }

    [Theory]
    [InlineData("PROXY TCP4 203.0.113.7 198.51.100.1 51234\r\n")]
    [InlineData("PROXY TCP4  203.0.113.7 198.51.100.1 51234 443\r\n")]
    [InlineData("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443 \r\n")]
    [InlineData("PROXY TCP4 203.0.113.7 198.51.100.1 051234 443\r\n")]
    [InlineData("PROXY TCP4 203.0.113.7 198.51.100.1 65536 443\r\n")]
    [InlineData("PROXY TCP4 203.0.113.7 198.51.100.1 -1 443\r\n")]
    [InlineData("PROXY TCP4 127.1 198.51.100.1 1 443\r\n")]
    [InlineData("PROXY TCP4 0x7f.0.0.1 198.51.100.1 1 443\r\n")]
    [InlineData("PROXY TCP4 2001:db8::7 198.51.100.1 1 443\r\n")]
    [InlineData("PROXY TCP6 203.0.113.7 2001:db8::1 1 443\r\n")]
    [InlineData("PROXY TCP6 fe80::1%eth0 2001:db8::1 1 443\r\n")]
    [InlineData("PROXY UDP4 203.0.113.7 198.51.100.1 1 443\r\n")]
    [InlineData("PROXY TCP4 203.0.113.7 198.51.100.1 1 443\n")]
    [InlineData("PROXY \r\n")]
    [InlineData("proxy TCP4 203.0.113.7 198.51.100.1 1 443\r\n")]
    public void A_malformed_v1_line_is_refused(string line)
    {
        var result = Parse(Encoding.ASCII.GetBytes(line));
        Assert.True(result.Status == ProxyHeaderStatus.Invalid, $"'{line.TrimEnd()}' gave {result.Status}");
    }

    [Fact]
    public void A_v1_line_with_no_end_within_107_bytes_is_refused()
    {
        var line = Encoding.ASCII.GetBytes("PROXY TCP6 " + new string('1', 200));
        Assert.Equal(ProxyHeaderStatus.Incomplete, Parse(line[..106]).Status);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse(line[..107]).Status);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse(line).Status);
    }

    [Fact]
    public void A_v1_line_with_a_control_byte_is_refused()
    {
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse("PROXY TCP4 203.0.113.7\t198.51.100.1 1 443\r\n"u8.ToArray()).Status);
        Assert.Equal(ProxyHeaderStatus.Invalid, Parse("PROXY TCP4 203.0.113.7 198.51.100.1 1 443\0\r\n"u8.ToArray()).Status);
    }

    /// <summary>The bytes as a two-segment sequence split at <paramref name="split"/>.</summary>
    private static ReadOnlySequence<byte> Segmented(byte[] bytes, int split)
    {
        var first = new Segment(bytes.AsMemory(0, split), 0);
        var last = first.Append(bytes.AsMemory(split));
        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory, long runningIndex)
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory, RunningIndex + Memory.Length);
            Next = next;
            return next;
        }
    }
}
