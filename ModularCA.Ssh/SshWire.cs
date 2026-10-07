using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Math;

namespace ModularCA.Ssh;

/// <summary>
/// Writes the SSH wire encoding (RFC 4251 section 5): big-endian integers, length-prefixed
/// strings and mpints.
/// </summary>
public sealed class SshWriter
{
    private readonly MemoryStream _buffer = new();

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Appends one byte.</summary>
    public SshWriter Byte(byte value)
    {
        _buffer.WriteByte(value);
        return this;
    }

    /// <summary>Appends a big-endian uint32.</summary>
    public SshWriter UInt32(uint value)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, value);
        _buffer.Write(b);
        return this;
    }

    /// <summary>Appends a big-endian uint64.</summary>
    public SshWriter UInt64(ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(b, value);
        _buffer.Write(b);
        return this;
    }

    /// <summary>Appends bytes with no length prefix.</summary>
    public SshWriter Raw(ReadOnlySpan<byte> bytes)
    {
        _buffer.Write(bytes);
        return this;
    }

    /// <summary>Appends a length-prefixed byte string.</summary>
    public SshWriter String(ReadOnlySpan<byte> bytes)
    {
        UInt32(checked((uint)bytes.Length));
        _buffer.Write(bytes);
        return this;
    }

    /// <summary>Appends a length-prefixed UTF-8 string.</summary>
    public SshWriter String(string text) => String(StrictUtf8.GetBytes(text));

    /// <summary>Appends a non-negative integer as an mpint: minimal two's complement, empty for zero.</summary>
    public SshWriter MPInt(BigInteger value)
    {
        if (value.SignValue < 0)
            throw new ArgumentOutOfRangeException(nameof(value), "SSH mpints written here are never negative.");
        return String(value.SignValue == 0 ? [] : value.ToByteArray());
    }

    /// <summary>Returns the bytes written so far.</summary>
    public byte[] ToArray() => _buffer.ToArray();
}

/// <summary>
/// Reads the SSH wire encoding. Every read is bounds-checked and throws
/// <see cref="FormatException"/> on truncated or malformed input.
/// </summary>
public sealed class SshReader
{
    private readonly byte[] _data;
    private int _offset;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Reads from the whole of <paramref name="data"/>.</summary>
    public SshReader(byte[] data)
    {
        _data = data;
    }

    /// <summary>The read position, in bytes from the start.</summary>
    public int Position => _offset;

    /// <summary>True when every byte has been read.</summary>
    public bool AtEnd => _offset == _data.Length;

    /// <summary>Reads one byte.</summary>
    public byte Byte() => Take(1)[0];

    /// <summary>Reads a big-endian uint32.</summary>
    public uint UInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

    /// <summary>Reads a big-endian uint64.</summary>
    public ulong UInt64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));

    /// <summary>Reads a length-prefixed byte string.</summary>
    public byte[] String()
    {
        var length = UInt32();
        if (length > (uint)(_data.Length - _offset))
            throw new FormatException("SSH string runs past the end of the data.");
        return Take((int)length).ToArray();
    }

    /// <summary>Reads a length-prefixed string that must be valid UTF-8.</summary>
    public string Utf8String()
    {
        try
        {
            return StrictUtf8.GetString(String());
        }
        catch (DecoderFallbackException)
        {
            throw new FormatException("SSH string is not valid UTF-8.");
        }
    }

    /// <summary>Reads an mpint that must be non-negative.</summary>
    public BigInteger MPInt()
    {
        var bytes = String();
        if (bytes.Length == 0)
            return BigInteger.Zero;
        if ((bytes[0] & 0x80) != 0)
            throw new FormatException("Negative mpint.");
        return new BigInteger(1, bytes);
    }

    /// <summary>Returns a copy of the bytes from <paramref name="start"/> up to the read position.</summary>
    public byte[] Slice(int start) => _data.AsSpan(start, _offset - start).ToArray();

    /// <summary>Throws unless every byte has been read.</summary>
    public void EnsureEnd(string what)
    {
        if (!AtEnd)
            throw new FormatException($"Trailing data after the {what}.");
    }

    private ReadOnlySpan<byte> Take(int count)
    {
        if (count > _data.Length - _offset)
            throw new FormatException("SSH data is truncated.");
        var span = _data.AsSpan(_offset, count);
        _offset += count;
        return span;
    }
}
