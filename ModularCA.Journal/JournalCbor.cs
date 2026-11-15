using System.Formats.Cbor;

namespace ModularCA.Journal;

/// <summary>
/// Builds one CBOR map with unsigned integer keys in deterministic encoding (RFC 8949, section
/// 4.2): definite lengths, shortest integers, keys in ascending order. With unsigned integer
/// keys only, ascending numeric order is the bytewise order of the encoded keys, which is what
/// the deterministic encoding asks for. A member whose value is null is left out, so "absent"
/// has one encoding.
/// </summary>
public sealed class CborMapBuilder
{
    private readonly SortedDictionary<ulong, Action<CborWriter>> _members = new();

    /// <summary>Adds a text member, or nothing when <paramref name="value"/> is null.</summary>
    public CborMapBuilder Text(ulong key, string? value)
    {
        if (value != null) _members[key] = w => w.WriteTextString(value);
        return this;
    }

    /// <summary>Adds a byte string member, or nothing when <paramref name="value"/> is null.</summary>
    public CborMapBuilder Bytes(ulong key, byte[]? value)
    {
        if (value != null) _members[key] = w => w.WriteByteString(value);
        return this;
    }

    /// <summary>Adds an unsigned integer member, or nothing when <paramref name="value"/> is null.</summary>
    public CborMapBuilder UInt(ulong key, ulong? value)
    {
        if (value is ulong v) _members[key] = w => w.WriteUInt64(v);
        return this;
    }

    /// <summary>Adds a signed integer member, or nothing when <paramref name="value"/> is null.</summary>
    public CborMapBuilder Int(ulong key, long? value)
    {
        if (value is long v) _members[key] = w => w.WriteInt64(v);
        return this;
    }

    /// <summary>Adds a boolean member, or nothing when <paramref name="value"/> is null.</summary>
    public CborMapBuilder Bool(ulong key, bool? value)
    {
        if (value is bool v) _members[key] = w => w.WriteBoolean(v);
        return this;
    }

    /// <summary>Adds a nested map, or nothing when <paramref name="value"/> is null.</summary>
    public CborMapBuilder Map(ulong key, CborMapBuilder? value)
    {
        if (value != null) _members[key] = value.WriteTo;
        return this;
    }

    /// <summary>Adds an array of maps, or nothing when <paramref name="values"/> is null or empty.</summary>
    public CborMapBuilder MapArray(ulong key, IReadOnlyList<CborMapBuilder>? values)
    {
        if (values is { Count: > 0 })
        {
            _members[key] = w =>
            {
                w.WriteStartArray(values.Count);
                foreach (var value in values)
                    value.WriteTo(w);
                w.WriteEndArray();
            };
        }
        return this;
    }

    /// <summary>Writes the map to <paramref name="writer"/>.</summary>
    public void WriteTo(CborWriter writer)
    {
        writer.WriteStartMap(_members.Count);
        foreach (var (key, write) in _members)
        {
            writer.WriteUInt64(key);
            write(writer);
        }
        writer.WriteEndMap();
    }

    /// <summary>The map's deterministic encoding.</summary>
    public byte[] Encode()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical, convertIndefiniteLengthEncodings: false, allowMultipleRootLevelValues: false);
        WriteTo(writer);
        return writer.Encode();
    }
}

/// <summary>
/// A decoded CBOR map with unsigned integer keys. A member under a key the caller does not ask
/// for is never looked at, which is how a reader ignores a key it does not know; a member whose
/// key is not an unsigned integer is skipped.
/// </summary>
public sealed class CborMap
{
    private readonly Dictionary<ulong, object?> _members;

    private CborMap(Dictionary<ulong, object?> members) => _members = members;

    /// <summary>The keys present, for a reader that lists them.</summary>
    public IReadOnlyCollection<ulong> Keys => _members.Keys;

    /// <summary>
    /// Decodes a payload: exactly one CBOR map, nothing after it.
    /// </summary>
    /// <exception cref="FormatException">The bytes are not one well-formed CBOR map.</exception>
    public static CborMap Decode(ReadOnlyMemory<byte> payload)
    {
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Lax);
            if (reader.PeekState() != CborReaderState.StartMap)
                throw new FormatException("A journal payload is one CBOR map.");
            var map = ReadMap(reader, depth: 0);
            if (reader.BytesRemaining != 0)
                throw new FormatException("A journal payload is one CBOR map, with nothing after it.");
            return map;
        }
        catch (CborContentException ex)
        {
            throw new FormatException($"The payload is not well-formed CBOR: {ex.Message}", ex);
        }
        catch (InvalidOperationException ex)
        {
            throw new FormatException($"The payload is not well-formed CBOR: {ex.Message}", ex);
        }
    }

    private static CborMap ReadMap(CborReader reader, int depth)
    {
        if (depth > 16)
            throw new FormatException("The payload nests deeper than a journal payload does.");
        var members = new Dictionary<ulong, object?>();
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (reader.PeekState() == CborReaderState.UnsignedInteger)
            {
                var key = reader.ReadUInt64();
                members[key] = ReadValue(reader, depth + 1);
            }
            else
            {
                reader.SkipValue();
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();
        return new CborMap(members);
    }

    private static object? ReadValue(CborReader reader, int depth)
    {
        switch (reader.PeekState())
        {
            case CborReaderState.UnsignedInteger: return reader.ReadUInt64();
            case CborReaderState.NegativeInteger: return reader.ReadInt64();
            case CborReaderState.ByteString:
            case CborReaderState.StartIndefiniteLengthByteString: return reader.ReadByteString();
            case CborReaderState.TextString:
            case CborReaderState.StartIndefiniteLengthTextString: return reader.ReadTextString();
            case CborReaderState.Boolean: return reader.ReadBoolean();
            case CborReaderState.Null: reader.ReadNull(); return null;
            case CborReaderState.StartMap: return ReadMap(reader, depth);
            case CborReaderState.StartArray:
            {
                if (depth > 16)
                    throw new FormatException("The payload nests deeper than a journal payload does.");
                var items = new List<object?>();
                reader.ReadStartArray();
                while (reader.PeekState() != CborReaderState.EndArray)
                    items.Add(ReadValue(reader, depth + 1));
                reader.ReadEndArray();
                return items;
            }
            default:
                // A tag, a float or a simple value: nothing this layout writes. Skipped, as an
                // unknown member is.
                reader.SkipValue();
                return null;
        }
    }

    /// <summary>The text under <paramref name="key"/>, or null when absent or of another kind.</summary>
    public string? Text(ulong key) => _members.TryGetValue(key, out var v) ? v as string : null;

    /// <summary>The bytes under <paramref name="key"/>, or null when absent or of another kind.</summary>
    public byte[]? Bytes(ulong key) => _members.TryGetValue(key, out var v) ? v as byte[] : null;

    /// <summary>The unsigned integer under <paramref name="key"/>, or null when absent or of another kind.</summary>
    public ulong? UInt(ulong key) => _members.TryGetValue(key, out var v) && v is ulong u ? u : null;

    /// <summary>The integer under <paramref name="key"/>, or null when absent, of another kind or out of range.</summary>
    public long? Int(ulong key)
    {
        if (!_members.TryGetValue(key, out var v)) return null;
        return v switch
        {
            long l => l,
            ulong u when u <= long.MaxValue => (long)u,
            _ => null,
        };
    }

    /// <summary>The boolean under <paramref name="key"/>, or null when absent or of another kind.</summary>
    public bool? Bool(ulong key) => _members.TryGetValue(key, out var v) && v is bool b ? b : null;

    /// <summary>The map under <paramref name="key"/>, or null when absent or of another kind.</summary>
    public CborMap? Map(ulong key) => _members.TryGetValue(key, out var v) ? v as CborMap : null;

    /// <summary>The maps in the array under <paramref name="key"/>; empty when absent. Items that are not maps are left out.</summary>
    public IReadOnlyList<CborMap> MapArray(ulong key)
        => _members.TryGetValue(key, out var v) && v is List<object?> list
            ? list.OfType<CborMap>().ToList()
            : Array.Empty<CborMap>();

    /// <summary>The text under <paramref name="key"/>.</summary>
    /// <exception cref="FormatException">The member is absent or not text.</exception>
    public string RequireText(ulong key) => Text(key) ?? throw Missing(key, "text");

    /// <summary>The bytes under <paramref name="key"/>.</summary>
    /// <exception cref="FormatException">The member is absent or not a byte string.</exception>
    public byte[] RequireBytes(ulong key) => Bytes(key) ?? throw Missing(key, "a byte string");

    /// <summary>The unsigned integer under <paramref name="key"/>.</summary>
    /// <exception cref="FormatException">The member is absent or not an unsigned integer.</exception>
    public ulong RequireUInt(ulong key) => UInt(key) ?? throw Missing(key, "an unsigned integer");

    /// <summary>The integer under <paramref name="key"/>.</summary>
    /// <exception cref="FormatException">The member is absent or not an integer.</exception>
    public long RequireInt(ulong key) => Int(key) ?? throw Missing(key, "an integer");

    /// <summary>The map under <paramref name="key"/>.</summary>
    /// <exception cref="FormatException">The member is absent or not a map.</exception>
    public CborMap RequireMap(ulong key) => Map(key) ?? throw Missing(key, "a map");

    private static FormatException Missing(ulong key, string kind)
        => new($"The payload has no member {key}, or it is not {kind}.");
}
