using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace ModularCA.Ssh;

/// <summary>
/// An OpenSSH public key: its type, its wire-format blob and the equivalent BouncyCastle key.
/// Parsing is strict: the blob must be complete, have no trailing bytes, and hold a valid key.
/// </summary>
public sealed class SshPublicKey : IEquatable<SshPublicKey>
{
    /// <summary>The longest authorized_keys line accepted, matching what the node accepts today.</summary>
    public const int MaxAuthorizedKeyLength = 16384;

    private SshPublicKey(string keyType, byte[] blob, AsymmetricKeyParameter key, int keySizeBits, string? comment)
    {
        KeyType = keyType;
        _blob = blob;
        KeyParameter = key;
        KeySizeBits = keySizeBits;
        Comment = comment;
    }

    private readonly byte[] _blob;

    /// <summary>The key type name, for example <c>ssh-ed25519</c> or <c>ecdsa-sha2-nistp384</c>.</summary>
    public string KeyType { get; }

    /// <summary>A copy of the wire-format public key blob, type string included.</summary>
    public byte[] Blob => (byte[])_blob.Clone();

    /// <summary>The key as a BouncyCastle public key parameter.</summary>
    public AsymmetricKeyParameter KeyParameter { get; }

    /// <summary>The key size: the RSA or DSA modulus length, the curve size, or 256 for Ed25519.</summary>
    public int KeySizeBits { get; }

    /// <summary>The comment from an authorized_keys line, when the key was parsed from one.</summary>
    public string? Comment { get; }

    /// <summary>The OpenSSH SHA-256 fingerprint, <c>SHA256:</c> and unpadded base64.</summary>
    public string Fingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(_blob)).TrimEnd('=');

    /// <summary>The key-specific fields after the type string, as a certificate embeds them.</summary>
    internal ReadOnlySpan<byte> KeyFields => _blob.AsSpan(4 + System.Text.Encoding.UTF8.GetByteCount(KeyType));

    /// <summary>
    /// Parses one authorized_keys style line, <c>type base64 [comment]</c>. Options before the type,
    /// several lines, certificates and security-key (<c>sk-</c>) types are refused.
    /// </summary>
    /// <exception cref="FormatException">The line is not a single supported public key.</exception>
    public static SshPublicKey ParseAuthorizedKey(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        var trimmed = line.Trim();
        if (trimmed.Length == 0)
            throw new FormatException("The public key is empty.");
        if (trimmed.Length > MaxAuthorizedKeyLength)
            throw new FormatException("The public key is too long.");
        if (trimmed.Contains('\n') || trimmed.Contains('\r'))
            throw new FormatException("Give exactly one public key, on one line.");

        var parts = trimmed.Split([' ', '\t'], 3, StringSplitOptions.RemoveEmptyEntries);
        var type = parts[0];
        if (type.EndsWith(SshKeyTypes.CertificateSuffix, StringComparison.Ordinal))
            throw new FormatException("This is an SSH certificate, not a public key.");
        if (type.StartsWith("sk-", StringComparison.Ordinal))
            throw new FormatException("Security key (sk-) public keys are not supported.");
        if (!SshKeyTypes.Certifiable.Contains(type) && type != SshKeyTypes.Dss)
            throw new FormatException("Not an OpenSSH public key of a supported type (Ed25519, ECDSA or RSA).");
        if (parts.Length < 2)
            throw new FormatException("The public key has no key data.");

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException)
        {
            throw new FormatException("The public key data is not valid base64.");
        }

        var key = FromBlob(blob, parts.Length > 2 ? parts[2].Trim() : null);
        if (key.KeyType != type)
            throw new FormatException($"The key data is a {key.KeyType} key, but the line names {type}.");
        return key;
    }

    /// <summary>Parses a wire-format public key blob.</summary>
    /// <exception cref="FormatException">The blob is malformed or not a supported key type.</exception>
    public static SshPublicKey FromBlob(byte[] blob) => FromBlob(blob, null);

    private static SshPublicKey FromBlob(byte[] blob, string? comment)
    {
        ArgumentNullException.ThrowIfNull(blob);
        var reader = new SshReader(blob);
        var type = reader.Utf8String();
        var (key, bits) = ReadKeyFields(reader, type);
        reader.EnsureEnd("public key");
        return new SshPublicKey(type, (byte[])blob.Clone(), key, bits, string.IsNullOrEmpty(comment) ? null : comment);
    }

    /// <summary>Encodes a BouncyCastle Ed25519, ECDSA (P-256, P-384, P-521), RSA or DSA public key.</summary>
    /// <exception cref="ArgumentException">The key is private, or of a type or curve SSH does not carry.</exception>
    public static SshPublicKey FromKeyParameter(AsymmetricKeyParameter key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.IsPrivate)
            throw new ArgumentException("A public key is required.", nameof(key));

        var writer = new SshWriter();
        switch (key)
        {
            case Ed25519PublicKeyParameters ed:
                writer.String(SshKeyTypes.Ed25519).String(ed.GetEncoded());
                break;
            case ECPublicKeyParameters ec:
                var keyType = EcKeyTypeOf(ec.Parameters)
                    ?? throw new ArgumentException("Only the P-256, P-384 and P-521 curves have SSH key types.", nameof(key));
                writer.String(keyType).String(SshKeyTypes.CurveName(keyType)!).String(ec.Q.GetEncoded(false));
                break;
            case RsaKeyParameters rsa:
                writer.String(SshKeyTypes.Rsa).MPInt(rsa.Exponent).MPInt(rsa.Modulus);
                break;
            case DsaPublicKeyParameters dsa:
                writer.String(SshKeyTypes.Dss).MPInt(dsa.Parameters.P).MPInt(dsa.Parameters.Q)
                    .MPInt(dsa.Parameters.G).MPInt(dsa.Y);
                break;
            default:
                throw new ArgumentException($"{key.GetType().Name} has no SSH encoding.", nameof(key));
        }
        return FromBlob(writer.ToArray());
    }

    /// <summary>Renders the key as an authorized_keys line, <c>type base64 [comment]</c>.</summary>
    public string ToAuthorizedKey(string? comment = null)
    {
        var line = KeyType + " " + Convert.ToBase64String(_blob);
        return string.IsNullOrEmpty(comment) ? line : line + " " + comment;
    }

    /// <summary>
    /// Reads the key-specific fields of a key of <paramref name="type"/>, as a public key blob and a
    /// certificate both lay them out.
    /// </summary>
    internal static (AsymmetricKeyParameter Key, int Bits) ReadKeyFields(SshReader reader, string type)
    {
        switch (type)
        {
            case SshKeyTypes.Ed25519:
                var pk = reader.String();
                if (pk.Length != Ed25519PublicKeyParameters.KeySize)
                    throw new FormatException("An Ed25519 public key is 32 bytes.");
                try
                {
                    return (new Ed25519PublicKeyParameters(pk), 256);
                }
                catch (ArgumentException ex)
                {
                    throw new FormatException("The Ed25519 public key is not a valid point.", ex);
                }

            case SshKeyTypes.EcdsaP256 or SshKeyTypes.EcdsaP384 or SshKeyTypes.EcdsaP521:
                var curve = reader.Utf8String();
                if (curve != SshKeyTypes.CurveName(type))
                    throw new FormatException($"Curve '{curve}' does not match key type {type}.");
                var q = reader.String();
                if (q.Length == 0 || q[0] != 0x04)
                    throw new FormatException("An ECDSA public key must be an uncompressed point.");
                var domain = Domain(type);
                try
                {
                    var point = domain.Curve.DecodePoint(q);
                    if (point.IsInfinity)
                        throw new FormatException("The ECDSA public key is the point at infinity.");
                    return (new ECPublicKeyParameters("EC", point, domain), domain.Curve.FieldSize);
                }
                catch (Exception ex) when (ex is not FormatException)
                {
                    throw new FormatException("The ECDSA public key is not a point on its curve.", ex);
                }

            case SshKeyTypes.Rsa:
                var exponent = reader.MPInt();
                var modulus = reader.MPInt();
                if (modulus.SignValue <= 0 || exponent.CompareTo(BigInteger.Three) < 0 || !exponent.TestBit(0))
                    throw new FormatException("The RSA public key is malformed.");
                return (new RsaKeyParameters(false, modulus, exponent), modulus.BitLength);

            case SshKeyTypes.Dss:
                var p = reader.MPInt();
                var dq = reader.MPInt();
                var g = reader.MPInt();
                var y = reader.MPInt();
                if (p.SignValue <= 0 || dq.SignValue <= 0 || g.SignValue <= 0 || y.SignValue <= 0)
                    throw new FormatException("The DSA public key is malformed.");
                return (new DsaPublicKeyParameters(y, new DsaParameters(p, dq, g)), p.BitLength);

            default:
                throw new FormatException($"Unsupported SSH key type '{type}'.");
        }
    }

    /// <summary>The named curve domain for an ECDSA key type.</summary>
    public static ECNamedDomainParameters Domain(string keyType)
    {
        DerObjectIdentifier oid = keyType switch
        {
            SshKeyTypes.EcdsaP256 => SecObjectIdentifiers.SecP256r1,
            SshKeyTypes.EcdsaP384 => SecObjectIdentifiers.SecP384r1,
            SshKeyTypes.EcdsaP521 => SecObjectIdentifiers.SecP521r1,
            _ => throw new ArgumentException($"'{keyType}' is not an ECDSA key type.", nameof(keyType)),
        };
        return new ECNamedDomainParameters(oid, ECNamedCurveTable.GetByOid(oid));
    }

    private static string? EcKeyTypeOf(ECDomainParameters parameters)
    {
        foreach (var keyType in new[] { SshKeyTypes.EcdsaP256, SshKeyTypes.EcdsaP384, SshKeyTypes.EcdsaP521 })
        {
            var known = Domain(keyType);
            if (parameters is ECNamedDomainParameters named && named.Name.Equals(known.Name))
                return keyType;
            if (parameters.Curve.Equals(known.Curve) && parameters.G.Equals(known.G))
                return keyType;
        }
        return null;
    }

    /// <inheritdoc />
    public bool Equals(SshPublicKey? other) => other is not null && _blob.AsSpan().SequenceEqual(other._blob);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as SshPublicKey);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_blob);
        return hash.ToHashCode();
    }

    /// <inheritdoc />
    public override string ToString() => $"{KeyType} {Fingerprint}";
}
