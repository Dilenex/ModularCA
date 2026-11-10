using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Hsm;

/// <summary>The outcome of binding a CA's key on a token.</summary>
/// <param name="Key">The private key object to sign with; null when none is.</param>
/// <param name="Refusal">Why a key that was found is not used; null when one is bound or none carries the label.</param>
public sealed record Pkcs11KeyBinding(IObjectHandle? Key, string? Refusal)
{
    /// <summary>No private key object carries the label.</summary>
    public bool NotFound => Key == null && Refusal == null;
}

/// <summary>
/// Binds a CA's key on a PKCS#11 token to the CA's certificate. The label finds the private key
/// object; it is used only when it is the one private key object carrying that label, it passes
/// the HSM-containment check, and the public key the token reports for it is the certificate's
/// public key. A wrong, swapped or duplicated label therefore binds nothing, rather than making
/// the CA sign with a key its certificate does not carry, or with another CA's key.
/// </summary>
/// <remarks>
/// The signer binds each key once, when it loads its PKCS#11 signers at startup, and keeps the
/// verdict for the life of the session: a bound key is registered against its certificate and a
/// refused one never is. Object handles are only valid for the session that found them, so a
/// token re-provisioned underneath a running signer needs a restart whatever this class does,
/// and checking at every signature would add a token round trip under the session lock to each
/// one for no gain.
/// </remarks>
public static class Pkcs11KeyBinder
{
    /// <summary>
    /// Finds the private key object labelled <paramref name="label"/> on <paramref name="token"/>
    /// and binds it to <paramref name="certificate"/> if, and only if, it is the only one with
    /// that label, it is held the way an HSM key must be, and its public key is the certificate's.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="label">The CA's key label (<c>HsmKeyLabel</c>).</param>
    /// <param name="certificate">The CA certificate the key must belong to.</param>
    /// <returns>The bound key, the reason a key carrying the label was refused, or neither when no key carries it.</returns>
    public static Pkcs11KeyBinding Bind(IPkcs11Token token, string label, X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(certificate);

        var candidates = token.FindPrivateKeysByLabel(label);
        if (candidates.Count == 0)
            return new Pkcs11KeyBinding(null, null);
        if (candidates.Count > 1)
            return Refused($"{candidates.Count} private key objects carry the label '{label}'; a label must name exactly one key, so none of them is used.");

        var key = candidates[0];
        if (!token.IsHsmContained(key, $"label='{label}'"))
            return Refused($"the private key labelled '{label}' does not satisfy the HSM-containment policy " +
                "(CKA_TOKEN, CKA_PRIVATE and CKA_SENSITIVE true, CKA_EXTRACTABLE false).");

        Pkcs11PublicKeyMaterial material;
        try
        {
            material = token.ReadPublicKey(key, label);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Pkcs11Exception)
        {
            return Refused($"the public key of the private key labelled '{label}' could not be read from the token: {ex.Message}");
        }

        var mismatch = Compare(material, certificate.GetPublicKey());
        return mismatch == null
            ? new Pkcs11KeyBinding(key, null)
            : Refused($"the key labelled '{label}' is not the certificate's key: {mismatch}.");
    }

    /// <summary>
    /// Compares the public key a token reports with a certificate's public key, value by value:
    /// the RSA modulus and exponent as integers; the EC curve and the point decoded on the
    /// certificate's curve, so a wrapped, raw or compressed point compares by what it is; the
    /// EdDSA curve and raw key. Returns null when they are the same key, otherwise what differs.
    /// </summary>
    /// <param name="tokenKey">What the token reports.</param>
    /// <param name="certificateKey">The certificate's public key.</param>
    public static string? Compare(Pkcs11PublicKeyMaterial tokenKey, AsymmetricKeyParameter certificateKey)
    {
        ArgumentNullException.ThrowIfNull(tokenKey);
        ArgumentNullException.ThrowIfNull(certificateKey);

        return certificateKey switch
        {
            RsaKeyParameters rsa => CompareRsa(tokenKey, rsa),
            ECPublicKeyParameters ec => CompareEc(tokenKey, ec),
            Ed25519PublicKeyParameters ed => CompareEdwards(tokenKey, ed.GetEncoded(), EdECObjectIdentifiers.id_Ed25519, "edwards25519", "Ed25519"),
            Ed448PublicKeyParameters ed => CompareEdwards(tokenKey, ed.GetEncoded(), EdECObjectIdentifiers.id_Ed448, "edwards448", "Ed448"),
            _ => $"a {certificateKey.GetType().Name} certificate key cannot be compared with a PKCS#11 key",
        };
    }

    /// <summary>Compares an RSA token key's modulus and public exponent with the certificate's.</summary>
    private static string? CompareRsa(Pkcs11PublicKeyMaterial tokenKey, RsaKeyParameters certificateKey)
    {
        if (tokenKey.KeyType != Pkcs11PublicKeyMaterial.CkkRsa)
            return $"the certificate holds an RSA key but the token key ({tokenKey.Source}) is of type {DescribeKeyType(tokenKey.KeyType)}";
        if (tokenKey.Modulus is not { Length: > 0 } || tokenKey.PublicExponent is not { Length: > 0 })
            return $"the RSA modulus or public exponent of the token key ({tokenKey.Source}) is empty";
        if (!new BigInteger(1, tokenKey.Modulus).Equals(certificateKey.Modulus))
            return $"the RSA modulus of the token key ({tokenKey.Source}) differs from the certificate's";
        if (!new BigInteger(1, tokenKey.PublicExponent).Equals(certificateKey.Exponent))
            return $"the RSA public exponent of the token key ({tokenKey.Source}) differs from the certificate's";
        return null;
    }

    /// <summary>Compares an EC token key's curve and point with the certificate's.</summary>
    private static string? CompareEc(Pkcs11PublicKeyMaterial tokenKey, ECPublicKeyParameters certificateKey)
    {
        if (tokenKey.KeyType != Pkcs11PublicKeyMaterial.CkkEc)
            return $"the certificate holds an EC key but the token key ({tokenKey.Source}) is of type {DescribeKeyType(tokenKey.KeyType)}";
        if (tokenKey.EcParams is not { Length: > 0 } || tokenKey.EcPoint is not { Length: > 0 })
            return $"the EC parameters or point of the token key ({tokenKey.Source}) are empty";

        var tokenCurve = ParseOid(tokenKey.EcParams);
        if (tokenCurve == null)
            return $"the curve of the token key ({tokenKey.Source}) is not given as a named-curve OID";
        var domain = certificateKey.Parameters;
        if (domain is ECNamedDomainParameters named)
        {
            if (!named.Name.Equals(tokenCurve))
                return $"the token key ({tokenKey.Source}) is on curve {tokenCurve.Id}, the certificate's on {named.Name.Id}";
        }
        else
        {
            var x9 = ECNamedCurveTable.GetByOid(tokenCurve);
            if (x9 == null || !x9.Curve.Equals(domain.Curve)
                || !x9.G.GetEncoded(false).AsSpan().SequenceEqual(domain.G.GetEncoded(false)))
                return $"the token key ({tokenKey.Source}) is on curve {tokenCurve.Id}, which is not the certificate's curve";
        }

        var point = DecodePoint(domain.Curve, tokenKey.EcPoint);
        if (point == null)
            return $"the EC point of the token key ({tokenKey.Source}) is not a point on the certificate's curve";
        if (!point.GetEncoded(false).AsSpan().SequenceEqual(certificateKey.Q.GetEncoded(false)))
            return $"the EC point of the token key ({tokenKey.Source}) differs from the certificate's";
        return null;
    }

    /// <summary>Compares an EdDSA token key's curve and raw public key with the certificate's.</summary>
    private static string? CompareEdwards(Pkcs11PublicKeyMaterial tokenKey, byte[] certificateKey, DerObjectIdentifier oid, string curveName, string algorithm)
    {
        if (tokenKey.KeyType != Pkcs11PublicKeyMaterial.CkkEcEdwards)
            return $"the certificate holds an {algorithm} key but the token key ({tokenKey.Source}) is of type {DescribeKeyType(tokenKey.KeyType)}";
        if (tokenKey.EcParams is not { Length: > 0 } || tokenKey.EcPoint is not { Length: > 0 })
            return $"the EC parameters or point of the token key ({tokenKey.Source}) are empty";
        if (!NamesEdwardsCurve(tokenKey.EcParams, oid, curveName))
            return $"the curve of the token key ({tokenKey.Source}) is not {curveName}, the certificate's";

        var raw = Unwrap(tokenKey.EcPoint, certificateKey.Length);
        if (raw == null || !raw.AsSpan().SequenceEqual(certificateKey))
            return $"the {algorithm} public key of the token key ({tokenKey.Source}) differs from the certificate's";
        return null;
    }

    /// <summary>
    /// Whether <c>CKA_EC_PARAMS</c> names the Edwards curve: PKCS#11 3.0 allows the curve's OID
    /// or its name as a DER PrintableString.
    /// </summary>
    private static bool NamesEdwardsCurve(byte[] ecParams, DerObjectIdentifier oid, string curveName)
    {
        try
        {
            return Asn1Object.FromByteArray(ecParams) switch
            {
                DerObjectIdentifier o => o.Equals(oid),
                DerPrintableString s => string.Equals(s.GetString(), curveName, StringComparison.Ordinal),
                _ => false,
            };
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidCastException)
        {
            return false;
        }
    }

    /// <summary>The OID <paramref name="ecParams"/> encodes, or null when it is not one (explicit parameters, garbage).</summary>
    private static DerObjectIdentifier? ParseOid(byte[] ecParams)
    {
        try
        {
            return Asn1Object.FromByteArray(ecParams) as DerObjectIdentifier;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidCastException)
        {
            return null;
        }
    }

    /// <summary>
    /// Decodes <c>CKA_EC_POINT</c> on <paramref name="curve"/>. The standard says the point is a
    /// DER OCTET STRING; some tokens return the bare point, which (uncompressed) also starts with
    /// 0x04. The wrapped reading is tried first and the bare one second; a misreading cannot
    /// produce a valid point, since a point encoding has a fixed length for its curve.
    /// </summary>
    private static ECPoint? DecodePoint(ECCurve curve, byte[] ecPoint)
    {
        var inner = UnwrapOctetString(ecPoint);
        if (inner != null && TryDecode(curve, inner) is { } wrapped)
            return wrapped;
        return TryDecode(curve, ecPoint);
    }

    /// <summary>Decodes <paramref name="encoded"/> as a point on <paramref name="curve"/>, or null when it is not one.</summary>
    private static ECPoint? TryDecode(ECCurve curve, byte[] encoded)
    {
        try
        {
            var point = curve.DecodePoint(encoded);
            return point.IsValid() && !point.IsInfinity ? point : null;
        }
        catch (Exception ex) when (ex is ArgumentException or ArithmeticException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// The raw EdDSA key from <c>CKA_EC_POINT</c>: the content of a DER OCTET STRING of
    /// <paramref name="length"/> bytes, or the bare value when it already has that length.
    /// </summary>
    private static byte[]? Unwrap(byte[] ecPoint, int length)
    {
        var inner = UnwrapOctetString(ecPoint);
        if (inner != null && inner.Length == length)
            return inner;
        return ecPoint.Length == length ? ecPoint : null;
    }

    /// <summary>The content of <paramref name="der"/> when it is exactly one DER OCTET STRING, otherwise null.</summary>
    private static byte[]? UnwrapOctetString(byte[] der)
    {
        try
        {
            return Asn1Object.FromByteArray(der) is Asn1OctetString octets ? octets.GetOctets() : null;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidCastException)
        {
            return null;
        }
    }

    /// <summary>A <c>CKA_KEY_TYPE</c> value by name, for messages.</summary>
    private static string DescribeKeyType(ulong keyType) => keyType switch
    {
        Pkcs11PublicKeyMaterial.CkkRsa => "CKK_RSA",
        Pkcs11PublicKeyMaterial.CkkEc => "CKK_EC",
        Pkcs11PublicKeyMaterial.CkkEcEdwards => "CKK_EC_EDWARDS",
        _ => $"0x{keyType:X}",
    };

    /// <summary>A refusal with <paramref name="reason"/>.</summary>
    private static Pkcs11KeyBinding Refused(string reason) => new(null, reason);
}
