namespace ModularCA.Keystore.Hsm;

/// <summary>
/// A public key as a PKCS#11 token reports it, attribute by attribute, before anything is built
/// from it: the key type, and either the RSA modulus and public exponent or the EC parameters
/// and point. <see cref="Pkcs11KeyBinder.Compare"/> holds it against a certificate's key.
/// </summary>
/// <param name="KeyType">The <c>CKA_KEY_TYPE</c> value: <see cref="CkkRsa"/>, <see cref="CkkEc"/> or <see cref="CkkEcEdwards"/>.</param>
/// <param name="Modulus">The RSA <c>CKA_MODULUS</c>, big-endian unsigned; null for other key types.</param>
/// <param name="PublicExponent">The RSA <c>CKA_PUBLIC_EXPONENT</c>, big-endian unsigned; null for other key types.</param>
/// <param name="EcParams">The <c>CKA_EC_PARAMS</c> DER (a named-curve OID, or for EdDSA a curve name); null for RSA.</param>
/// <param name="EcPoint">The <c>CKA_EC_POINT</c>, DER OCTET STRING wrapped as the standard says or raw as some tokens return it; null for RSA.</param>
/// <param name="Source">Which object the values were read from, for the message a mismatch reports.</param>
public sealed record Pkcs11PublicKeyMaterial(
    ulong KeyType,
    byte[]? Modulus,
    byte[]? PublicExponent,
    byte[]? EcParams,
    byte[]? EcPoint,
    string Source)
{
    /// <summary><c>CKK_RSA</c>.</summary>
    public const ulong CkkRsa = 0x00000000;

    /// <summary><c>CKK_EC</c> (also <c>CKK_ECDSA</c>).</summary>
    public const ulong CkkEc = 0x00000003;

    /// <summary><c>CKK_EC_EDWARDS</c> (PKCS#11 3.0): Ed25519 and Ed448 keys.</summary>
    public const ulong CkkEcEdwards = 0x00000040;

    /// <summary>An RSA public key read from <paramref name="source"/>.</summary>
    public static Pkcs11PublicKeyMaterial Rsa(byte[] modulus, byte[] publicExponent, string source)
        => new(CkkRsa, modulus, publicExponent, null, null, source);

    /// <summary>An EC or EdDSA public key of type <paramref name="keyType"/> read from <paramref name="source"/>.</summary>
    public static Pkcs11PublicKeyMaterial Ec(ulong keyType, byte[] ecParams, byte[] ecPoint, string source)
        => new(keyType, null, null, ecParams, ecPoint, source);
}
