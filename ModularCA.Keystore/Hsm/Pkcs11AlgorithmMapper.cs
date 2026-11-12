using Net.Pkcs11Interop.Common;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// Maps BouncyCastle algorithm names to PKCS#11 CKM mechanism constants, with the mechanism
/// parameters each needs, used for signing and key generation operations on an HSM.
/// </summary>
public static class Pkcs11AlgorithmMapper
{
    /// <summary><c>CKM_EDDSA</c> (PKCS#11 3.0), which Pkcs11Interop 5 does not name.</summary>
    private const CKM CkmEddsa = (CKM)0x00001057;

    /// <summary>
    /// The mechanism for each algorithm name, with its parameters. The RSA-PSS parameters are
    /// those of the <c>RSASSA-PSS-params</c> BouncyCastle writes for the same name (and so the
    /// signer's signature factory writes into the certificate or CRL): the named hash, MGF1 with
    /// that hash, and a salt as long as the hash. Ed448 takes <c>CK_EDDSA_PARAMS</c> for pure
    /// EdDSA with no context, as PKCS#11 3.0 requires; Ed25519 takes none, since with parameters
    /// a token may sign Ed25519ctx instead of the pure Ed25519 its AlgorithmIdentifier names.
    /// </summary>
    private static readonly Dictionary<string, Pkcs11SignMechanism> SignMechanisms = new(StringComparer.OrdinalIgnoreCase)
    {
        // PKCS#1 v1.5 RSA padding
        ["SHA256withRSA"]   = new(CKM.CKM_SHA256_RSA_PKCS),
        ["SHA384withRSA"]   = new(CKM.CKM_SHA384_RSA_PKCS),
        ["SHA512withRSA"]   = new(CKM.CKM_SHA512_RSA_PKCS),
        // RSA-PSS padding (NIST SP 800-131A Rev 2 recommended)
        ["SHA256withRSAandMGF1"] = new(CKM.CKM_SHA256_RSA_PKCS_PSS, new Pkcs11PssParameters(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32)),
        ["SHA384withRSAandMGF1"] = new(CKM.CKM_SHA384_RSA_PKCS_PSS, new Pkcs11PssParameters(CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384, 48)),
        ["SHA512withRSAandMGF1"] = new(CKM.CKM_SHA512_RSA_PKCS_PSS, new Pkcs11PssParameters(CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512, 64)),
        // ECDSA
        ["SHA256withECDSA"] = new(CKM.CKM_ECDSA_SHA256),
        ["SHA384withECDSA"] = new(CKM.CKM_ECDSA_SHA384),
        ["SHA512withECDSA"] = new(CKM.CKM_ECDSA_SHA512),
        // EdDSA
        ["Ed25519"]         = new(CkmEddsa),
        ["Ed448"]           = new(CkmEddsa, Eddsa: new Pkcs11EddsaParameters(PreHash: false)),
    };

    private static readonly Dictionary<string, CKM> KeyGenMechanisms = new(StringComparer.OrdinalIgnoreCase)
    {
        ["RSA"] = CKM.CKM_RSA_PKCS_KEY_PAIR_GEN,
        ["EC"]  = CKM.CKM_EC_KEY_PAIR_GEN,
    };

    /// <summary>
    /// Returns the PKCS#11 signing mechanism, with the parameters it needs, corresponding to a
    /// BouncyCastle algorithm name.
    /// </summary>
    /// <param name="bcAlgorithmName">
    /// BouncyCastle-style algorithm identifier (e.g. "SHA256withRSA", "SHA384withECDSA", "Ed25519").
    /// </param>
    /// <returns>The matching mechanism and its parameters.</returns>
    /// <exception cref="NotSupportedException">Thrown when the algorithm name is not recognised.</exception>
    public static Pkcs11SignMechanism GetSignMechanism(string bcAlgorithmName)
    {
        if (SignMechanisms.TryGetValue(bcAlgorithmName, out var mechanism))
            return mechanism;

        throw new NotSupportedException(
            $"Unsupported signing algorithm '{bcAlgorithmName}'. " +
            $"Supported: {string.Join(", ", SignMechanisms.Keys)}");
    }

    /// <summary>
    /// Whether <paramref name="mechanism"/> is an ECDSA mechanism, whose signature a token
    /// returns as raw <c>r || s</c> rather than the DER X.509 carries.
    /// </summary>
    /// <param name="mechanism">The signing mechanism.</param>
    public static bool IsEcdsa(CKM mechanism) => mechanism is CKM.CKM_ECDSA
        or CKM.CKM_ECDSA_SHA1 or CKM.CKM_ECDSA_SHA224 or CKM.CKM_ECDSA_SHA256
        or CKM.CKM_ECDSA_SHA384 or CKM.CKM_ECDSA_SHA512;

    /// <summary>
    /// Returns the PKCS#11 key-pair generation mechanism for the given key algorithm family.
    /// </summary>
    /// <param name="keyAlgorithm">Key algorithm family, e.g. "RSA" or "EC".</param>
    /// <returns>The matching <see cref="CKM"/> key generation constant.</returns>
    /// <exception cref="NotSupportedException">Thrown when the key algorithm is not recognised.</exception>
    public static CKM GetKeyGenMechanism(string keyAlgorithm)
    {
        if (KeyGenMechanisms.TryGetValue(keyAlgorithm, out var mechanism))
            return mechanism;

        throw new NotSupportedException(
            $"Unsupported key algorithm '{keyAlgorithm}'. " +
            $"Supported: {string.Join(", ", KeyGenMechanisms.Keys)}");
    }
}
