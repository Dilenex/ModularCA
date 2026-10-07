using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Central key-algorithm policy for ModularCA. Single source of truth for:
/// <list type="bullet">
/// <item>which key algorithm + size/curve combinations are allowed to be used for CA and leaf certs</item>
/// <item>resolving a signature algorithm name from a key algorithm + size/curve (with curve-matched hash)</item>
/// <item>generating an allowed key pair (delegating to <see cref="KeyGenerationUtil"/>)</item>
/// </list>
/// This policy is enforced at request entry (controllers) AND at the generation chokepoint
/// so no caller can downgrade to weak algorithms. RSA is restricted to 2048/3072/4096/7680/8192
/// (CABF BR floor at 2048; 7680 is NIST SP 800-57's 192-bit-strength tier; 8192 is the
/// power-of-two future-proof option common on offline roots). ECDSA curves are restricted to
/// NIST P-256/P-384/P-521; Ed25519/Ed448 and FIPS 204/205 PQC are allowed; all other
/// algorithms (DSA, GOST, legacy RSA sizes, non-NIST curves) are rejected with
/// <see cref="ArgumentException"/>.
/// </summary>
public static class KeyAlgorithmPolicy
{
    private static volatile Func<string?> _rsaPadding = () => null;

    /// <summary>
    /// When <c>true</c>, RSA signature algorithms resolve to RSA-PSS (RSASSA-PSS with MGF1)
    /// instead of PKCS#1 v1.5. Asked on every use of the padding setting given to
    /// <see cref="FollowRsaPadding"/>, so a change to it applies to the next signature; PSS
    /// until a setting is given.
    /// </summary>
    public static bool UseRsaPss => IsPss(_rsaPadding());

    /// <summary>
    /// Makes <see cref="UseRsaPss"/> follow <paramref name="padding"/>, which returns
    /// <see cref="ModularCA.Shared.Models.Config.CertPolicyConfig.RsaSignaturePadding"/> as it
    /// stands when asked. Called once at startup.
    /// </summary>
    public static void FollowRsaPadding(Func<string?> padding) => _rsaPadding = padding;

    /// <summary>
    /// Whether a configured RSA signature padding means PSS: <c>"PSS"</c> in any case, or
    /// nothing configured. Any other value (<c>"v15"</c>) means PKCS#1 v1.5.
    /// </summary>
    public static bool IsPss(string? padding) => padding?.Equals("PSS", StringComparison.OrdinalIgnoreCase) ?? true;

    /// <summary>
    /// Returns true if the given key algorithm + size/curve is allowed by the CA policy.
    /// Accepts RSA 2048/3072/4096/7680/8192, ECDSA P-256/P-384/P-521 (curve name or bit size),
    /// Ed25519, Ed448, ML-DSA-44/65/87, and all SLH-DSA-SHA2/SHAKE parameter sets.
    /// </summary>
    public static bool IsAllowed(string algorithm, string? sizeOrCurve)
    {
        if (string.IsNullOrWhiteSpace(algorithm)) return false;
        switch (algorithm.ToUpperInvariant())
        {
            case "RSA":
                return sizeOrCurve is "2048" or "3072" or "4096" or "7680" or "8192";
            case "ECDSA":
                if (string.IsNullOrWhiteSpace(sizeOrCurve)) return false;
                return sizeOrCurve is "P-256" or "P-384" or "P-521"
                    or "secp256r1" or "secp384r1" or "secp521r1"
                    or "256" or "384" or "521";
            case "ED25519":
            case "ED448":
                return true;
            case "ML-DSA":
            case "ML-DSA-44":
            case "ML-DSA-65":
            case "ML-DSA-87":
            case "DILITHIUM":
                return true;
            case "SLH-DSA":
            case "SPHINCSPLUS":
            case "SLH-DSA-SHA2-128F":
            case "SLH-DSA-SHA2-128S":
            case "SLH-DSA-SHA2-192F":
            case "SLH-DSA-SHA2-192S":
            case "SLH-DSA-SHA2-256F":
            case "SLH-DSA-SHA2-256S":
            case "SLH-DSA-SHAKE-128F":
            case "SLH-DSA-SHAKE-128S":
            case "SLH-DSA-SHAKE-192F":
            case "SLH-DSA-SHAKE-192S":
            case "SLH-DSA-SHAKE-256F":
            case "SLH-DSA-SHAKE-256S":
                return true;
            default:
                return false;
        }
    }

    /// <summary>
    /// Integer-size overload of <see cref="IsAllowed(string, string)"/> for callers that deal
    /// with <see cref="int"/> key sizes (e.g. <c>CertificateRequestModel.KeySize</c>). ECDSA
    /// integer sizes are interpreted as bit sizes (256/384/521).
    /// </summary>
    public static bool IsAllowed(string algorithm, int sizeOrCurve)
        => IsAllowed(algorithm, sizeOrCurve.ToString());

    /// <summary>
    /// Resolves the canonical BouncyCastle signature algorithm name for the given key algorithm
    /// and size/curve. Pairs ECDSA curves with NIST-recommended hashes (P-256→SHA-256,
    /// P-384→SHA-384, P-521→SHA-512) per SP 800-57. For EdDSA and PQC the signature algorithm
    /// name equals the key algorithm name. Throws <see cref="ArgumentException"/> on unknown
    /// or disallowed combinations.
    /// </summary>
    public static string ResolveSignatureAlgorithm(string algorithm, string? sizeOrCurve)
    {
        if (!IsAllowed(algorithm, sizeOrCurve))
            throw new ArgumentException($"Key algorithm '{algorithm}' with size/curve '{sizeOrCurve}' is not permitted by KeyAlgorithmPolicy.");

        switch (algorithm.ToUpperInvariant())
        {
            case "RSA":
                return UseRsaPss ? "SHA256withRSAandMGF1" : "SHA256withRSA";
            case "ECDSA":
                return (sizeOrCurve ?? string.Empty) switch
                {
                    "P-384" or "secp384r1" or "384" => "SHA384withECDSA",
                    "P-521" or "secp521r1" or "521" => "SHA512withECDSA",
                    _ => "SHA256withECDSA",
                };
            case "ED25519":
                return "Ed25519";
            case "ED448":
                return "Ed448";
            case "ML-DSA":
            case "DILITHIUM":
                return "ML-DSA-65";
            case "ML-DSA-44":
                return "ML-DSA-44";
            case "ML-DSA-65":
                return "ML-DSA-65";
            case "ML-DSA-87":
                return "ML-DSA-87";
            case "SLH-DSA":
            case "SPHINCSPLUS":
                return "SLH-DSA-SHA2-128F";
            default:
                // SLH-DSA-* variants
                return algorithm.ToUpperInvariant();
        }
    }

    /// <summary>
    /// Integer-size overload of <see cref="ResolveSignatureAlgorithm(string, string)"/>.
    /// </summary>
    public static string ResolveSignatureAlgorithm(string algorithm, int sizeOrCurve)
        => ResolveSignatureAlgorithm(algorithm, sizeOrCurve.ToString());

    /// <summary>
    /// Generates a key pair after policy validation. Delegates to <see cref="KeyGenerationUtil.GenerateKeyPair"/>.
    /// Throws <see cref="ArgumentException"/> if the algorithm + size/curve is not allowed.
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateKeyPair(string algorithm, string sizeOrCurve)
    {
        if (!IsAllowed(algorithm, sizeOrCurve))
            throw new ArgumentException($"Key algorithm '{algorithm}' with size/curve '{sizeOrCurve}' is not permitted by KeyAlgorithmPolicy.");
        return KeyGenerationUtil.GenerateKeyPair(algorithm, NormalizeCurve(algorithm, sizeOrCurve));
    }

    /// <summary>
    /// Converts a numeric key size to the string format used by certificate profiles.
    /// ECDSA: 256→"P-256", 384→"P-384", 521→"P-521". RSA/others: numeric string.
    /// </summary>
    public static string FormatKeySizeForProfile(string algorithm, int sizeOrCurve) =>
        algorithm.ToUpperInvariant() switch
        {
            "ECDSA" => sizeOrCurve switch
            {
                256 => "P-256",
                384 => "P-384",
                521 => "P-521",
                _ => sizeOrCurve.ToString(),
            },
            _ => sizeOrCurve.ToString(),
        };

    /// <summary>
    /// Integer-size overload of <see cref="GenerateKeyPair(string, string)"/>. Integer ECDSA
    /// sizes are mapped to canonical curve names (256→P-256, 384→P-384, 521→P-521).
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateKeyPair(string algorithm, int sizeOrCurve)
        => GenerateKeyPair(algorithm, FormatKeySizeForProfile(algorithm, sizeOrCurve));

    /// <summary>
    /// Detects the key algorithm name from a BouncyCastle key parameter (e.g. "RSA", "ECDSA", "Ed25519").
    /// </summary>
    public static string DetectKeyAlgorithm(AsymmetricKeyParameter key) => key switch
    {
        RsaKeyParameters or RsaPrivateCrtKeyParameters => "RSA",
        ECPublicKeyParameters or ECPrivateKeyParameters => "ECDSA",
        Ed25519PublicKeyParameters or Ed25519PrivateKeyParameters => "Ed25519",
        Ed448PublicKeyParameters or Ed448PrivateKeyParameters => "Ed448",
        MLDsaPublicKeyParameters or MLDsaPrivateKeyParameters => "ML-DSA-65",
        SlhDsaPublicKeyParameters or SlhDsaPrivateKeyParameters => "SLH-DSA-SHA2-128F",
        _ => "Unknown"
    };

    /// <summary>
    /// Detects the key size from a BouncyCastle key parameter. Returns the numeric size
    /// (RSA bit length, ECDSA curve bit size, 0 for fixed-size algorithms).
    /// </summary>
    public static int DetectKeySize(AsymmetricKeyParameter key) => key switch
    {
        RsaKeyParameters rsa => rsa.Modulus.BitLength,
        ECPublicKeyParameters ec => ec.Parameters.Curve.FieldSize,
        ECPrivateKeyParameters ec => ec.Parameters.Curve.FieldSize,
        _ => 0
    };

    /// <summary>
    /// Resolves the signature algorithm that should be used when the supplied
    /// <paramref name="publicKey"/> is acting as the signing key (e.g. a CA signing its own CRL).
    /// This is distinct from the signature algorithm recorded on the CA's own certificate, which
    /// describes how the CA's parent signed the CA — using that for CRL signing breaks every
    /// subordinate whose own key type differs from its parent's. Routes through
    /// <see cref="ResolveSignatureAlgorithm(string, string)"/> so curve→hash pairing stays in one
    /// place.
    /// </summary>
    public static string ResolveSignatureAlgorithmForKey(AsymmetricKeyParameter publicKey)
    {
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));

        switch (publicKey)
        {
            case RsaKeyParameters:
                // Size doesn't matter for RSA sig-alg resolution — all RSA sizes
                // use the same hash. Pass "2048" as a placeholder to satisfy IsAllowed.
                return ResolveSignatureAlgorithm("RSA", "2048");

            case ECPublicKeyParameters ec:
            {
                var curve = ResolveEcCurveName(ec);
                return ResolveSignatureAlgorithm("ECDSA", curve);
            }

            case ECPrivateKeyParameters ecPriv:
            {
                var curve = ResolveEcCurveName(ecPriv.Parameters, ecPriv.AlgorithmName);
                return ResolveSignatureAlgorithm("ECDSA", curve);
            }

            case Ed25519PublicKeyParameters:
            case Ed25519PrivateKeyParameters:
                return "Ed25519";

            case Ed448PublicKeyParameters:
            case Ed448PrivateKeyParameters:
                return "Ed448";

            case MLDsaPublicKeyParameters mlDsaPub:
                return ResolveMlDsaName(mlDsaPub.Parameters.Name);

            case MLDsaPrivateKeyParameters mlDsaPriv:
                return ResolveMlDsaName(mlDsaPriv.Parameters.Name);

            case SlhDsaPublicKeyParameters slhDsaPub:
                return ResolveSlhDsaName(slhDsaPub.Parameters.Name);

            case SlhDsaPrivateKeyParameters slhDsaPriv:
                return ResolveSlhDsaName(slhDsaPriv.Parameters.Name);

            default:
                throw new NotSupportedException(
                    $"Cannot resolve signature algorithm for key type {publicKey.GetType().FullName}");
        }
    }

    private static string ResolveEcCurveName(ECPublicKeyParameters ec)
        => ResolveEcCurveName(ec.Parameters, ec.AlgorithmName);

    private static string ResolveEcCurveName(ECDomainParameters parameters, string? algorithmName)
    {
        // BouncyCastle's AlgorithmName is often "ECDSA"; curve resolution is via Parameters.N or
        // the named-curve table. We normalise to the canonical P-256/P-384/P-521 labels the policy
        // accepts. Falls through to the bit length of the order when the curve isn't recognised.
        if (parameters != null)
        {
            // Use the order bit length as the canonical discriminator. secp256r1/P-256 has a
            // 256-bit order, secp384r1/P-384 a 384-bit order, secp521r1/P-521 a 521-bit order.
            var bits = parameters.N?.BitLength ?? 0;
            return bits switch
            {
                256 => "P-256",
                384 => "P-384",
                521 => "P-521",
                _ => throw new NotSupportedException(
                    $"Unsupported ECDSA curve (order bit length {bits})."),
            };
        }

        // Fallback: some providers set AlgorithmName to the curve label itself.
        if (!string.IsNullOrWhiteSpace(algorithmName))
            return algorithmName!;

        throw new NotSupportedException("Cannot determine ECDSA curve for key.");
    }

    private static string ResolveMlDsaName(string? parameterSetName)
    {
        // BouncyCastle parameter names look like "ML-DSA-65"; pass them straight through after
        // the allow-list check so ResolveSignatureAlgorithm picks the matching branch.
        var name = (parameterSetName ?? "ML-DSA-65").ToUpperInvariant();
        return ResolveSignatureAlgorithm(name, null);
    }

    private static string ResolveSlhDsaName(string? parameterSetName)
    {
        var name = (parameterSetName ?? "SLH-DSA-SHA2-128F").ToUpperInvariant();
        return ResolveSignatureAlgorithm(name, null);
    }

    /// <summary>
    /// Normalises ECDSA integer or OpenSSL-style curve names to the canonical P-xxx form that
    /// <see cref="KeyGenerationUtil"/> expects. Non-ECDSA inputs are returned unchanged.
    /// </summary>
    private static string NormalizeCurve(string algorithm, string sizeOrCurve)
    {
        if (!string.Equals(algorithm, "ECDSA", StringComparison.OrdinalIgnoreCase))
            return sizeOrCurve;
        return sizeOrCurve switch
        {
            "secp256r1" or "256" => "P-256",
            "secp384r1" or "384" => "P-384",
            "secp521r1" or "521" => "P-521",
            _ => sizeOrCurve,
        };
    }
}
