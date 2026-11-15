using ModularCA.Shared.Entities;
using Org.BouncyCastle.Crypto.Parameters;

namespace ModularCA.Shared.Utils;

/// <summary>One thing an operator should know about a CA's key: a stable code and a sentence to act on.</summary>
/// <param name="Reason">A stable code the console can switch on, e.g. <c>CaRsaKeyBelow3072</c>.</param>
/// <param name="Message">What is wrong and what to do about it.</param>
public sealed record CaKeyAdvisory(string Reason, string Message);

/// <summary>
/// The rule for the key of a certificate authority, X.509 or SSH, on top of
/// <see cref="KeyAlgorithmPolicy"/>: a NEW CA's RSA key must be at least
/// <see cref="MinRsaBitsForNewCa"/> bits. NIST SP 800-57 Part 1 rates RSA 2048 at 112 bits of
/// security and accepts that strength only through 2030; a CA key made today signs, and is relied
/// on, long after that. Every path that creates a CA key asks <see cref="RefusalForNewCa(string, int)"/>:
/// the admin API (directly and through a key ceremony, when it is opened and again when it is
/// executed), the setup wizard, <c>bootstrap.yaml</c>, and SSH CA keys.
/// <para>
/// An existing CA is not touched and keeps issuing. One whose key is RSA under 3072 bits carries
/// an advisory (<see cref="Advisories"/>) on its page and on System Health. End-entity keys are a
/// different matter and keep their own floor, <c>CertPolicy.MinRsaKeySize</c>.
/// </para>
/// </summary>
public static class CaKeyPolicy
{
    /// <summary>The smallest RSA modulus, in bits, a new CA key may have.</summary>
    public const int MinRsaBitsForNewCa = 3072;

    /// <summary>The advisory code for an existing CA whose RSA key is under <see cref="MinRsaBitsForNewCa"/> bits.</summary>
    public const string RsaKeyBelow3072 = "CaRsaKeyBelow3072";

    /// <summary>
    /// Why a new CA may not have this key, or null when it may. Only RSA under
    /// <see cref="MinRsaBitsForNewCa"/> bits is refused here; whether the algorithm and size are
    /// allowed at all is <see cref="KeyAlgorithmPolicy.IsAllowed(string, int)"/>'s to say.
    /// </summary>
    /// <param name="algorithm">The key algorithm as requested, e.g. <c>RSA</c> or <c>rsa</c>.</param>
    /// <param name="keySize">The RSA modulus length in bits (ignored for every other algorithm).</param>
    public static string? RefusalForNewCa(string? algorithm, int keySize)
    {
        if (!string.Equals(algorithm?.Trim(), "RSA", StringComparison.OrdinalIgnoreCase)) return null;
        if (keySize >= MinRsaBitsForNewCa) return null;
        return $"A new CA cannot have an RSA {keySize} key: a CA's RSA key must be at least {MinRsaBitsForNewCa} bits. "
            + "NIST SP 800-57 accepts RSA 2048 only through 2030, and a CA key made today is relied on well beyond that. "
            + "Choose RSA 3072 or 4096, or ECDSA P-384. Existing CAs are not affected.";
    }

    /// <summary>
    /// <see cref="RefusalForNewCa(string, int)"/> for a size given as text (<c>"2048"</c>). A size
    /// that is not a number is not refused here.
    /// </summary>
    public static string? RefusalForNewCa(string? algorithm, string? keySize)
        => int.TryParse(keySize, out var bits) ? RefusalForNewCa(algorithm, bits) : null;

    /// <summary>
    /// What an operator should know about an existing CA's key, read from its certificate; empty
    /// when there is nothing to say or the certificate cannot be read (nothing is said on a guess).
    /// Today one case: an RSA key under <see cref="MinRsaBitsForNewCa"/> bits.
    /// </summary>
    public static IReadOnlyList<CaKeyAdvisory> Advisories(CertificateEntity? certificate)
        => RsaBitsOf(certificate) is { } bits ? AdvisoriesForRsa(bits) : [];

    /// <summary>The advisories for a CA whose key is RSA of <paramref name="rsaBits"/> bits.</summary>
    public static IReadOnlyList<CaKeyAdvisory> AdvisoriesForRsa(int rsaBits)
        => rsaBits < MinRsaBitsForNewCa
            ? [new CaKeyAdvisory(RsaKeyBelow3072, RsaBelow3072Message(rsaBits))]
            : [];

    /// <summary>The sentence shown on a CA whose RSA key is under <see cref="MinRsaBitsForNewCa"/> bits.</summary>
    public static string RsaBelow3072Message(int rsaBits)
        => $"This CA's key is RSA {rsaBits}. NIST SP 800-57 accepts RSA keys under {MinRsaBitsForNewCa} bits only through 2030, "
            + "so this CA should be replaced before 2031. A CA's key cannot be changed: replacing it means creating a new CA now "
            + "(RSA 3072 or larger, or ECDSA P-384), moving issuance to it, and retiring this one once the certificates it issued "
            + "have expired or been reissued. It keeps working until then.";

    /// <summary>
    /// The modulus length of the RSA key in a CA's stored certificate, or null when the key is not
    /// RSA or the certificate is missing or unreadable.
    /// </summary>
    public static int? RsaBitsOf(CertificateEntity? certificate)
    {
        if (certificate == null) return null;
        try
        {
            var parsed = !string.IsNullOrWhiteSpace(certificate.Pem)
                ? CertificateUtil.ParseFromPem(certificate.Pem)
                : certificate.RawCertificate != null
                    ? new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate.RawCertificate)
                    : null;
            return parsed?.GetPublicKey() is RsaKeyParameters rsa ? rsa.Modulus.BitLength : null;
        }
        catch
        {
            return null;
        }
    }
}
