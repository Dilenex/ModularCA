using ModularCA.Shared.Entities;
using Org.BouncyCastle.Crypto.Parameters;

namespace ModularCA.Shared.Utils;

/// <summary>One thing an operator should know about a CA's key: a stable code and a sentence to act on.</summary>
/// <param name="Reason">A stable code the console can switch on, e.g. <c>CaRsaKeyBelow3072</c>.</param>
/// <param name="Message">What is wrong and what to do about it.</param>
/// <param name="Severity">
/// How pressing it is: <see cref="CaKeyAdvisory.Notice"/> for something to plan for,
/// <see cref="CaKeyAdvisory.Warning"/> once a deadline is close, <see cref="CaKeyAdvisory.Critical"/>
/// when something has stopped or is about to. None of them stops the CA or the node.
/// </param>
/// <param name="Title">A few words for a badge or a list heading, e.g. <c>Replace before 2031</c>; null when the console has its own.</param>
public sealed record CaKeyAdvisory(string Reason, string Message, string Severity = CaKeyAdvisory.Notice, string? Title = null)
{
    /// <summary>Something to plan for.</summary>
    public const string Notice = "notice";

    /// <summary>A deadline is close.</summary>
    public const string Warning = "warning";

    /// <summary>Something has stopped, or is about to.</summary>
    public const string Critical = "critical";
}

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
    /// One case here: an RSA key under <see cref="MinRsaBitsForNewCa"/> bits. What depends on time
    /// and on the rest of the instance (expiry, how long the key has signed, what its profiles
    /// allow) is <see cref="CaCryptoperiod.Advisories"/>, and travels in the same list.
    /// </summary>
    public static IReadOnlyList<CaKeyAdvisory> Advisories(CertificateEntity? certificate)
        => RsaBitsOf(certificate) is { } bits ? AdvisoriesForRsa(bits) : [];

    /// <summary>The advisories for a CA whose key is RSA of <paramref name="rsaBits"/> bits.</summary>
    public static IReadOnlyList<CaKeyAdvisory> AdvisoriesForRsa(int rsaBits)
        => rsaBits < MinRsaBitsForNewCa
            ? [new CaKeyAdvisory(RsaKeyBelow3072, RsaBelow3072Message(rsaBits), CaKeyAdvisory.Notice, "Replace before 2031")]
            : [];

    /// <summary>The sentence shown on a CA whose RSA key is under <see cref="MinRsaBitsForNewCa"/> bits.</summary>
    public static string RsaBelow3072Message(int rsaBits)
        => $"This CA's key is RSA {rsaBits}. NIST SP 800-57 accepts RSA keys under {MinRsaBitsForNewCa} bits only through 2030, "
            + "so this CA should be replaced before 2031. A CA's key cannot be changed: replacing it means creating a new CA now "
            + "(RSA 3072 or larger, or ECDSA P-384), moving issuance to it, and retiring this one once the certificates it issued "
            + "have expired or been reissued. It keeps working until then.";

    /// <summary>The advisory code for a CA certificate whose validity is longer than common practice.</summary>
    public const string ValidityBeyondCommonPractice = "CaValidityBeyondCommonPractice";

    /// <summary>The advisory code for a certificate that would carry an RSA key under <see cref="MinRsaBitsForNewCa"/> bits past 2030.</summary>
    public const string RsaBelow3072Past2030 = "CaRsaKeyBelow3072Past2030";

    /// <summary>The validity of a root CA certificate, in years, beyond which the console says it is longer than common practice.</summary>
    public const int CommonRootValidityYears = 25;

    /// <summary>The same for an intermediate CA certificate.</summary>
    public const int CommonIntermediateValidityYears = 10;

    /// <summary>The last instant NIST SP 800-57 accepts an RSA key under <see cref="MinRsaBitsForNewCa"/> bits: the end of 2030.</summary>
    public static readonly DateTime RsaBelow3072AcceptedThrough = new(2030, 12, 31, 23, 59, 59, DateTimeKind.Utc);

    /// <summary>
    /// What to say about the validity chosen for a CA certificate, when it is created or renewed.
    /// Neither notice refuses anything, and neither is a standard's requirement for a private
    /// PKI: common practice is a root valid 10 to 25 years and an intermediate 5 to 10, and no
    /// standard that binds a private CA caps either.
    /// <list type="bullet">
    /// <item><see cref="ValidityBeyondCommonPractice"/> (a notice): the certificate would be valid for more than
    /// <see cref="CommonRootValidityYears"/> years for a root, <see cref="CommonIntermediateValidityYears"/> for an intermediate.</item>
    /// <item><see cref="RsaBelow3072Past2030"/> (a warning the administrator acknowledges): the key is RSA under
    /// <see cref="MinRsaBitsForNewCa"/> bits and the certificate would run past 2030, the date
    /// <see cref="RsaBelow3072Message"/> gives. Only a renewal can meet it, since a new CA cannot have
    /// such a key. It is not a refusal: refusing would leave an existing CA no way to stay in
    /// service while its replacement is prepared.</item>
    /// </list>
    /// </summary>
    /// <param name="isRoot">Whether the certificate is a root's.</param>
    /// <param name="notBefore">Start of the validity chosen.</param>
    /// <param name="notAfter">End of the validity chosen.</param>
    /// <param name="rsaBits">The RSA modulus length of the CA's key, or null for another algorithm.</param>
    public static IReadOnlyList<CaKeyAdvisory> ValidityAdvisories(bool isRoot, DateTime notBefore, DateTime notAfter, int? rsaBits)
    {
        var found = new List<CaKeyAdvisory>();
        if (rsaBits is int bits && bits < MinRsaBitsForNewCa && notAfter.ToUniversalTime() > RsaBelow3072AcceptedThrough)
            found.Add(new CaKeyAdvisory(RsaBelow3072Past2030,
                $"This CA's key is RSA {bits}, and the certificate would be valid until {notAfter.ToUniversalTime():yyyy-MM-dd}. "
                + $"NIST SP 800-57 accepts RSA keys under {MinRsaBitsForNewCa} bits only through 2030, so a certificate that runs past 2030 says the key may be relied on longer than that. "
                + "The certificate can be issued: the CA has to stay in service while its replacement is prepared. Choose a validity that ends by 2030 if you can, "
                + "and plan the replacement in either case: a new CA with RSA 3072 or larger, or ECDSA P-384.",
                CaKeyAdvisory.Warning, "RSA key under 3072 bits past 2030"));

        var common = isRoot ? CommonRootValidityYears : CommonIntermediateValidityYears;
        if (notAfter > notBefore.AddYears(common).AddDays(1))
            found.Add(new CaKeyAdvisory(ValidityBeyondCommonPractice,
                $"This certificate would be valid for more than {common} years, which is longer than common practice for {(isRoot ? "a root" : "an intermediate")} CA "
                + $"({(isRoot ? "10 to 25" : "5 to 10")} years). No standard that binds a private CA sets a limit, so nothing is refused. "
                + "A longer validity means the key is relied on for longer; the certificate can be renewed later instead.",
                CaKeyAdvisory.Notice, "Longer than common practice"));
        return found;
    }

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
