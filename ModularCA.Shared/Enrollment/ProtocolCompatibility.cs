using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;

namespace ModularCA.Shared.Enrollment;

/// <summary>
/// One reason a protocol's configuration on one CA cannot work, as a short machine-readable
/// reason code and a sentence an operator can act on.
/// </summary>
/// <param name="Reason">A stable code the console can switch on, e.g. <c>ScepRequiresRsaKey</c>.</param>
/// <param name="Message">A single sentence naming the problem and what to do about it.</param>
public sealed record ProtocolAdvisory(string Reason, string Message);

/// <summary>
/// Says whether a protocol can work on a given CA at all, independently of whether an operator
/// has switched it on.
/// </summary>
/// <remarks>
/// This is not a readiness service. A readiness checklist (see the MSAE one) walks the many
/// preconditions of a protocol that <em>can</em> run; what lives here is the smaller, harder
/// class of fact: a combination that is impossible whatever else is configured, because the
/// protocol's own message format cannot be built against that CA. The first and currently only
/// member is SCEP on a non-RSA authority: a SCEP client wraps its certification request in a
/// CMS envelope encrypted to the CA certificate using RSA key transport, which is the only
/// recipient type SCEP defines, so an ECDSA authority cannot be a recipient and the client fails
/// with "unknown algorithm: 1.2.840.10045.2.1" before the server sees anything.
/// <para>
/// Kept as pure functions over the CA's certificate so the same judgement backs both the refusal
/// when the combination is being enabled and the advisory shown beside an existing row.
/// </para>
/// </remarks>
public static class ProtocolCompatibility
{
    /// <summary>The system feature flag that gates a protocol, e.g. <c>SCEP</c> → <c>SCEP.Enabled</c>.</summary>
    /// <remarks>
    /// The same names <c>ProtocolFeatureGateMiddleware</c> enforces and the public portal filters
    /// on; derived rather than tabulated so a new protocol needs no second list to be updated.
    /// </remarks>
    public static string FeatureFlagName(string protocol)
        => $"{(protocol ?? string.Empty).Trim().ToUpperInvariant()}.Enabled";

    /// <summary>
    /// The key algorithm of a CA's certificate — "RSA", "ECDSA", "Ed25519" and so on — read from
    /// the stored certificate itself, or null when there is no parseable certificate.
    /// </summary>
    /// <remarks>
    /// Read from the certificate rather than from any stored algorithm string: the string records
    /// what was asked for at creation, the certificate records what the CA actually has, and a CA
    /// imported or cross-certified from elsewhere only ever has the latter.
    /// </remarks>
    public static string? KeyAlgorithmOf(CertificateEntity? certificate)
    {
        if (certificate == null) return null;
        try
        {
            var parsed = !string.IsNullOrWhiteSpace(certificate.Pem)
                ? CertificateUtil.ParseFromPem(certificate.Pem)
                : certificate.RawCertificate != null
                    ? new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate.RawCertificate)
                    : null;
            if (parsed == null) return null;
            var algorithm = CertificateUtil.ParseCertificate(parsed).KeyAlgorithm;
            return string.IsNullOrWhiteSpace(algorithm) ? null : algorithm;
        }
        catch
        {
            // An unparseable stored certificate is not evidence of an incompatible key; say
            // nothing rather than refusing a configuration on a guess.
            return null;
        }
    }

    /// <summary>
    /// True when <paramref name="keyAlgorithm"/> is known and is not RSA. An unknown algorithm
    /// (null or empty) returns false: nothing is refused on a guess.
    /// </summary>
    public static bool IsNonRsa(string? keyAlgorithm)
        => !string.IsNullOrWhiteSpace(keyAlgorithm)
           && !string.Equals(keyAlgorithm, "RSA", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Every reason the given protocol cannot work on a CA with the given key algorithm, or an
    /// empty list when nothing is known to be wrong.
    /// </summary>
    /// <remarks>
    /// A list rather than a single value so a second case — on this protocol or another — is a
    /// new entry here and a new item in the array the console already renders, with no change to
    /// the endpoint or its shape.
    /// </remarks>
    public static IReadOnlyList<ProtocolAdvisory> Advisories(string protocol, string? keyAlgorithm)
    {
        var found = new List<ProtocolAdvisory>();
        if (string.Equals(protocol, "SCEP", StringComparison.OrdinalIgnoreCase) && IsNonRsa(keyAlgorithm))
            found.Add(new ProtocolAdvisory(ScepRequiresRsaKey, ScepNonRsaMessage(keyAlgorithm!)));
        return found;
    }

    /// <summary>The reason code for SCEP configured on an authority whose key is not RSA.</summary>
    public const string ScepRequiresRsaKey = "ScepRequiresRsaKey";

    /// <summary>
    /// The sentence shown for SCEP on a non-RSA authority, naming the algorithm the CA actually
    /// has so the operator does not have to go and look it up.
    /// </summary>
    public static string ScepNonRsaMessage(string keyAlgorithm)
        => $"SCEP cannot run on this CA: its key is {keyAlgorithm}, and a SCEP client encrypts its "
           + "certification request to the CA certificate using RSA key transport, the only recipient "
           + "type SCEP defines — so the client cannot build the message and this CA could not decrypt "
           + "it. Serve SCEP from an RSA authority instead.";

    /// <summary>
    /// The refusal message for enabling a protocol that cannot work on this CA, or null when the
    /// combination is allowed. Only checked when the protocol is being turned on: an existing row
    /// is left alone, because this is about enabling, not migrating.
    /// </summary>
    public static string? RefusalForEnabling(string protocol, string? keyAlgorithm)
        => Advisories(protocol, keyAlgorithm).FirstOrDefault()?.Message;
}
