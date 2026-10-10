namespace ModularCA.Shared.Models.Issuance;

/// <summary>
/// A key the CA can generate for a request under one signing profile and certificate profile.
/// </summary>
/// <param name="Algorithm">The key algorithm, e.g. <c>RSA</c>, <c>ECDSA</c>, <c>Ed25519</c>, <c>ML-DSA-65</c>.</param>
/// <param name="KeySize">The RSA size or ECDSA curve; null for an algorithm that has neither.</param>
/// <param name="SignatureAlgorithm">The algorithm the CA signs the generated request with.</param>
public sealed record ServerKeyOption(string Algorithm, string? KeySize, string SignatureAlgorithm);

/// <summary>
/// A key the CA can generate that the profile pair or the system key policy refuses, and why.
/// </summary>
/// <param name="Algorithm">The key algorithm.</param>
/// <param name="KeySize">The RSA size or ECDSA curve; null for an algorithm that has neither.</param>
/// <param name="Reason">The refusal as the check that made it words it.</param>
public sealed record ServerKeyRefusal(string Algorithm, string? KeySize, string Reason);

/// <summary>
/// Which server-generated keys a signing profile and certificate profile accept together, so a
/// request form offers only keys that will pass both submission and issuance.
/// </summary>
/// <param name="SigningProfileName">The signing profile the answer is for.</param>
/// <param name="CertProfileName">The certificate profile the answer is for.</param>
/// <param name="Options">The accepted keys, in catalog order.</param>
/// <param name="Refused">The keys the CA could generate but the pair refuses.</param>
/// <param name="Constraints">What the pair imposes on the certificate besides its key; null when not resolved.</param>
public sealed record ServerKeyOptions(
    string SigningProfileName,
    string CertProfileName,
    List<ServerKeyOption> Options,
    List<ServerKeyRefusal> Refused,
    ProfilePairConstraints? Constraints = null);

/// <summary>An extended key usage as a profile stores it, with the OID catalog's name for it.</summary>
/// <param name="Value">The stored value: an OID, or a name from an older profile.</param>
/// <param name="Name">The catalog's name for it, or the value when the catalog has none.</param>
public sealed record NamedUsage(string Value, string Name);

/// <summary>
/// What a signing profile and a certificate profile impose on a certificate issued under them,
/// for a form to show beside the pickers: who issues it, which names the CA may sign, and what
/// the certificate profile (after inheritance) gives and allows.
/// </summary>
/// <param name="IssuingCaName">The CA the signing profile issues from; null when it names none.</param>
/// <param name="NameConstraintsPermitted">The name subtrees the CA is limited to, as <c>TYPE:value</c>.</param>
/// <param name="NameConstraintsExcluded">The name subtrees the CA may not sign.</param>
/// <param name="KeyUsages">The key usages the certificate carries, as the profile stores them.</param>
/// <param name="ExtendedKeyUsages">The extended key usages the certificate carries.</param>
/// <param name="ValidityPeriodMin">The shortest validity, as an ISO 8601 duration; null for none.</param>
/// <param name="ValidityPeriodMax">The longest validity the profile allows; a space or CA may shorten it further.</param>
/// <param name="AllowWildcard">Whether a wildcard DNS name may be issued.</param>
public sealed record ProfilePairConstraints(
    string? IssuingCaName,
    List<string> NameConstraintsPermitted,
    List<string> NameConstraintsExcluded,
    List<string> KeyUsages,
    List<NamedUsage> ExtendedKeyUsages,
    string? ValidityPeriodMin,
    string? ValidityPeriodMax,
    bool AllowWildcard);
