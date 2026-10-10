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
public sealed record ServerKeyOptions(
    string SigningProfileName,
    string CertProfileName,
    List<ServerKeyOption> Options,
    List<ServerKeyRefusal> Refused);
