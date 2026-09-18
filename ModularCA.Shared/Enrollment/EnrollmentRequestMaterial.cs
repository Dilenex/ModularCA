namespace ModularCA.Shared.Enrollment;

/// <summary>
/// The certification request itself, normalized: the CSR a protocol parsed, or the subject, names
/// and public key a protocol built when its wire format carries no PKCS#10 of its own.
/// </summary>
/// <remarks>
/// <para>
/// The parsed fields are carried alongside <see cref="CsrPem"/> rather than re-derived, because
/// every protocol has already parsed the request by the time it authenticates the caller, and
/// parsing it twice would be two chances to disagree about what it says.
/// </para>
/// <para>
/// <see cref="Subject"/> and <see cref="SubjectAlternativeNames"/> are what the pipeline validates
/// against the request profile and what it records; a protocol that replaces them — MSAE puts a
/// Kerberos identity's name in place of whatever the CSR claimed — passes the replacement here,
/// and the profile's naming rules still narrow it.
/// </para>
/// </remarks>
public sealed record EnrollmentRequestMaterial
{
    /// <summary>The PEM-encoded PKCS#10, when the request carries one. Stored on the request row.</summary>
    public string? CsrPem { get; init; }

    /// <summary>The subject DN the certificate should carry.</summary>
    public string? Subject { get; init; }

    /// <summary>
    /// The alternative names requested, in the <c>TYPE:value</c> form the rest of the system uses
    /// (<c>DNS:host.example.com</c>).
    /// </summary>
    public IReadOnlyList<string> SubjectAlternativeNames { get; init; } = [];

    /// <summary>
    /// The DER-encoded SubjectPublicKeyInfo, base64, for a protocol that supplies a key without a
    /// CSR. Null when <see cref="CsrPem"/> carries the key.
    /// </summary>
    public string? PublicKeyDerBase64 { get; init; }

    /// <summary>Key algorithm as the request row records it, e.g. <c>RSA</c>.</summary>
    public string? KeyAlgorithm { get; init; }

    /// <summary>Key size or curve name as the request row records it, e.g. <c>2048</c>, <c>P-256</c>.</summary>
    public string? KeySize { get; init; }

    /// <summary>Signature algorithm of the CSR, as the request row records it.</summary>
    public string? SignatureAlgorithm { get; init; }
}
