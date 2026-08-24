namespace ModularCA.Core.Services;

/// <summary>
/// Base type for issuance failures caused by the request rather than by the server.
/// </summary>
/// <remarks>
/// These must reach the client as a 4xx with an actionable message. Several of them previously
/// threw bare <see cref="System.Exception"/> or <see cref="System.InvalidOperationException"/>
/// out of the service layer, which produced a 500 and a full stack trace for what was simply a
/// request the profile or policy does not allow — indistinguishable, in the journal, from the
/// CA actually being broken.
/// <para>
/// <see cref="RequestValidationMiddleware"/> catches this base type; a new validation failure
/// only has to derive from it to be reported correctly.
/// </para>
/// </remarks>
public abstract class RequestValidationException(string message) : Exception(message)
{
    /// <summary>Short problem-details title describing the class of failure.</summary>
    public abstract string Title { get; }
}

/// <summary>
/// Raised when a submitted key algorithm, key size, or signature algorithm is not permitted by
/// the chosen signing or certificate profile.
/// </summary>
/// <remarks>
/// <see cref="AllowedValues"/> carries what the profile does permit, so the response can tell
/// the operator how to fix it rather than only what went wrong.
/// </remarks>
public sealed class ProfileValidationException : RequestValidationException
{
    /// <inheritdoc/>
    public override string Title => "Profile does not permit these key parameters";

    /// <summary>The parameter that was rejected, e.g. "Signature algorithm".</summary>
    public string Parameter { get; }

    /// <summary>The value the caller supplied.</summary>
    public string SuppliedValue { get; }

    /// <summary>The values the profile permits, for inclusion in the error response.</summary>
    public IReadOnlyList<string> AllowedValues { get; }

    /// <summary>Creates a validation failure describing what was rejected and what is allowed.</summary>
    public ProfileValidationException(string parameter, string suppliedValue, IReadOnlyList<string> allowedValues, string profileKind)
        : base($"{parameter} \"{suppliedValue}\" is not permitted by the {profileKind}. Allowed: {(allowedValues.Count > 0 ? string.Join(", ", allowedValues) : "(none configured)")}.")
    {
        Parameter = parameter;
        SuppliedValue = suppliedValue;
        AllowedValues = allowedValues;
    }
}

/// <summary>
/// Raised when a certificate would violate one or more system certificate-policy rules — for
/// example a validity period longer than <c>CertPolicy.MaxValidityDays</c>.
/// </summary>
/// <remarks>
/// Policy rules are deliberate limits, so tripping one is a normal answer to an over-reaching
/// request, not a server fault. Warnings are logged and do not raise this.
/// </remarks>
public sealed class CertificatePolicyViolationException(IReadOnlyList<string> violations)
    : RequestValidationException($"Certificate policy violation(s): {string.Join("; ", violations)}")
{
    /// <inheritdoc/>
    public override string Title => "Certificate policy violation";

    /// <summary>The individual rule violations, each already formatted as "[Rule] message".</summary>
    public IReadOnlyList<string> Violations { get; } = violations;
}
