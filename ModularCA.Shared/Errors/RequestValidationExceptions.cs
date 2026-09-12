namespace ModularCA.Shared.Errors;

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
/// <c>RequestValidationMiddleware</c> catches this base type; a new validation failure
/// only has to derive from it to be reported correctly.
/// </para>
/// </remarks>
public abstract class RequestValidationException(string message) : Exception(message)
{
    /// <summary>Short problem-details title describing the class of failure.</summary>
    public abstract string Title { get; }

    /// <summary>
    /// HTTP status for this failure. Defaults to 400.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every member of this family answered 400 originally, which was right while the family
    /// only described malformed or disallowed request content. It stopped being right once
    /// "the id you named does not exist" and "something with that name already exists" joined
    /// it: a client that branches on 404 or 409 — and the API client does — cannot tell those
    /// apart from a policy refusal when all three arrive as 400.
    /// </para>
    /// <para>
    /// The whole family stays 4xx by construction. A failure caused by the server's own state
    /// rather than by the request does not belong here at all, because a 4xx tells the caller
    /// their request was wrong, and that is a lie when the request was fine. Those keep the
    /// sanitized 500.
    /// </para>
    /// <para>
    /// <b>Anonymous callers do not get these messages.</b> The enrollment protocols — ACME, EST,
    /// SCEP, CMP — catch this family alongside <see cref="InvalidOperationException"/> at their
    /// controller boundary and answer with their own sanitized, protocol-shaped error instead.
    /// That is deliberate, not an oversight: those endpoints are unauthenticated, and these
    /// messages name profiles, CAs, tenants and policy internals. The detail reaches the
    /// authenticated admin and user paths, which have no such catch and fall through to
    /// <c>RequestValidationMiddleware</c>.
    /// <para>
    /// So when adding a member to this family, assume its message will be read by an operator
    /// and never by an anonymous enrollment client — and when adding a protocol endpoint, catch
    /// this family explicitly or it will start leaking.
    /// </para>
    /// </para>
    /// </remarks>
    public virtual int Status => 400;

    /// <summary>
    /// Stable identifier for this failure class, from <see cref="ErrorCodes"/>.
    /// </summary>
    /// <remarks>
    /// Abstract rather than defaulted, so a new member of the family cannot be added without
    /// deciding what it is. A nullable code with a null default would have produced a catalog
    /// that is populated wherever someone remembered, which is worse than no catalog: a code
    /// that is present on some refusals and absent on others cannot be relied on by a runbook
    /// or an alert rule, and the absences are invisible until someone needs one.
    /// </remarks>
    public abstract string Code { get; }

    /// <summary>
    /// What the operator should do about it, when that is not already part of the message.
    /// </summary>
    /// <remarks>
    /// Deliberately not populated everywhere. Many of these guards already end their message
    /// with the fix — "put the permitted issuance EKUs on the signing profile instead" — and
    /// the client appends remediation to the message it renders, so filling this in as well
    /// would say the same thing twice in one toast. Use it where the message states only the
    /// problem.
    /// </remarks>
    public virtual string? Remediation => null;
}

/// <summary>
/// Raised when the content of the request is malformed or unusable — an empty CSR, a signature
/// that does not verify, a subject DN or SAN override that cannot be parsed.
/// </summary>
/// <remarks>
/// Distinct from <see cref="ConfigurationValidationException"/>, which means the request was
/// well-formed and some configuration forbids it. Here the request itself is wrong, and no
/// configuration change would make it work.
/// </remarks>
public sealed class InvalidRequestException(
    string message, string? code = null, string? remediation = null)
    : RequestValidationException(message)
{
    /// <inheritdoc/>
    public override string Title => "Request is not valid";

    /// <inheritdoc/>
    public override string Code => code ?? ErrorCodes.RequestInvalid;

    /// <inheritdoc/>
    public override string? Remediation => remediation;
}

/// <summary>
/// Raised when the request names a resource — a tenant, a profile, a CA — that does not exist,
/// is disabled, or is not of the kind the operation requires.
/// </summary>
/// <remarks>
/// Answers 404 rather than 400: the request was well-formed, the thing it pointed at was not
/// there. <see cref="ResourceKind"/> and <see cref="Identifier"/> are carried separately so a
/// caller can render "profile" and the id it supplied without parsing the sentence.
/// </remarks>
public sealed class ResourceNotFoundException : RequestValidationException
{
    /// <inheritdoc/>
    public override string Title => "Not found";

    /// <inheritdoc/>
    public override int Status => 404;

    /// <summary>The kind of resource that was missing, e.g. "Certificate authority".</summary>
    public string ResourceKind { get; }

    /// <summary>The identifier the caller supplied, when the caller supplied one.</summary>
    public string? Identifier { get; }

    /// <summary>Creates a not-found failure with a message already written for the operator.</summary>
    /// <param name="resourceKind">The kind of resource, e.g. "Tenant".</param>
    /// <param name="message">The full sentence to show, including any remedy.</param>
    /// <param name="identifier">The identifier the caller supplied, if any.</param>
    public ResourceNotFoundException(
        string resourceKind, string message, string? identifier = null, string? code = null)
        : base(message)
    {
        ResourceKind = resourceKind;
        Identifier = identifier;
        Code = code ?? ErrorCodes.ResourceNotFound;
    }

    /// <inheritdoc/>
    public override string Code { get; }
}

/// <summary>
/// Raised when the request collides with state that already exists — a duplicate label, a
/// quota already at its ceiling.
/// </summary>
/// <remarks>
/// Answers 409 rather than 400 because the request is not malformed and will succeed unchanged
/// once the conflicting state is resolved. That distinction matters to the operator: a 400 says
/// "fix your request", a 409 says "fix the world, then send the same request".
/// </remarks>
public sealed class ResourceConflictException(
    string message, string? code = null, string? remediation = null)
    : RequestValidationException(message)
{
    /// <inheritdoc/>
    public override string Title => "Conflict";

    /// <inheritdoc/>
    public override int Status => 409;

    /// <inheritdoc/>
    public override string Code => code ?? ErrorCodes.ResourceConflict;

    /// <inheritdoc/>
    public override string? Remediation => remediation;
}

/// <summary>
/// Raised when configuration the request depends on forbids the operation — a signing profile
/// that does not permit a required usage, a revoked CA, a CA with no usable private key.
/// </summary>
/// <remarks>
/// <para>
/// This is the largest bucket freed from <see cref="InvalidOperationException"/>, and the one
/// that most needed freeing. These guards carry the most operator-actionable prose in the
/// codebase — they name the rule, the consequence of ignoring it, and the field to change —
/// and every word of it was being discarded by a catch-all that answered "An unexpected error
/// occurred. Please try again." Retrying reproduces the refusal exactly, every time.
/// </para>
/// <para>
/// 400 is correct here even though the operator will fix a profile rather than the request:
/// the request asked this CA, with this configuration, to do something that configuration
/// forbids, and no amount of server-side repair makes the request valid as sent.
/// </para>
/// </remarks>
public sealed class ConfigurationValidationException(
    string message, string? code = null, string? remediation = null)
    : RequestValidationException(message)
{
    /// <inheritdoc/>
    public override string Title => "Configuration does not permit this operation";

    /// <inheritdoc/>
    public override string Code => code ?? ErrorCodes.ConfigurationRefused;

    /// <inheritdoc/>
    public override string? Remediation => remediation;
}

/// <summary>
/// Raised when this installation is not licensed for the operation that was requested.
/// </summary>
/// <remarks>
/// <para>
/// Answers 403 rather than 400: the request was well-formed and the caller is authenticated and
/// authorised — the <em>installation</em> is not entitled. No edit to the request would change
/// the answer, which is what separates it from the rest of this family.
/// </para>
/// <para>
/// It belongs in the family anyway, because it wants exactly what the family provides: a code, a
/// remediation, and a rendering path that already reaches the operator. The alternative was a
/// second parallel mechanism carrying the same four fields.
/// </para>
/// <para>
/// These refusals gate <em>configuration</em>, never issuance. A lapsed or absent licence must
/// not stop a CA signing certificates, publishing CRLs or answering OCSP — every customer's
/// licence lapses on its own schedule, and a CA that stops signing takes down everything that
/// depends on it. What freezes is creating new things that need a licence.
/// </para>
/// </remarks>
public sealed class LicensingException(
    string message, string code, string? remediation = null)
    : RequestValidationException(message)
{
    /// <inheritdoc/>
    public override string Title => "Not licensed for this operation";

    /// <inheritdoc/>
    public override int Status => 403;

    /// <inheritdoc/>
    public override string Code => code;

    /// <inheritdoc/>
    public override string? Remediation => remediation;
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

    /// <inheritdoc/>
    public override string Code => ErrorCodes.KeyParametersNotPermitted;
}

/// <summary>
/// Raised when a certificate would violate one or more system certificate-policy rules — for
/// example a validity period longer than <c>CertPolicy.MaxValidityDays</c>.
/// </summary>
/// <remarks>
/// Policy rules are deliberate limits, so tripping one is a normal answer to an over-reaching
/// request, not a server fault. Warnings are logged and do not raise this.
/// </remarks>
public sealed class CertificatePolicyViolationException(
    IReadOnlyList<string> violations, string? code = null)
    : RequestValidationException($"Certificate policy violation(s): {string.Join("; ", violations)}")
{
    /// <inheritdoc/>
    public override string Title => "Certificate policy violation";

    /// <inheritdoc/>
    public override string Code => code ?? ErrorCodes.PolicyViolation;

    /// <summary>The individual rule violations, each already formatted as "[Rule] message".</summary>
    public IReadOnlyList<string> Violations { get; } = violations;
}
