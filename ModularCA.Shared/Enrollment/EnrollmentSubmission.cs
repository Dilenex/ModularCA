using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;

namespace ModularCA.Shared.Enrollment;

/// <summary>
/// What the shared middle knows by the time the profiles are resolved: the CA that will issue,
/// the profiles that govern the request, and the names as they now stand.
/// </summary>
/// <remarks>
/// Handed to <see cref="EnrollmentSubmission.AfterProfileValidation"/> so a protocol's own check
/// can run at the one point where it has the effective profile and the request row does not exist
/// yet. EST bounds a username-authenticated caller's SANs there, which needs to know whether the
/// request profile pins values of that SAN type.
/// </remarks>
/// <param name="CaId">The CA that will issue.</param>
/// <param name="CaLabel">Its label.</param>
/// <param name="RequestProfileId">The request profile in force, or null when the protocol has none.</param>
/// <param name="CertProfileId">The certificate profile the request resolved to.</param>
/// <param name="Subject">The subject DN as it now stands, after any fixed values the profile applied.</param>
/// <param name="SubjectAlternativeNames">The alternative names, unchanged from the submission.</param>
public sealed record EnrollmentPolicyContext(
    Guid CaId,
    string CaLabel,
    Guid? RequestProfileId,
    Guid CertProfileId,
    string? Subject,
    IReadOnlyList<string> SubjectAlternativeNames);

/// <summary>
/// What a protocol's post-authorization check has settled: the names the request will carry, and
/// the renewal it proved.
/// </summary>
/// <remarks>
/// <para>
/// The check runs where the protocol already ran it, and for some protocols the credential is what
/// the names come from, so the check cannot only refuse — it also answers. MSAE's CMC renewal is
/// the case: the certificate being renewed is what names the new one, and it names it only once
/// the evidence has been proven against the database, which must happen after the caller is
/// authorized so that an unauthorized caller is told they are unauthorized and nothing else.
/// </para>
/// <para>
/// A protocol with nothing to settle returns what it was given, which is what EST does.
/// </para>
/// </remarks>
/// <param name="Request">The certification request, as it now stands.</param>
/// <param name="Renewal">The renewal evidence, when the check proved one.</param>
public sealed record EnrollmentAuthorizedRequest(
    EnrollmentRequestMaterial Request,
    EnrollmentRenewal? Renewal);

/// <summary>
/// The normalized certification request every protocol produces, and the only thing the pipeline
/// is given. Everything protocol-specific — the wire format, the credential, the response — has
/// already been dealt with by the time one of these exists.
/// </summary>
public sealed record EnrollmentSubmission
{
    /// <summary>
    /// The protocol name, upper case, as <c>CaProtocolConfigEntity.Protocol</c> stores it and as
    /// the audit row records it.
    /// </summary>
    public required string Protocol { get; init; }

    /// <summary>The CA label from the route, or null for the default CA.</summary>
    public string? CaLabel { get; init; }

    /// <summary>Who is asking, and how that was proven.</summary>
    public required EnrollmentCaller Caller { get; init; }

    /// <summary>The certification request itself.</summary>
    public required EnrollmentRequestMaterial Request { get; init; }

    /// <summary>
    /// The template or profile the client named, if any, for the audit row. Which profiles a named
    /// template resolves to is the protocol's own lookup, because only MSAE has templates and only
    /// it knows how a client names one.
    /// </summary>
    public string? ProfileHint { get; init; }

    /// <summary>
    /// A certificate profile the requester chose explicitly. Held to the request profile's allowed
    /// list before it is used; null on every protocol that does not let a client choose.
    /// </summary>
    public Guid? RequestedCertProfileId { get; init; }

    /// <summary>
    /// The start the client asked for, or null for the default. Raised to the floor
    /// <see cref="ModularCA.Shared.Utils.CertificateValidityUtil.ClampRequestedNotBefore"/> applies,
    /// so a client cannot ask for a certificate that was already valid yesterday.
    /// </summary>
    /// <remarks>
    /// This and <see cref="RequestedNotAfter"/> replaced a single requested <c>TimeSpan</c>. The
    /// contract guessed that a client asks for a length; the protocol that actually asks — ACME,
    /// whose newOrder carries <c>notBefore</c> and <c>notAfter</c> — names two instants, and a
    /// length cannot express a certificate that starts next Tuesday. Nothing had set the duration
    /// yet, so nothing was lost by correcting it.
    /// </remarks>
    public DateTime? RequestedNotBefore { get; init; }

    /// <summary>
    /// The expiry the client asked for. Null means the certificate profile's maximum measured from
    /// the start, which is what every protocol but ACME asks for. The certificate profile, the
    /// tenant ceiling and the issuing CA can still shorten it at issuance; none of them lengthens
    /// it, so this is an upper bound the client asks for and not one it is promised.
    /// </summary>
    public DateTime? RequestedNotAfter { get; init; }

    /// <summary>
    /// Whether an expiry the client asked for is shortened to the certificate profile's maximum
    /// instead of being passed on as asked. False by default, so a protocol that has always sent
    /// the client's date through unaltered keeps doing so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Issuance does not shorten an over-long <see cref="RequestedNotAfter"/>; it refuses it, and
    /// the refusal is an exception rather than a decision about the request. CMP's OptionalValidity
    /// has always been clamped before issuance was called, so a client asking for ten years from a
    /// one-year profile is issued a year rather than told the request failed. That clamp cannot
    /// live in CMP any more — the certificate profile, and therefore its maximum, is resolved by
    /// the middle — and it cannot become the rule for everyone, because ACME's <c>notAfter</c> is a
    /// promise to the client that has always been refused rather than quietly shortened.
    /// </para>
    /// <para>
    /// Only the expiry the client named is clamped. The default expiry is the profile's maximum
    /// measured from the start already, so nothing else moves.
    /// </para>
    /// </remarks>
    public bool ClampRequestedNotAfterToProfileMax { get; init; }

    /// <summary>
    /// Extensions the protocol needs stamped on the issued certificate beyond what the profiles
    /// produce — the Windows template information extension is the one that exists. Recorded on
    /// the request row so a certificate issued later, after approval, still carries it.
    /// </summary>
    public IReadOnlyList<RequestedExtension>? RequestedExtensions { get; init; }

    /// <summary>
    /// Evidence that this request renews a certificate, when it does and when the protocol proved
    /// it before submitting; see <see cref="EnrollmentRenewal"/>. A protocol that can only prove it
    /// after the caller is authorized returns it from <see cref="AfterAuthorization"/> instead.
    /// </summary>
    public EnrollmentRenewal? Renewal { get; init; }

    /// <summary>
    /// The CA and profiles the protocol resolved for itself, when the protocol's own wire format
    /// decides them. Null on every protocol whose request addresses a CA and nothing more, and the
    /// pipeline then resolves both from <see cref="CaLabel"/>.
    /// </summary>
    /// <remarks>
    /// MSAE is why this exists: a Windows client names a certificate template, and the template —
    /// not the CA's protocol configuration — carries the CA, the signing profile, the certificate
    /// profile and the request profile the request is governed by. Which template a client named,
    /// and whether this CA offers it, is protocol work the shared middle cannot do. What the
    /// pipeline still owns is everything decided about that CA: the protocol's enablement on it,
    /// the caller's authorization against it, the profile and name validation, the row and the
    /// issuance.
    /// </remarks>
    public ResolvedCaContext? ResolvedContext { get; init; }

    /// <summary>
    /// Whether issuance refusing the request on the certificate profile's rules is a refusal of
    /// the request rather than a fault. False by default, so the exception propagates and a
    /// protocol that has no answer for it does not silently acquire one.
    /// </summary>
    /// <remarks>
    /// MSAE sets it: a Windows client reads a SOAP fault reason and shows it to its operator, so a
    /// validity window that resolves to nothing is worth saying rather than hiding behind
    /// "enrollment failed". The request row is then marked rejected — it exists by that point, and
    /// a row left at Pending for a request that will never issue is what the approval queue would
    /// show forever.
    /// </remarks>
    public bool IssuanceRefusalIsRefusal { get; init; }

    /// <summary>
    /// The account that owns the request, when the protocol can name one. Only that account may
    /// collect the certificate later.
    /// </summary>
    public Guid? RequestorUserId { get; init; }

    /// <summary>The caller's address, for the audit row.</summary>
    public string? SourceIp { get; init; }

    /// <summary>
    /// An opaque per-protocol correlation value carried into the audit row — a SCEP transaction
    /// id, a CMP transactionID, an ACME order id. The pipeline never reads it.
    /// </summary>
    public string? Correlation { get; init; }

    /// <summary>
    /// A check of the protocol's own, run once the caller is authorized and before any profile is
    /// resolved. It refuses by throwing, having written its own audit row, because a check this
    /// specific also has a refusal shape of its own, and it returns what it settled; see
    /// <see cref="EnrollmentAuthorizedRequest"/>.
    /// </summary>
    /// <remarks>
    /// This exists so a protocol keeps the order it already had. EST authorizes, then binds the
    /// CSR's subject and SANs to the credential that was presented, and only then looks at
    /// profiles; a caller who fails both would otherwise be told about the second failure rather
    /// than the first, which is a different answer to the same request. MSAE proves its renewal
    /// evidence at the same point, for the same reason, and the names of a renewal come out of it.
    /// </remarks>
    public Func<EnrollmentAuthorizedRequest, Task<EnrollmentAuthorizedRequest>>? AfterAuthorization { get; init; }

    /// <summary>
    /// A check of the protocol's own, run once the profiles are resolved and the names have been
    /// validated, and before the request row is written. Refuses the same way
    /// <see cref="AfterAuthorization"/> does.
    /// </summary>
    public Func<EnrollmentPolicyContext, Task>? AfterProfileValidation { get; init; }

    /// <summary>
    /// Where the pipeline sends the shared audit fields. The protocol writes its own table with
    /// its own operation names; see <see cref="EnrollmentAuditRecord"/>. A submission without one
    /// is not audited, which is why every migrated protocol supplies one.
    /// </summary>
    public Func<EnrollmentAuditRecord, Task>? Audit { get; init; }
}
