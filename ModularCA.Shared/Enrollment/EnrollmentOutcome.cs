namespace ModularCA.Shared.Enrollment;

/// <summary>
/// What the pipeline made of a submission: a closed set of four, which the protocol renders in
/// its own wire format.
/// </summary>
/// <remarks>
/// The set is closed by a private constructor, so the four cases nested here are the only ones
/// that can exist and a <c>switch</c> over them cannot be made incomplete from elsewhere.
/// </remarks>
public abstract record EnrollmentOutcome
{
    /// <summary>Private, so the set of outcomes is closed to the four nested below.</summary>
    private EnrollmentOutcome() { }

    /// <summary>A certificate was issued.</summary>
    /// <param name="RequestId">The request row, for the protocol that lets a client ask after it later.</param>
    /// <param name="CertificatePem">The issued leaf, PEM.</param>
    /// <param name="ChainPem">
    /// The issuer chain above the leaf, PEM, nearest issuer first, walked through the signing
    /// profile's issuer links. Empty when the signing profile names no issuer.
    /// </param>
    /// <param name="SerialNumber">The issued serial, as the certificate row stores it.</param>
    public sealed record Issued(
        Guid RequestId,
        string CertificatePem,
        IReadOnlyList<string> ChainPem,
        string? SerialNumber) : EnrollmentOutcome;

    /// <summary>
    /// The request was taken under submission: the profile requires an approver, and the row is
    /// waiting in the console's approval queue.
    /// </summary>
    /// <param name="RequestId">What the client quotes to ask after it.</param>
    public sealed record Pending(Guid RequestId) : EnrollmentOutcome;

    /// <summary>
    /// The request was refused on policy. The reason code is shared across protocols so the
    /// console explains a refusal once; the sentence is what the client is told.
    /// </summary>
    /// <param name="Reason">Why, as a code every protocol shares.</param>
    /// <param name="Message">The sentence, safe to return to the client.</param>
    public sealed record Refused(EnrollmentRefusalReason Reason, string Message) : EnrollmentOutcome;

    /// <summary>
    /// The request could not be answered: a misconfiguration or a fault, not a decision about the
    /// request. The protocol reports it generically; the detail belongs in the log.
    /// </summary>
    /// <param name="Message">What went wrong.</param>
    /// <param name="Cause">The exception, when there was one.</param>
    /// <param name="Reason">
    /// Which kind of fault, for a protocol that answers the two kinds differently; see
    /// <see cref="EnrollmentFailureReason"/>.
    /// </param>
    public sealed record Failed(
        string Message,
        Exception? Cause = null,
        EnrollmentFailureReason Reason = EnrollmentFailureReason.Unspecified) : EnrollmentOutcome;
}

/// <summary>
/// Which kind of configuration fault an <see cref="EnrollmentOutcome.Failed"/> reports.
/// </summary>
/// <remarks>
/// <para>
/// A failure carried only a sentence at first, which was enough while the one migrated protocol
/// answered every failure the same way. MSAE does not: a CA with no certificate profile to issue
/// from is something the client is told, on the MSAE audit tab and in the fault it receives,
/// because an operator testing the endpoint needs to read it; a profile row the configuration
/// names and the database does not have is a broken installation, reported generically and left in
/// the log. Telling those apart from the sentence would be a string comparison, so the pipeline
/// says which it was.
/// </para>
/// <para>
/// This is not <see cref="EnrollmentRefusalReason"/> and must not grow into it: nothing here is a
/// decision about the request.
/// </para>
/// </remarks>
public enum EnrollmentFailureReason
{
    /// <summary>Unclassified: a fault with nothing more to say about it than its sentence.</summary>
    Unspecified = 0,

    /// <summary>
    /// No certificate profile could be resolved for this CA and protocol, so there is nothing to
    /// issue from. The CA's protocol configuration names none, or the request profile allows none
    /// of the ones it names.
    /// </summary>
    NoCertificateProfileAvailable = 1,

    /// <summary>
    /// A profile the configuration points at is not in the database — a signing or certificate
    /// profile row that has been deleted out from under a protocol configuration.
    /// </summary>
    ConfiguredProfileMissing = 2,
}
