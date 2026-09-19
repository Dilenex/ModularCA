using ModularCA.Shared.Enrollment;

namespace ModularCA.Core.Services.Enrollment;

/// <summary>
/// The shared middle of every enrollment protocol: find the CA, check the protocol is enabled on
/// it, authorize the caller, resolve the effective profiles, validate the subject and alternative
/// names, record the request, issue it or take it under submission, and audit the outcome.
/// </summary>
/// <remarks>
/// <para>
/// A protocol supplies only what is genuinely its own — how to parse its wire format, how to
/// authenticate the caller, and how to render the answer — and calls this for everything between.
/// Before this existed each protocol wired that sequence by hand, in its own order, so the same
/// rule could be applied in five places and forgotten in a sixth.
/// </para>
/// <para>
/// There is no <c>PollAsync</c> here, and after the second migration the design should drop it.
/// EST does not poll at all: an approval-gated request is answered 202 and RFC 7030 has the client
/// repeat the whole enrollment rather than ask after the one it made, so migrating it produced no
/// second implementation to generalise from. MSAE remains the only poller, and what it does when a
/// client asks after a request — read the id the client quoted, check this caller submitted it and
/// that it belongs to the CA in the route, then render the chain or the state — is ownership and
/// rendering, not a middle. The half that might be shared is keyed differently in every protocol
/// that has one: MSAE quotes a request row id, SCEP re-sends a subject and a transaction id, CMP a
/// certReqId inside its transaction. A poll interface written from MSAE alone would describe MSAE.
/// The outcome type already covers what a poll answers; the poll itself belongs to the protocol
/// until two of them ask for the same thing.
/// </para>
/// </remarks>
public interface IEnrollmentPipeline
{
    /// <summary>
    /// Runs the shared middle for one submission and returns what became of it.
    /// </summary>
    /// <param name="submission">The normalized request; see <see cref="EnrollmentSubmission"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// One of the four outcomes. A protocol check the submission supplied refuses by throwing, and
    /// an exception raised by issuance propagates: neither is folded into an outcome, so a
    /// protocol that already audits and shapes those refusals keeps doing so.
    /// </returns>
    Task<EnrollmentOutcome> SubmitAsync(EnrollmentSubmission submission, CancellationToken cancellationToken = default);
}
