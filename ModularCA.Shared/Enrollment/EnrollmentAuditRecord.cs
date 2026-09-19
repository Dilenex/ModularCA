namespace ModularCA.Shared.Enrollment;

/// <summary>Which of the three decisions an audit row records.</summary>
public enum EnrollmentAuditEvent
{
    /// <summary>A certificate was issued.</summary>
    Issued = 0,

    /// <summary>The request was taken under submission, awaiting an approver.</summary>
    Pending = 1,

    /// <summary>The request was refused on policy.</summary>
    Refused = 2,
}

/// <summary>
/// The shared fields of an enrollment audit row. The pipeline fills these and hands them to the
/// protocol, which writes its own table with its own operation names and its own extra columns.
/// </summary>
/// <remarks>
/// The audit tables are per protocol — <c>AuditEst</c>, <c>AuditMsae</c> and the rest — and that
/// is worth keeping: each carries columns only its protocol has (a SCEP transaction id, an MSAE
/// template and realm). So the pipeline does not own the row; it owns the facts, and the protocol
/// owns the shape. A protocol that supplies no writer is audited nowhere, which is why every
/// migrated protocol supplies one.
/// </remarks>
/// <param name="Protocol">The protocol name, upper case.</param>
/// <param name="Event">Issued, pending, or refused.</param>
/// <param name="Reason">The refusal code, for <see cref="EnrollmentAuditEvent.Refused"/>; null otherwise.</param>
/// <param name="Message">The refusal sentence, or null when nothing was refused.</param>
/// <param name="Subject">The subject DN as recorded on the request row, when it is known yet.</param>
/// <param name="SerialNumber">The issued serial, for <see cref="EnrollmentAuditEvent.Issued"/>.</param>
/// <param name="KeyAlgorithm">Key algorithm of the request.</param>
/// <param name="KeySize">Key size or curve of the request.</param>
/// <param name="CaLabel">The CA the request addressed, as resolved when resolution got that far.</param>
/// <param name="CaId">The resolved CA's id, when one resolved.</param>
/// <param name="TenantId">That CA's tenant.</param>
/// <param name="SourceIp">Caller address.</param>
/// <param name="RequestId">The request row, once one exists.</param>
/// <param name="Correlation">The protocol's own opaque correlation value; see <see cref="EnrollmentSubmission.Correlation"/>.</param>
public sealed record EnrollmentAuditRecord(
    string Protocol,
    EnrollmentAuditEvent Event,
    EnrollmentRefusalReason? Reason,
    string? Message,
    string? Subject,
    string? SerialNumber,
    string? KeyAlgorithm,
    string? KeySize,
    string? CaLabel,
    Guid? CaId,
    Guid? TenantId,
    string? SourceIp,
    Guid? RequestId,
    string? Correlation);
